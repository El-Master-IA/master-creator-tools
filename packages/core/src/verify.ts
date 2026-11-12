import { randomBytes } from "node:crypto";
import { lstat, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
// The core package does not declare these workspace packages yet (package.json is outside C09),
// so they are reached by relative path, like the cli does for the licenses package.
import { buildVerifySpec as buildPythonSpec } from "@mct/adapter-python/verify";
import { MctError } from "@mct/contract/errors";
import type {
	Adapter,
	Finding,
	State,
	VerifySpec,
	VerifyStep,
} from "@mct/contract/types";
import type { LicenseRow } from "@mct/templates/report";
import { renderReport } from "@mct/templates/report";
import { ADAPTERS } from "./adapters.js";
import {
	clearVerifyAvisos,
	readReportAvisos,
	writeVerifyAvisos,
} from "./avisos.js";
import type { Runner } from "./clone.js";
import { type DockerTarget, runSandbox } from "./docker.js";
import { hashTree } from "./hash.js";
import { createLogger } from "./logger.js";
import {
	ETAPAS,
	readState,
	withLock,
	workspacePaths,
	writeState,
} from "./workspace.js";

/** VER-002: last resort when neither the config nor the adapter set a limit. */
export const DEFAULT_VERIFY_TIMEOUT_MIN = 10;

export type VerifyLang = "es" | "en";

export interface StageVerifyOptions {
	/**
	 * Docker the CLI already resolved (`resolveDocker`), or a thunk that resolves it. The thunk is
	 * only called when the adapter has something to run: an adapter without verify (VER-007) never
	 * needs Docker.
	 */
	target: DockerTarget | (() => Promise<DockerTarget>);
	/** `mct.config.json` > `verify.modo` (PY-003). Only the python adapter reads it. */
	configModo?: "compilar";
	/** `mct.config.json` > `verify.ignorar` (PY-003). Only the python adapter reads it. */
	configIgnorar?: string[];
	/** Test hook: nonce of the markers the start script prints. */
	nonce?: string;
	/** `mct.config.json` › `verify.timeoutMin`. */
	configTimeoutMin?: number;
	lang?: VerifyLang;
	now?: () => string;
	run?: Runner;
	/** Ctrl+C from the person. Not the same as the verify time limit. */
	signal?: AbortSignal;
	/** Test seam: defaults to the built-in adapters. */
	adapters?: readonly Adapter[];
	/** Test hook: can only shorten the time limit. */
	timeoutMs?: number;
	/** Test hook: wait between http probes. */
	pollMs?: number;
}

export interface VerifyResult {
	/** `"local"`, an SSH alias or `"(omitido)"` (VER-007). */
	destino: string;
	healthcheck:
		| {
				tipo: VerifySpec["healthcheck"]["tipo"];
				resultado: "ok";
				ms: number;
		  }
		| { tipo: "omitido" };
	distSha256: string;
	/** Text keys: `verify.poetrySinLock`, `verify.pipCheck`, `verify.omitido`. */
	avisos: string[];
}

const MSG = {
	es: {
		sinPackage: "package no ha pasado: no hay un dist/ que verificar",
		accionPackage: "Corre: mct package",
		distCambio: "dist/ no es el que generó package",
		distCambioDurante: "dist/ cambió mientras corría verify",
		accionDist: "Corre package de nuevo",
		sinAdaptador: "El adaptador del workspace no existe",
		accionWs: "Revisa el workspace o recréalo con init --force",
		timeout: "verify superó el tiempo máximo",
		accionTimeout:
			"Sube verify.timeoutMin en mct.config.json o revisa que el proyecto termine",
		instalacion: "La instalación en el contenedor falló",
		accionInstalacion: "Revisa las dependencias y el comando de instalación",
		arranque: "El arranque falló en el contenedor",
		accionArranque: "Revisa el comando de arranque y las variables de entorno",
		enlace: "report.html no puede ser un enlace simbólico",
		cancelado: "verify se canceló",
		recursoRoto: "Recurso local roto en index.html",
		accionRecurso:
			"Corrige el enlace en index.html o añade el archivo que falta",
		puerto: "El puerto o la ruta del healthcheck no son válidos",
		especInvalida: "El comando de verify del adaptador no es válido",
	},
	en: {
		sinPackage: "package has not passed: there is no dist/ to verify",
		accionPackage: "Run: mct package",
		distCambio: "dist/ is not the one package produced",
		distCambioDurante: "dist/ changed while verify was running",
		accionDist: "Run package again",
		sinAdaptador: "The workspace adapter does not exist",
		accionWs: "Check the workspace or recreate it with init --force",
		timeout: "verify exceeded the time limit",
		accionTimeout:
			"Raise verify.timeoutMin in mct.config.json or check that the project finishes",
		instalacion: "The install in the container failed",
		accionInstalacion: "Check the dependencies and the install command",
		arranque: "The start failed in the container",
		accionArranque: "Check the start command and the environment variables",
		enlace: "report.html cannot be a symbolic link",
		cancelado: "verify was cancelled",
		recursoRoto: "Broken local resource in index.html",
		accionRecurso: "Fix the link in index.html or add the missing file",
		puerto: "The healthcheck port or path is not valid",
		especInvalida: "The adapter verify command is not valid",
	},
} as const;

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

/** VER-002: config > adapter > 10 minutes. Pure. */
export function resolveTimeoutMin(
	configMin: number | undefined,
	spec: Pick<VerifySpec, "timeoutMin">,
): number {
	for (const v of [configMin, spec.timeoutMin]) {
		if (typeof v === "number" && Number.isFinite(v) && v > 0) return v;
	}
	return DEFAULT_VERIFY_TIMEOUT_MIN;
}

/** One shell word, single quoted unless it is plainly safe. */
export function shellQuote(word: string): string {
	if (SAFE_WORD.test(word)) return word;
	return `'${word.replaceAll("'", String.raw`'\''`)}'`;
}

/**
 * The sandbox runs a shell string (`sh -c "cd /app && …"`), the adapter gives an argv.
 * `sh -c '<script>' sh <args…>` is real argv (the n8n import passes workflow paths as
 * positional arguments): every word is quoted, nothing is interpolated raw. Any other argv
 * is a command line the adapter split on whitespace; joining it with spaces restores it.
 */
export function argvToShell(argv: readonly string[]): string {
	if (argv[0] === "sh" && argv[1] === "-c") {
		return argv.map(shellQuote).join(" ");
	}
	return argv.join(" ");
}

/** api.md › verify: `.env.example` becomes `.env` before the start, when there is no `.env`. */
const ENV_FILE_STEP =
	"if [ -f .env.example ] && [ ! -e .env ]; then cp .env.example .env; fi";

function withEnvFile(command: string): string {
	return `${ENV_FILE_STEP} && ${command}`;
}

/** PY-003 / WEB-002: how long the server gets to answer before the start counts as failed. */
export const SERVER_WAIT_S = 30;
const VENV_BIN = "/tmp/venv/bin";

export interface Step {
	argv: string[];
	/** `VerifyStep.avisoSiFalla`: a failure of this step warns instead of blocking. */
	aviso?: string;
}

const isStrings = (v: unknown): v is string[] =>
	Array.isArray(v) && v.every((x) => typeof x === "string");

/** `flat` is the 0.1.x shape (one argv); otherwise a sequence. `null` = malformed. */
export function readSteps(
	start: VerifySpec["start"],
): { flat: boolean; steps: Step[] } | null {
	const list: readonly unknown[] = start;
	if (list.length === 0) return null;
	if (isStrings(list)) return { flat: true, steps: [{ argv: list }] };
	const steps: Step[] = [];
	for (const item of list) {
		if (isStrings(item) && item.length > 0) {
			steps.push({ argv: item });
		} else if (
			isObj(item) &&
			isStrings(item.argv) &&
			item.argv.length > 0 &&
			typeof item.avisoSiFalla === "string" &&
			item.avisoSiFalla !== ""
		) {
			steps.push({
				argv: item.argv,
				aviso: (item as unknown as VerifyStep).avisoSiFalla,
			});
		} else {
			return null;
		}
	}
	return { flat: false, steps };
}

const isRichHttp = (hc: VerifySpec["healthcheck"]): boolean =>
	hc.tipo === "http" &&
	(hc.ruta !== undefined ||
		hc.aceptar !== undefined ||
		hc.cuerpoContiene !== undefined ||
		hc.rutasExtra !== undefined);

const PY_PROBE = [
	"import http.client as h,json,sys",
	"from urllib.parse import quote as q",
	"c=json.loads(sys.argv[1])",
	"def ok(s):",
	" for a in c['a']:",
	"  if isinstance(a,int):",
	"   if s==a:return True",
	"  elif s//100==int(a[0]):return True",
	" return False",
	"def get(p):",
	" try:",
	"  x=h.HTTPConnection('127.0.0.1',c['p'],timeout=2)",
	"  x.request('GET',q(p,safe='/%'))",
	"  r=x.getresponse()",
	"  return r.status,r.read(2000000).decode('utf-8','replace')",
	" except Exception:",
	"  return None",
	"m=get(c['r'])",
	"if m is None or not ok(m[0]) or (c['b'] is not None and c['b'].lower() not in m[1].lower()):sys.exit(1)",
	"for p in c['x']:",
	" e=get(p)",
	" if e is None or not ok(e[0]):",
	"  print(c['n']+json.dumps(p));sys.exit(2)",
].join("\n");

const NODE_PROBE = [
	"const c=JSON.parse(process.argv[1]);",
	"const ok=s=>c.a.some(a=>typeof a==='number'?s===a:Math.floor(s/100)===Number(a[0]));",
	"const get=async p=>{try{const r=await fetch('http://127.0.0.1:'+c.p+p,{redirect:'manual',signal:AbortSignal.timeout(2000)});return [r.status,await r.text()]}catch{return null}};",
	"(async()=>{",
	"const m=await get(c.r);",
	"if(!m||!ok(m[0])||(c.b!==null&&!m[1].toLowerCase().includes(c.b.toLowerCase())))process.exit(1);",
	"for(const p of c.x){const e=await get(p);if(!e||!ok(e[0])){console.log(c.n+JSON.stringify(p));process.exit(2)}}",
	"process.exit(0)})()",
].join("\n");

const quoteArgv = (argv: readonly string[]): string =>
	argv.map(shellQuote).join(" ");

/**
 * api.md > verify, start as a sequence: one script for the whole start phase, in the same
 * container, always `--network none`. A step that must pass leaves with its own exit code;
 * a step with `avisoSiFalla` prints `MCT_AVISO:<nonce>:<key>` and goes on. With an http
 * healthcheck the last step is the server: it runs in the background and the script probes it
 * (VER-005 / PY-003 / WEB-002) for up to `SERVER_WAIT_S`. The steps' own output goes to stderr
 * so the markers on stdout cannot be drowned or forged by the project.
 */
export function buildStartScript(
	spec: VerifySpec,
	steps: readonly Step[],
	nonce: string,
	python: boolean,
): string {
	const lines = ["{", ENV_FILE_STEP];
	if (python) lines.push(`export PATH="${VENV_BIN}:$PATH"`);
	const hc = spec.healthcheck;
	const http = hc.tipo === "http" ? hc : null;
	const upfront = http === null ? steps : steps.slice(0, -1);
	for (const step of upfront) {
		const cmd = `${quoteArgv(step.argv)} >&2`;
		lines.push(
			step.aviso === undefined
				? `${cmd} || exit $?`
				: `${cmd} || echo ${shellQuote(`MCT_AVISO:${nonce}:${step.aviso}`)}`,
		);
	}
	if (http !== null) {
		const server = steps[steps.length - 1] as Step;
		const probeCfg = JSON.stringify({
			p: http.puerto,
			r: http.ruta ?? "/",
			a: http.aceptar ?? ["2xx"],
			b: http.cuerpoContiene ?? null,
			x: http.rutasExtra ?? [],
			n: `MCT_ROUTE:${nonce}:`,
		});
		const probe = spec.imagen.startsWith("python:")
			? `python -c ${shellQuote(PY_PROBE)} ${shellQuote(probeCfg)}`
			: `node -e ${shellQuote(NODE_PROBE)} ${shellQuote(probeCfg)}`;
		lines.push(
			`${quoteArgv(server.argv)} >/tmp/mct-server.log 2>&1 &`,
			"mct_pid=$!",
			"mct_i=0",
			"mct_rc=1",
			`while [ "$mct_i" -lt ${SERVER_WAIT_S} ]; do`,
			probe,
			"mct_rc=$?",
			'[ "$mct_rc" -ne 1 ] && break',
			'kill -0 "$mct_pid" 2>/dev/null || break',
			"mct_i=$((mct_i+1))",
			"sleep 1",
			"done",
			'kill "$mct_pid" 2>/dev/null',
			'exit "$mct_rc"',
		);
	} else {
		lines.push("exit 0");
	}
	lines.push("}");
	return lines.join("\n");
}

/** What the start script printed that verify trusts: only lines carrying this run's nonce. */
export function readMarkers(
	stdout: string,
	nonce: string,
	known: ReadonlySet<string>,
): { avisos: string[]; ruta?: string } {
	const avisos: string[] = [];
	let ruta: string | undefined;
	const aviso = `MCT_AVISO:${nonce}:`;
	const route = `MCT_ROUTE:${nonce}:`;
	for (const raw of stdout.split(/\r?\n/)) {
		const line = raw.trimEnd();
		if (line.startsWith(aviso)) {
			const key = line.slice(aviso.length);
			if (known.has(key) && !avisos.includes(key)) avisos.push(key);
		} else if (line.startsWith(route) && ruta === undefined) {
			try {
				const v: unknown = JSON.parse(line.slice(route.length));
				if (typeof v === "string") ruta = v;
			} catch {
				// A malformed marker is not a route.
			}
		}
	}
	return ruta === undefined ? { avisos } : { avisos, ruta };
}

function blocked(
	mensaje: string,
	accion: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("PUERTA_BLOQUEADA", mensaje, {
		etapa: "verify",
		accion,
		...(detalle !== undefined && { detalle }),
	});
}

function invalid(mensaje: string, accion: string): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		etapa: "verify",
		accion,
	});
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

async function readJsonLoose(path: string): Promise<unknown> {
	try {
		return JSON.parse(await readFile(path, "utf8"));
	} catch {
		return undefined;
	}
}

/** Same masked data the other stages put in the report; missing files mean empty lists. */
async function reportData(
	raiz: string,
): Promise<{ hallazgos: Finding[]; licencias: LicenseRow[] }> {
	const f = await readJsonLoose(join(raiz, "findings.json"));
	const hallazgos =
		isObj(f) && Array.isArray(f.hallazgos) ? (f.hallazgos as Finding[]) : [];
	const l = await readJsonLoose(join(raiz, "license-report.json"));
	const licencias: LicenseRow[] = [];
	if (Array.isArray(l)) {
		for (const r of l as unknown[]) {
			if (
				isObj(r) &&
				typeof r.paquete === "string" &&
				typeof r.version === "string" &&
				typeof r.spdx === "string" &&
				(r.origen === "directa" || r.origen === "transitiva") &&
				typeof r.veredicto === "string"
			) {
				licencias.push({
					paquete: r.paquete,
					version: r.version,
					spdx: r.spdx,
					relacion: r.origen,
					veredicto: r.veredicto,
					...(typeof r.alternativa === "string" && {
						alternativa: r.alternativa,
					}),
				});
			}
		}
	}
	return { hallazgos, licencias };
}

async function writeReport(
	raiz: string,
	state: State,
	lang: VerifyLang,
	ts: string,
): Promise<void> {
	const destino = join(raiz, "report.html");
	const info = await lstat(destino).catch(() => null);
	if (info?.isSymbolicLink()) throw invalid(MSG[lang].enlace, "");
	const html = renderReport({
		lang,
		generadoEn: ts,
		puertas: ETAPAS.map((etapa) => ({
			etapa,
			estado: state.etapas[etapa].estado,
		})),
		...(await reportData(raiz)),
		avisos: await readReportAvisos(raiz, state.verificado),
	});
	const tmp = `${destino}.${process.pid}.tmp`;
	await writeFile(tmp, html, { mode: 0o600 });
	await rename(tmp, destino).catch(async (e: unknown) => {
		await rm(tmp, { force: true });
		throw e;
	});
}

async function setVerify(
	raiz: string,
	lang: VerifyLang,
	ts: string,
	result: { estado: "ok" | "bloqueada"; verificado: State["verificado"] },
): Promise<void> {
	const state = await readState(raiz);
	const next: State = {
		...state,
		verificado: result.verificado,
		etapas: { ...state.etapas, verify: { estado: result.estado, ts } },
	};
	await writeState(raiz, next);
	await writeReport(raiz, next, lang, ts).catch(() => undefined);
}

/**
 * Verify stage (api.md › verify): runs the adapter's VerifySpec in the Docker sandbox with a time
 * limit (VER-002), checks the healthcheck (VER-004 n8n import, VER-005 http) and, if it passes,
 * records the hash of the dist/ that was verified. A failure marks the gate `bloqueada` and clears
 * `verificado`; Ctrl+C leaves the workspace as it was.
 */
export async function stageVerify(
	raiz: string,
	options: StageVerifyOptions,
): Promise<VerifyResult> {
	const lang = options.lang ?? "es";
	const m = MSG[lang];
	const now = options.now ?? (() => new Date().toISOString());
	const ws = workspacePaths(raiz);
	const logger = createLogger(raiz, "verify", { now });
	const t0 = Date.now();

	return withLock(raiz, async () => {
		const state = await readState(raiz);
		const adapter = (options.adapters ?? ADAPTERS).find(
			(a) => a.id === state.adapter,
		);
		if (adapter === undefined) throw invalid(m.sinAdaptador, m.accionWs);
		if (state.etapas.package.estado !== "ok") {
			throw blocked(m.sinPackage, m.accionPackage, { motivo: "sin-package" });
		}
		try {
			const before = await hashTree(ws.dist);
			if (before !== state.distSha256) {
				throw invalid(m.distCambio, m.accionDist);
			}
			// The static adapter keeps its extra routes on this very Analysis (WeakMap).
			const analysis = await adapter.analyze(ws);
			const spec =
				adapter.id === "python"
					? buildPythonSpec(analysis, {
							...(options.configModo !== undefined && {
								modo: options.configModo,
							}),
							...(options.configIgnorar !== undefined && {
								ignorar: options.configIgnorar,
							}),
						})
					: adapter.verifyCommand(analysis);
			if (spec === null) {
				// VER-007: no container, no Docker. The gate passes and dist/ is still pinned.
				const ts = now();
				await clearVerifyAvisos(raiz).catch(() => undefined);
				await setVerify(raiz, lang, ts, {
					estado: "ok",
					verificado: { distSha256: before, destino: "(omitido)", ts },
				});
				await logger.log({ evento: "verify.omitido" });
				await logger.log({ evento: "verify.ok", duracionMs: Date.now() - t0 });
				return {
					destino: "(omitido)",
					healthcheck: { tipo: "omitido" },
					distSha256: before,
					avisos: ["verify.omitido"],
				};
			}
			const parsed = readSteps(spec.start);
			if (parsed === null) throw invalid(m.especInvalida, m.accionWs);
			const hc = spec.healthcheck;
			if (hc.tipo === "http") {
				const rutas = [hc.ruta ?? "/", ...(hc.rutasExtra ?? [])];
				if (
					!Number.isInteger(hc.puerto) ||
					hc.puerto < 1 ||
					hc.puerto > 65_535 ||
					rutas.length > 51 ||
					rutas.some((r) => !r.startsWith("/") || r.length > 2_000)
				) {
					throw invalid(m.puerto, m.accionWs);
				}
			}
			// 0.1.x specs (one argv, plain http, not a python image) keep the original sandbox path.
			const script =
				!parsed.flat || isRichHttp(hc) || spec.imagen.startsWith("python:");
			const nonce = options.nonce ?? randomBytes(8).toString("hex");
			const knownAvisos = new Set(
				parsed.steps.flatMap((x) => (x.aviso === undefined ? [] : [x.aviso])),
			);
			const startCommand = script
				? buildStartScript(spec, parsed.steps, nonce, adapter.id === "python")
				: withEnvFile(argvToShell(parsed.steps[0]?.argv ?? []));
			const dockerTarget =
				typeof options.target === "function"
					? await options.target()
					: options.target;
			const limitMs = Math.min(
				resolveTimeoutMin(options.configTimeoutMin, spec) * 60_000,
				options.timeoutMs ?? Number.POSITIVE_INFINITY,
			);

			const limit = new AbortController();
			let timedOut = false;
			const timer = setTimeout(() => {
				timedOut = true;
				limit.abort();
			}, limitMs);
			const signals = [limit.signal];
			if (options.signal !== undefined) signals.push(options.signal);
			const started = Date.now();
			let outcome: Awaited<ReturnType<typeof runSandbox>>;
			try {
				outcome = await runSandbox({
					target: dockerTarget,
					image: spec.imagen,
					distDir: ws.dist,
					installCommand:
						spec.install === undefined ? "true" : argvToShell(spec.install),
					startCommand,
					signal: AbortSignal.any(signals),
					lang,
					...(options.run !== undefined && { run: options.run }),
					...(hc.tipo === "http" &&
						!script && {
							http: {
								port: hc.puerto,
								...(options.pollMs !== undefined && {
									intervalMs: options.pollMs,
								}),
							},
						}),
				});
			} catch (e) {
				// Our own limit is not Ctrl+C: the sandbox reports both as INTERRUMPIDO.
				if (
					timedOut &&
					e instanceof MctError &&
					e.codigo === "INTERRUMPIDO" &&
					options.signal?.aborted !== true
				) {
					throw blocked(m.timeout, m.accionTimeout, {
						motivo: "timeout",
						limiteMin: limitMs / 60_000,
					});
				}
				throw e;
			} finally {
				clearTimeout(timer);
			}
			const ms = Date.now() - started;
			// A killed docker client returns normally; an abort is never a pass or a start failure.
			if (options.signal?.aborted === true) {
				throw new MctError("INTERRUMPIDO", m.cancelado, { etapa: "verify" });
			}
			if (timedOut) {
				throw blocked(m.timeout, m.accionTimeout, {
					motivo: "timeout",
					limiteMin: limitMs / 60_000,
				});
			}

			if (outcome.install.code !== 0) {
				throw blocked(m.instalacion, m.accionInstalacion, {
					motivo: "instalacion",
					codigo: outcome.install.code,
				});
			}
			const markers = script
				? readMarkers(outcome.start?.stdout ?? "", nonce, knownAvisos)
				: { avisos: [] as string[] };
			if (outcome.start === null || outcome.start.code !== 0) {
				if (markers.ruta !== undefined) {
					// WEB-002: the site answers but a local resource of index.html does not.
					throw blocked(m.recursoRoto, m.accionRecurso, {
						motivo: "recurso-roto",
						ruta: markers.ruta.slice(0, 500),
					});
				}
				throw blocked(m.arranque, m.accionArranque, {
					motivo: "arranque",
					codigo: outcome.start?.code ?? null,
				});
			}
			const after = await hashTree(ws.dist);
			if (after !== before) throw invalid(m.distCambioDurante, m.accionDist);

			const ts = now();
			const destino =
				dockerTarget.kind === "remote" ? dockerTarget.alias : "local";
			const avisos = [...new Set([...(spec.avisos ?? []), ...markers.avisos])];
			await writeVerifyAvisos(raiz, [
				...avisos,
				...(adapter.id === "python" && options.configModo === "compilar"
					? ["verify.compilar"]
					: []),
			]);
			await setVerify(raiz, lang, ts, {
				estado: "ok",
				verificado: { distSha256: before, destino, ts },
			});
			for (const aviso of avisos) {
				await logger.log({ evento: `verify.aviso.${aviso}` });
			}
			await logger.log({ evento: "verify.ok", duracionMs: Date.now() - t0 });
			return {
				destino,
				healthcheck: { tipo: hc.tipo, resultado: "ok", ms },
				distSha256: before,
				avisos,
			};
		} catch (error) {
			if (error instanceof MctError && error.codigo === "PUERTA_BLOQUEADA") {
				await clearVerifyAvisos(raiz).catch(() => undefined);
				await setVerify(raiz, lang, now(), {
					estado: "bloqueada",
					verificado: null,
				}).catch(() => undefined);
			}
			await logger.error(error).catch(() => undefined);
			throw error;
		}
	});
}
