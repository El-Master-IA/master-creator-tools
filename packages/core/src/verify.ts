import { lstat, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { n8nAdapter } from "@mct/adapter-n8n/index";
import { nodeAdapter } from "@mct/adapter-node/index";
import { MctError } from "@mct/contract/errors";
import type { Adapter, Finding, State, VerifySpec } from "@mct/contract/types";
import type { LicenseRow } from "@mct/templates/report";
import { renderReport } from "@mct/templates/report";
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
	/** Docker the CLI already resolved (`resolveDocker`). */
	target: DockerTarget;
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
	destino: string;
	healthcheck: {
		tipo: VerifySpec["healthcheck"]["tipo"];
		resultado: "ok";
		ms: number;
	};
	distSha256: string;
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
	},
} as const;

const ADAPTERS: readonly Adapter[] = [nodeAdapter, n8nAdapter];
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
function withEnvFile(command: string): string {
	return `if [ -f .env.example ] && [ ! -e .env ]; then cp .env.example .env; fi && ${command}`;
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
			const spec = adapter.verifyCommand(await adapter.analyze(ws));
			const hc = spec.healthcheck;
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
					target: options.target,
					image: spec.imagen,
					distDir: ws.dist,
					installCommand:
						spec.install === undefined ? "true" : argvToShell(spec.install),
					startCommand: withEnvFile(argvToShell(spec.start)),
					signal: AbortSignal.any(signals),
					lang,
					...(options.run !== undefined && { run: options.run }),
					...(hc.tipo === "http" && {
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
			if (outcome.start === null || outcome.start.code !== 0) {
				throw blocked(m.arranque, m.accionArranque, {
					motivo: "arranque",
					codigo: outcome.start?.code ?? null,
				});
			}
			const after = await hashTree(ws.dist);
			if (after !== before) throw invalid(m.distCambioDurante, m.accionDist);

			const ts = now();
			const destino =
				options.target.kind === "remote" ? options.target.alias : "local";
			await setVerify(raiz, lang, ts, {
				estado: "ok",
				verificado: { distSha256: before, destino, ts },
			});
			await logger.log({ evento: "verify.ok", duracionMs: Date.now() - t0 });
			return {
				destino,
				healthcheck: { tipo: hc.tipo, resultado: "ok", ms },
				distSha256: before,
			};
		} catch (error) {
			if (error instanceof MctError && error.codigo === "PUERTA_BLOQUEADA") {
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
