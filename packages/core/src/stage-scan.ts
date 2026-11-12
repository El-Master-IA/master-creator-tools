import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmod,
	lstat,
	readFile,
	rename,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";
import { findRegistryIssues } from "@mct/adapter-node/index";
import { MctError } from "@mct/contract/errors";
import type {
	Adapter,
	Analysis,
	Finding,
	Rule,
	Severidad,
	State,
} from "@mct/contract/types";
import { detectDictionary, loadDictionary } from "@mct/scanner/dictionary";
import { detectPii } from "@mct/scanner/pii";
import type { ScanGitleaksOptions } from "@mct/scanner/scan";
import { scan } from "@mct/scanner/scan";
import { detectSecrets } from "@mct/scanner/secrets";
import { renderReport } from "@mct/templates/report";
import { ADAPTERS } from "./adapters.js";
import { hashTree } from "./hash.js";
import { defaultDictionaryPath, type Lang } from "./init-guards.js";
import { createLogger } from "./logger.js";
import {
	applyCascade,
	readState,
	reconcileFindings,
	withLock,
	workspacePaths,
	writeState,
} from "./workspace.js";

export const FINDINGS_SCHEMA_VERSION = 2;

export interface StageScanOptions {
	/** Home that holds `~/.mct/sensible.txt` and the pinned gitleaks. */
	home?: string;
	lang?: Lang;
	/** Overrides for the gitleaks engine; defaults come from `.mct/tmp` and `~/.mct/bin`. */
	gitleaks?: Partial<ScanGitleaksOptions>;
	now?: () => string;
	mctVersion?: string;
}

export interface StageScanResult {
	hallazgos: {
		abiertos: number;
		aislados: number;
		porSeveridad: Record<Severidad, number>;
	};
	analysis: Analysis;
	gitleaksVersion: string;
}

function invalido(
	mensaje: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		etapa: "scan",
		accion: "Revisa el workspace o recréalo con init --force",
		...(detalle !== undefined && { detalle }),
	});
}

/** Atomic write (temp + rename), owner-only, never through a link. */
async function writeArtifact(
	raiz: string,
	name: string,
	content: string,
): Promise<void> {
	const destino = join(raiz, name);
	try {
		if ((await lstat(destino)).isSymbolicLink()) {
			throw invalido("Un artefacto no puede ser un enlace simbólico", {
				archivo: name,
			});
		}
	} catch (cause) {
		if (cause instanceof MctError) throw cause;
		if ((cause as NodeJS.ErrnoException).code !== "ENOENT") {
			throw invalido("No se pudo inspeccionar un artefacto", { archivo: name });
		}
	}
	const tmp = `${destino}.${process.pid}.tmp`;
	await writeFile(tmp, content, { mode: 0o600 });
	if (process.platform === "win32") {
		try {
			execFileSync(
				"icacls",
				[tmp, "/inheritance:r", "/grant:r", `${userInfo().username}:F`],
				{ stdio: "ignore" },
			);
		} catch (cause) {
			await rm(tmp, { force: true });
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"No se pudieron aplicar los permisos",
				{ cause, detalle: { archivo: name } },
			);
		}
	} else {
		await chmod(tmp, 0o600);
	}
	await rename(tmp, destino);
}

async function readPrevious(raiz: string): Promise<Finding[] | undefined> {
	let raw: string;
	try {
		raw = await readFile(join(raiz, "findings.json"), "utf8");
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw invalido("findings.json no se pudo leer");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw invalido("findings.json no es JSON válido");
	}
	const obj = parsed as { schemaVersion?: unknown; hallazgos?: unknown };
	if (
		parsed === null ||
		typeof parsed !== "object" ||
		obj.schemaVersion !== FINDINGS_SCHEMA_VERSION ||
		!Array.isArray(obj.hallazgos)
	) {
		throw invalido("findings.json trae una forma o schemaVersion inválidos");
	}
	return obj.hallazgos as Finding[];
}

async function hashWork(work: string): Promise<string> {
	const info = await stat(work).catch(() => null);
	if (info === null || !info.isDirectory()) throw invalido("work/ no existe");
	try {
		return await hashTree(work);
	} catch (cause) {
		if (cause instanceof MctError) throw cause;
		throw invalido("No se pudo calcular el hash de work/");
	}
}

/** True when `text` holds a dictionary term, a secret or PII (the value is never kept). */
function makeSensitive(
	terms: readonly string[],
	rules: readonly Rule[],
): (text: string) => boolean {
	return (text) => {
		if (text.length === 0) return false;
		return (
			detectDictionary(text, terms).length > 0 ||
			detectSecrets(text).length > 0 ||
			detectPii(text).length > 0 ||
			// Fresh RegExp per call: no lastIndex carried between strings.
			rules.some((r) => new RegExp(r.patron.source, r.patron.flags).test(text))
		);
	};
}

/** Semver range or dist-tag: no URL, path, alias or credential can match. */
const SAFE_VERSION = /^[\w.^~<>=*|+\- ]{1,100}$/;

/** Allowlist: any dependency version that is not a range or tag is replaced. */
function maskDeps(analysis: Analysis): Analysis {
	return {
		...analysis,
		deps: analysis.deps.map((d) =>
			SAFE_VERSION.test(d.version)
				? d
				: { ...d, version: maskPath(`dep:${d.nombre}:${d.version}`) },
		),
	};
}

function maskPath(salt: string): string {
	return `[ruta:${createHash("sha256").update(salt).digest("hex").slice(0, 12)}]`;
}

function maskStrings(
	value: unknown,
	sensitive: (t: string) => boolean,
	salt: string,
): unknown {
	if (typeof value === "string") {
		return sensitive(value) ? maskPath(`${salt}:${value}`) : value;
	}
	if (Array.isArray(value))
		return value.map((v) => maskStrings(v, sensitive, salt));
	if (value !== null && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value)) {
			out[k] = maskStrings(v, sensitive, salt);
		}
		return out;
	}
	return value;
}

function summarize(hallazgos: readonly Finding[]) {
	const porSeveridad: Record<Severidad, number> = {
		critico: 0,
		alto: 0,
		medio: 0,
		bajo: 0,
	};
	let abiertos = 0;
	let aislados = 0;
	for (const f of hallazgos) {
		if (f.estado === "abierto") {
			abiertos++;
			porSeveridad[f.severidad]++;
		} else if (f.estado === "aislado") {
			aislados++;
		}
	}
	return { abiertos, aislados, porSeveridad };
}

/**
 * Scan stage (api.md › scan): loads the adapter of the workspace, runs analyze
 * and the double-engine scan, writes findings.json, analysis.json and
 * report.html (masked data only) and applies the STATE-001 cascade. Exit 10
 * (PUERTA_BLOQUEADA) with open findings. Fail closed: any failure leaves
 * `scan` pendiente and no report.
 */
export async function stageScan(
	raiz: string,
	options: StageScanOptions = {},
): Promise<StageScanResult> {
	const state0 = await readState(raiz);
	const adapter = ADAPTERS.find((a) => a.id === state0.adapter);
	if (adapter === undefined)
		throw invalido("El adaptador del workspace no existe");
	const now = options.now ?? (() => new Date().toISOString());
	const home = options.home ?? homedir();
	const ws = workspacePaths(raiz);
	const t0 = Date.now();

	const result = await withLock(raiz, async () => {
		try {
			const antes = await hashWork(ws.work);
			const terms = await loadDictionary(defaultDictionaryPath(home));
			const sensitive = makeSensitive(terms, adapter.rules());
			const previos = await readPrevious(raiz);

			const analysisRaw = await adapter.analyze(ws);
			// Registry checks apply to every adapter: a lockfile can ship in any project.
			const registryIssues = await findRegistryIssues(ws);
			const g = options.gitleaks ?? {};
			const scanned = await scan({
				work: ws.work,
				quarantine: ws.quarantine,
				rules: adapter.rules(),
				dictionary: terms,
				registryIssues,
				...(previos === undefined ? {} : { previos }),
				reconcile: reconcileFindings,
				gitleaks: {
					installDir: join(home, ".mct", "bin"),
					tmpDir: join(raiz, "tmp"),
					...g,
				},
			});
			const despues = await hashWork(ws.work);
			if (despues !== antes) {
				throw invalido("work/ cambió durante el scan; vuelve a ejecutar scan");
			}

			const hallazgos = scanned.hallazgos.map((f) =>
				sensitive(f.archivo) ? { ...f, archivo: maskPath(f.id) } : f,
			);
			const analysis = maskStrings(
				maskDeps(analysisRaw),
				sensitive,
				"analysis",
			) as Analysis;
			const resumen = summarize(hallazgos);

			const ts = now();
			const actual = await readState(raiz);
			let next: State = applyCascade(actual, { workSha256: despues }, ts);
			next = {
				...next,
				etapas: {
					...next.etapas,
					scan: { estado: resumen.abiertos > 0 ? "bloqueada" : "ok", ts },
				},
			};
			const html = renderReport({
				lang: options.lang ?? "es",
				generadoEn: ts,
				puertas: (Object.keys(next.etapas) as (keyof State["etapas"])[]).map(
					(etapa) => ({ etapa, estado: next.etapas[etapa].estado }),
				),
				hallazgos,
				licencias: [],
			});
			await writeArtifact(
				raiz,
				"findings.json",
				`${JSON.stringify(
					{
						schemaVersion: FINDINGS_SCHEMA_VERSION,
						mctVersion: options.mctVersion ?? actual.mctVersion,
						gitleaksVersion: scanned.gitleaksVersion,
						generadoEn: ts,
						hallazgos,
					},
					null,
					2,
				)}\n`,
			);
			await writeArtifact(
				raiz,
				"analysis.json",
				`${JSON.stringify(analysis, null, 2)}\n`,
			);
			await writeArtifact(raiz, "report.html", html);
			// State goes last: a partial scan never marks the stage as done.
			await writeState(raiz, next);
			await createLogger(raiz, "scan", { now }).log({
				evento: "scan.ok",
				duracionMs: Date.now() - t0,
			});
			return {
				hallazgos: resumen,
				analysis,
				gitleaksVersion: scanned.gitleaksVersion,
			};
		} catch (error) {
			await invalidate(raiz, now, error);
			throw error;
		}
	});

	if (result.hallazgos.abiertos > 0) {
		throw new MctError(
			"PUERTA_BLOQUEADA",
			`Hay ${result.hallazgos.abiertos} hallazgos sin resolver`,
			{
				etapa: "scan",
				accion: "Corre: mct sanitize",
				detalle: {
					abiertos: result.hallazgos.abiertos,
					aislados: result.hallazgos.aislados,
					porSeveridad: result.hallazgos.porSeveridad,
					gitleaksVersion: result.gitleaksVersion,
				},
			},
		);
	}
	return result;
}

/** Best effort after a failure: no valid scan state and no stale report/analysis. */
async function invalidate(
	raiz: string,
	now: () => string,
	error: unknown,
): Promise<void> {
	try {
		await rm(join(raiz, "report.html"), { force: true });
		await rm(join(raiz, "analysis.json"), { force: true });
		const s = await readState(raiz);
		await writeState(raiz, {
			...s,
			etapas: { ...s.etapas, scan: { estado: "pendiente", ts: now() } },
		});
		await createLogger(raiz, "scan", { now }).error(error);
	} catch {
		// The original error is the one that matters.
	}
}
