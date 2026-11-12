import { lstat, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import {
	type AuditOptions,
	type AuditResult,
	auditLicenses,
	type FetchLike,
	summarize,
} from "./audit.js";
import { normalizePypiName } from "./pypi.js";
import {
	auditPython,
	findNestedManifests,
	findPythonManifests,
	hasPythonManifest,
	type MotivoConfig,
	subcarpetaLabel,
	syntheticEntry,
} from "./python.js";
import type { LicenseAllow, LicenseEntry, Verdict } from "./verdict.js";

const RANK: Record<Verdict, number> = { ok: 0, revisar: 1, bloquea: 2 };

export const PACKAGE_JSON_SIN_LOCK = "(package.json sin lockfile)";
export const AVISO_SIN_GESTOR = "sin-gestor";
export const AVISOS_SCHEMA_VERSION = 1;

const NODE_LOCKFILES = [
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
] as const;
const UNSUPPORTED_NAMES = new Set([
	"composer.json",
	"go.mod",
	"Gemfile",
	"Cargo.toml",
]);
const SKIPPED_DIRS = new Set([
	"node_modules",
	".git",
	"vendor",
	".venv",
	"venv",
	"__pycache__",
]);
const MAX_SCAN_DEPTH = 3;
const MAX_SCAN_ENTRIES = 5_000;
const MAX_UNSUPPORTED = 50;

export interface SinGestorOptions {
	/** Only `estatico` and `generico` use this path; python goes to `auditPython`. */
	adapter: string;
	/** Directory with the project (`.mct/work`). */
	workDir: string;
	/** `.mct`: when given, `license-avisos.json` is written there. */
	mctDir?: string;
	/** `.mct/quarantine` (names of variables only); default `<mctDir>/quarantine`. */
	quarantineDir?: string;
	allow?: readonly LicenseAllow[];
	/** `licenses.sinLock` of mct.config.json. */
	sinLock?: MotivoConfig;
	/** `licenses.gestorNoSoportado` of mct.config.json. */
	gestorNoSoportado?: MotivoConfig;
	offline?: boolean;
	fetch?: FetchLike;
	timeoutMs?: number;
	concurrency?: number;
	mctVersion?: string;
	/** Options for the LIC-004 audit when the project has package.json + lockfile. */
	node?: Pick<AuditOptions, "originDir" | "lockfile">;
}

export interface SinGestorResult extends AuditResult {
	/** `["sin-gestor"]` when no manifest of any kind was found; otherwise empty. */
	avisos: string[];
}

async function isFile(path: string): Promise<boolean> {
	try {
		const st = await lstat(path);
		return st.isFile() && !st.isSymbolicLink();
	} catch {
		return false;
	}
}

function isUnsupported(name: string): boolean {
	return UNSUPPORTED_NAMES.has(name) || name.endsWith(".csproj");
}

/** Unsupported manifests as POSIX relative paths, bounded in depth and count. */
export async function findUnsupportedManifests(
	workDir: string,
): Promise<string[]> {
	const found: string[] = [];
	let visited = 0;
	async function walk(rel: string, depth: number): Promise<void> {
		let items: import("node:fs").Dirent[];
		try {
			items = await readdir(join(workDir, rel), { withFileTypes: true });
		} catch {
			return;
		}
		items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
		for (const item of items) {
			if (++visited > MAX_SCAN_ENTRIES || found.length >= MAX_UNSUPPORTED) {
				return;
			}
			const path = rel === "" ? item.name : `${rel}/${item.name}`;
			if (item.isSymbolicLink()) continue;
			if (item.isDirectory()) {
				if (depth < MAX_SCAN_DEPTH && !SKIPPED_DIRS.has(item.name)) {
					await walk(path, depth + 1);
				}
			} else if (item.isFile() && isUnsupported(item.name)) {
				found.push(path);
			}
		}
	}
	await walk("", 0);
	return found;
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Writes `.mct/license-avisos.json` (LIC-006, datos.md). */
export async function writeLicenseAvisos(
	mctDir: string,
	avisos: readonly string[],
): Promise<void> {
	const target = join(mctDir, "license-avisos.json");
	const tmp = `${target}.tmp`;
	const body = `${JSON.stringify({ schemaVersion: AVISOS_SCHEMA_VERSION, avisos }, null, 2)}\n`;
	await writeFile(tmp, body, { mode: 0o600 });
	await rename(tmp, target);
}

/**
 * Licenses of an `estatico` or `generico` project (LIC-006): package.json + lockfile
 * through LIC-004, a Python manifest through LIC-005, unsupported managers as `revisar`,
 * and the `sin-gestor` notice when there is nothing to audit.
 */
export async function auditSinGestor(
	options: SinGestorOptions,
): Promise<SinGestorResult> {
	if (options.adapter !== "estatico" && options.adapter !== "generico") {
		throw new MctError(
			"INTERNO",
			`auditSinGestor solo aplica a estatico y generico, no a ${options.adapter}`,
		);
	}
	const { workDir } = options;
	const entries: { eco: "npm" | "pypi" | "otro"; entry: LicenseEntry }[] = [];
	const add = (eco: "npm" | "pypi" | "otro", list: readonly LicenseEntry[]) => {
		for (const entry of list) entries.push({ eco, entry });
	};
	let sinPresupuesto = 0;
	let manifests = 0;
	const avisosExtra: string[] = [];
	const quarantineDir =
		options.quarantineDir ??
		(options.mctDir !== undefined
			? join(options.mctDir, "quarantine")
			: undefined);

	if (await isFile(join(workDir, "package.json"))) {
		manifests++;
		let hasLock = false;
		for (const lock of NODE_LOCKFILES) {
			if (await isFile(join(workDir, lock))) hasLock = true;
		}
		if (hasLock) {
			const node = await auditLicenses({
				lockDir: workDir,
				...(options.node?.originDir !== undefined && {
					originDir: options.node.originDir,
				}),
				...(options.node?.lockfile !== undefined && {
					lockfile: options.node.lockfile,
				}),
				...(options.offline !== undefined && { offline: options.offline }),
				...(options.allow !== undefined && { allow: options.allow }),
				...(options.fetch !== undefined && { fetch: options.fetch }),
				...(options.timeoutMs !== undefined && {
					timeoutMs: options.timeoutMs,
				}),
				...(options.concurrency !== undefined && {
					concurrency: options.concurrency,
				}),
			});
			add("npm", node.entries);
			sinPresupuesto += node.sinPresupuesto;
		} else {
			add("otro", [syntheticEntry(PACKAGE_JSON_SIN_LOCK, options.sinLock)]);
		}
	}

	if (hasPythonManifest(await findPythonManifests(workDir))) {
		manifests++;
		const py = await auditPython({
			workDir,
			...(quarantineDir !== undefined && { quarantineDir }),
			...(options.allow !== undefined && { allow: options.allow }),
			...(options.sinLock !== undefined && { sinLock: options.sinLock }),
			...(options.offline !== undefined && { offline: options.offline }),
			...(options.fetch !== undefined && { fetch: options.fetch }),
			...(options.timeoutMs !== undefined && { timeoutMs: options.timeoutMs }),
			...(options.concurrency !== undefined && {
				concurrency: options.concurrency,
			}),
			...(options.mctVersion !== undefined && {
				mctVersion: options.mctVersion,
			}),
		});
		add("pypi", py.entries);
		sinPresupuesto += py.sinPresupuesto;
		avisosExtra.push(...py.avisos.filter((a) => a !== AVISO_SIN_GESTOR));
	}

	// LIC-006: manifests below the root are not audited, so they stay in revisar.
	for (const ruta of await findNestedManifests(workDir, "all")) {
		manifests++;
		add("otro", [syntheticEntry(subcarpetaLabel(ruta), options.sinLock)]);
	}

	for (const file of await findUnsupportedManifests(workDir)) {
		manifests++;
		add("otro", [
			syntheticEntry(
				`(gestor no soportado: ${file})`,
				options.gestorNoSoportado,
			),
		]);
	}

	// Ecosystem-aware key; on a collision the stricter verdict wins.
	const unique = new Map<string, LicenseEntry>();
	for (const { eco, entry: e } of entries) {
		const key = e.paquete.startsWith("(")
			? e.paquete
			: eco === "pypi"
				? `pypi:${normalizePypiName(e.paquete)}@${e.version}`
				: `${eco}:${e.paquete}@${e.version}`;
		const prev = unique.get(key);
		if (!prev || RANK[e.veredicto] > RANK[prev.veredicto]) unique.set(key, e);
	}
	const sorted = [...unique.values()].sort(
		(a, b) => compare(a.paquete, b.paquete) || compare(a.version, b.version),
	);
	const avisos = manifests === 0 ? [AVISO_SIN_GESTOR] : [...avisosExtra];
	if (options.mctDir !== undefined) {
		await writeLicenseAvisos(options.mctDir, avisos);
	}
	return {
		entries: sorted,
		resumen: summarize(sorted),
		sinPresupuesto,
		avisos,
	};
}
