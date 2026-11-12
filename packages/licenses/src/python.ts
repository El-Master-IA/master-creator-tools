import { lstat, readdir, readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import { parse as parseToml } from "smol-toml";
import { type AuditResult, type FetchLike, pool, summarize } from "./audit.js";
import {
	fetchPypiSpdx,
	isValidPypiName,
	isValidPypiVersion,
	normalizePypiName,
} from "./pypi.js";
import {
	judgePackage,
	type LicenseAllow,
	type LicenseEntry,
} from "./verdict.js";

export interface MotivoConfig {
	motivo: string;
}

export interface PythonAuditOptions {
	/** Directory with the manifests (`.mct/work`). */
	workDir: string;
	allow?: readonly LicenseAllow[];
	/** `licenses.sinLock` of mct.config.json: accepts the synthetic lockfile entries. */
	sinLock?: MotivoConfig;
	/** Skips PyPI (LIC-005). */
	offline?: boolean;
	/**
	 * `.mct/quarantine`: read only for the NAMES of variables (PIP_INDEX_URL...), never
	 * for values, to detect a private index declared outside the requirements.
	 */
	quarantineDir?: string;
	fetch?: FetchLike;
	/** Per-package PyPI timeout (default 10 s). */
	timeoutMs?: number;
	/** Parallel PyPI requests (default and ceiling: 8). */
	concurrency?: number;
	/** Global budget: PyPI requests per audit (default 500). The rest stay in revisar. */
	maxRegistryQueries?: number;
	/** Global wall-clock budget for the network use of the audit (default 300 000 ms). */
	maxTotalMs?: number;
	/** Largest PyPI body accepted (default 5 MB). */
	maxBodyBytes?: number;
	/** Version for the `mct/<version>` User-Agent. */
	mctVersion?: string;
}

export interface PythonAuditResult extends AuditResult {
	/**
	 * `["sin-gestor"]` when the project has no dependency manifest at all;
	 * `"indice-privado-fuera"` when a private index was found outside requirements.
	 */
	avisos: string[];
}

export const SIN_LOCKFILE = "(dependencias transitivas sin lockfile)";
export const POETRY_SIN_LOCK = "(instalación sin respetar poetry.lock)";
export const AVISO_INDICE_PRIVADO = "indice-privado-fuera";
export const subcarpetaLabel = (ruta: string): string =>
	`(manifiesto en subcarpeta: ${ruta})`;

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CONCURRENCY = 8;
const MAX_CONCURRENCY = 8;
const DEFAULT_MAX_QUERIES = 500;
const DEFAULT_MAX_TOTAL_MS = 300_000;
const DEFAULT_MAX_BODY = 5_000_000;
const MAX_FILE_BYTES = 16_000_000;
const MAX_PACKAGES = 50_000;
const MIN_REASON = 10;
const MAX_REASON = 500;
const PYPI_SIMPLE = "https://pypi.org/simple";

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

function fileError(mensaje: string, detalle?: Record<string, unknown>) {
	return new MctError("VALIDACION", mensaje, {
		accion: "Regenera el lockfile o corrige el manifiesto Python",
		...(detalle !== undefined && { detalle }),
	});
}

/** Reads a regular file (no symlinks); `undefined` if it does not exist. */
export async function readRegularFile(
	path: string,
	maxBytes = MAX_FILE_BYTES,
): Promise<string | undefined> {
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw fileError("No se pudo inspeccionar un archivo de dependencias");
	}
	if (st.isSymbolicLink() || !st.isFile() || st.size > maxBytes) {
		throw fileError(
			"Un archivo de dependencias debe ser regular y sin enlaces",
		);
	}
	try {
		return await readFile(path, "utf8");
	} catch {
		throw fileError("No se pudo leer un archivo de dependencias");
	}
}

/** Accepts the motivo only when it has 10 to 500 visible characters (config rule). */
export function validMotivo(
	config: MotivoConfig | undefined,
): string | undefined {
	if (!config || typeof config.motivo !== "string") return undefined;
	const clean = config.motivo.replace(/\p{Cf}/gu, "").trim();
	return clean.length >= MIN_REASON && clean.length <= MAX_REASON
		? clean
		: undefined;
}

/** Synthetic `revisar` entry; accepted (ok + override) only with a valid motivo. */
export function syntheticEntry(
	paquete: string,
	acceptance: MotivoConfig | undefined,
): LicenseEntry {
	const motivo = validMotivo(acceptance);
	return {
		paquete,
		version: "",
		spdx: null,
		origen: "directa",
		veredicto: motivo === undefined ? "revisar" : "ok",
		...(motivo !== undefined && { override: { motivo } }),
	};
}

// ---------- dependency model ----------

interface PyDep {
	paquete: string;
	/** Exact version, or "" when none. */
	version: string;
	directa: boolean;
	/** True only when PyPI may be asked (exact version, public index). */
	consultar: boolean;
}

// ---------- requirement lines (requirements*.txt and [project.dependencies]) ----------

const EXACT =
	/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$/;
const NAME_PREFIX = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/;
const DIRECT_REF =
	/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*@\s*\S+/;
const VCS = /^(?:git|hg|svn|bzr)\+/i;
const ARCHIVE = /\.(?:whl|zip|tar\.gz|tgz|tar\.bz2|tar)$/i;

const NON_PUBLIC = "(origen no público)";
const URL_TOKEN = /(?:(?:git|hg|svn|bzr)\+)?[A-Za-z][A-Za-z0-9+.-]*:\/\/\S*/g;

/** One URL without credentials, query or fragment; unparsable becomes a fixed label. */
function cleanUrl(token: string): string {
	const rest = token.replace(/^(?:git|hg|svn|bzr)\+/i, "");
	const noFragment = rest.split(/[#?]/, 1)[0] ?? "";
	try {
		const first = new URL(noFragment);
		let target = noFragment;
		if (first.username !== "" || first.password !== "") {
			// Credentials may hold `@` or `/`: keep only what follows the last `@`.
			const tail = noFragment.slice(noFragment.lastIndexOf("@") + 1);
			target = `${first.protocol}//${tail}`;
		}
		const u = new URL(target);
		u.username = "";
		u.password = "";
		u.search = "";
		u.hash = "";
		return `${u.protocol}//${u.host}${u.pathname}`;
	} catch {
		return NON_PUBLIC;
	}
}

/** Drops credentials and bounds the label of an entry that has no package name. */
function safeLabel(text: string): string {
	return text.replace(URL_TOKEN, (token) => cleanUrl(token)).slice(0, 200);
}

function stripComment(line: string): string {
	const m = /(^|\s)#/.exec(line);
	return (m ? line.slice(0, m.index) : line).trim();
}

function logicalLines(text: string): string[] {
	const out: string[] = [];
	let acc = "";
	for (const raw of text.split(/\r?\n/)) {
		const line = raw.trimEnd();
		if (line.endsWith("\\")) {
			acc += `${line.slice(0, -1)} `;
			continue;
		}
		out.push(stripComment(acc + line));
		acc = "";
	}
	if (acc !== "") out.push(stripComment(acc));
	return out.filter((l) => l !== "");
}

function parseRequirement(line: string): PyDep {
	// Per-requirement options such as `--hash=...` come after the specifier.
	const spec = line.split(/\s+--?[A-Za-z]/, 1)[0]?.trim() ?? line;
	const direct = DIRECT_REF.exec(spec);
	if (direct) {
		return {
			paquete: direct[1] as string,
			version: "",
			directa: true,
			consultar: false,
		};
	}
	const isLocal =
		VCS.test(spec) ||
		spec.includes("://") ||
		/^(?:\.{1,2}[\\/]|[\\/~]|[A-Za-z]:[\\/])/.test(spec) ||
		spec === "." ||
		ARCHIVE.test(spec);
	if (isLocal) {
		const egg = /[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec);
		return {
			paquete: egg?.[1] ?? safeLabel(spec),
			version: "",
			directa: true,
			consultar: false,
		};
	}
	const exact = EXACT.exec(spec);
	if (exact) {
		return {
			paquete: exact[1] as string,
			version: exact[2] as string,
			directa: true,
			consultar: true,
		};
	}
	const name = NAME_PREFIX.exec(spec);
	return {
		paquete: name?.[0] ?? safeLabel(spec),
		version: "",
		directa: true,
		consultar: false,
	};
}

// Closed list of options known to be harmless for the source of packages. Anything else
// that starts with "-" (index, find-links, no-index, trusted-host, optparse abbreviations
// such as --ind) leaves the whole file unqueried (fail closed).
const SAFE_FLAGS = new Set([
	"--hash",
	"--pre",
	"--prefer-binary",
	"--only-binary",
	"--no-binary",
	"--require-hashes",
	"--use-feature",
]);
const INCLUDE_FLAGS = new Set(["-r", "--requirement", "-c", "--constraint"]);
const EDITABLE_FLAGS = new Set(["-e", "--editable"]);
const NO_ARG_FLAGS = new Set(["--pre", "--prefer-binary", "--require-hashes"]);

/** shlex-like split: whitespace separates, quotes and backslashes group. */
function shellTokens(line: string): string[] {
	const out: string[] = [];
	let cur = "";
	let has = false;
	let quote: string | undefined;
	for (let i = 0; i < line.length; i++) {
		const ch = line[i] as string;
		if (quote !== undefined) {
			if (ch === quote) quote = undefined;
			else if (ch === "\\" && quote === '"' && i + 1 < line.length) {
				cur += line[++i];
			} else cur += ch;
		} else if (ch === '"' || ch === "'") {
			quote = ch;
			has = true;
		} else if (ch === "\\" && i + 1 < line.length) {
			cur += line[++i];
			has = true;
		} else if (/\s/.test(ch)) {
			if (has || cur !== "") out.push(cur);
			cur = "";
			has = false;
		} else {
			cur += ch;
		}
	}
	if (has || cur !== "") out.push(cur);
	return out;
}

/** Splits `--flag=value` into the flag and the first argument. */
function splitFlag(token: string): { flag: string; inline: string[] } {
	const eq = token.startsWith("--") ? token.indexOf("=") : -1;
	return eq === -1
		? { flag: token, inline: [] }
		: { flag: token.slice(0, eq), inline: [token.slice(eq + 1)] };
}

export interface ParsedRequirements {
	deps: PyDep[];
	/** True when the file declares an index, find-links or `--no-index`. */
	privateIndex: boolean;
	/** Targets of `-r` / `-c`, as written. */
	includes: string[];
}

/** Parses one requirements file. A custom index makes the whole file non-queryable. */
export function parseRequirementsText(text: string): PyDep[] {
	const parsed = parseRequirementsDetailed(text);
	return parsed.privateIndex
		? parsed.deps.map((d) => ({ ...d, consultar: false }))
		: parsed.deps;
}

export function parseRequirementsDetailed(text: string): ParsedRequirements {
	const deps: PyDep[] = [];
	const includes: string[] = [];
	let privateIndex = false;
	for (const line of logicalLines(text)) {
		if (line.startsWith("-")) {
			const tokens = shellTokens(line);
			const { flag, inline } = splitFlag(tokens[0] ?? line);
			const args = [...inline, ...tokens.slice(1)];
			// Any further option on the same line must not hide an index.
			const extraOption = args.some((a) => a.startsWith("-"));
			if (INCLUDE_FLAGS.has(flag)) {
				includes.push((args[0] ?? "").trim());
				if (extraOption || args.length > 1) privateIndex = true;
			} else if (EDITABLE_FLAGS.has(flag)) {
				const value = args.join(" ").trim();
				const egg = /[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(value);
				deps.push({
					paquete: egg?.[1] ?? safeLabel(`-e ${value}`),
					version: "",
					directa: true,
					consultar: false,
				});
				if (extraOption) privateIndex = true;
			} else if (NO_ARG_FLAGS.has(flag)) {
				if (args.length > 0) privateIndex = true;
			} else if (SAFE_FLAGS.has(flag)) {
				if (extraOption) privateIndex = true;
			} else {
				privateIndex = true;
			}
			continue;
		}
		// Per-requirement options: only `--hash` is harmless.
		if (
			shellTokens(line).some(
				(tok) => tok.startsWith("-") && !tok.startsWith("--hash"),
			)
		) {
			privateIndex = true;
		}
		deps.push(parseRequirement(line));
	}
	return { deps, privateIndex, includes };
}

const MAX_INCLUDE_DEPTH = 5;

/**
 * Parses a requirements file and the files it pulls in with `-r`/`-c`. If any file of
 * the chain declares an index, or an include cannot be followed safely (outside the
 * workspace, missing, too deep), every dependency of the chain stays unqueried.
 */
async function loadRequirements(
	workDir: string,
	file: string,
	seen: Set<string>,
	depth: number,
): Promise<{ deps: PyDep[]; privateIndex: boolean }> {
	const abs = resolve(workDir, file);
	const rel = relative(resolve(workDir), abs);
	if (rel.startsWith("..") || isAbsolute(rel) || seen.has(abs)) {
		return { deps: [], privateIndex: !seen.has(abs) };
	}
	seen.add(abs);
	const text = await readRegularFile(abs);
	if (text === undefined) return { deps: [], privateIndex: true };
	const parsed = parseRequirementsDetailed(text);
	let deps = parsed.deps;
	let privateIndex = parsed.privateIndex;
	for (const target of parsed.includes) {
		if (
			depth >= MAX_INCLUDE_DEPTH ||
			target === "" ||
			/^[a-z]+:\/\//i.test(target)
		) {
			privateIndex = true;
			continue;
		}
		const inner = await loadRequirements(
			workDir,
			join(dirname(abs), target),
			seen,
			depth + 1,
		);
		deps = deps.concat(inner.deps);
		privateIndex = privateIndex || inner.privateIndex;
	}
	return { deps, privateIndex };
}

// ---------- lockfiles ----------

function tomlOf(text: string, que: string): Record<string, unknown> {
	try {
		const doc: unknown = parseToml(text);
		if (isObj(doc)) return doc;
	} catch {
		// falls through to the error below
	}
	throw fileError(`${que} no es un TOML válido`);
}

const isPublicIndex = (url: unknown): boolean =>
	typeof url === "string" && url.replace(/\/+$/, "") === PYPI_SIMPLE;

function depNames(list: unknown): string[] {
	if (!Array.isArray(list)) return [];
	return list.flatMap((d) => {
		if (isObj(d) && typeof d.name === "string") return [d.name];
		if (typeof d === "string") return NAME_PREFIX.exec(d)?.slice(0, 1) ?? [];
		return [];
	});
}

function tableDepNames(table: unknown): string[] {
	if (!isObj(table)) return [];
	return Object.values(table).flatMap(depNames);
}

export function parseUvLock(text: string): PyDep[] {
	const doc = tomlOf(text, "uv.lock");
	const list = doc.package;
	if (!Array.isArray(list)) return [];
	const direct = new Set<string>();
	const pkgs: Record<string, unknown>[] = [];
	for (const raw of list) {
		if (!isObj(raw) || typeof raw.name !== "string") continue;
		const source = isObj(raw.source) ? raw.source : {};
		if ("virtual" in source || "editable" in source) {
			// The project itself (or a workspace member): it names the direct deps.
			for (const n of [
				...depNames(raw.dependencies),
				...tableDepNames(raw["dev-dependencies"]),
				...tableDepNames(raw["optional-dependencies"]),
			]) {
				direct.add(normalizePypiName(n));
			}
			continue;
		}
		pkgs.push(raw);
	}
	return pkgs.map((raw) => {
		const source = isObj(raw.source) ? raw.source : {};
		const version = typeof raw.version === "string" ? raw.version : "";
		const paquete = raw.name as string;
		return {
			paquete,
			version,
			directa: direct.has(normalizePypiName(paquete)),
			consultar: isPublicIndex(source.registry) && version !== "",
		};
	});
}

function poetryDirectNames(pyproject: Record<string, unknown> | undefined) {
	const names = new Set<string>();
	if (!pyproject) return names;
	const project = isObj(pyproject.project) ? pyproject.project : {};
	for (const n of depNames(project.dependencies))
		names.add(normalizePypiName(n));
	const tool = isObj(pyproject.tool) ? pyproject.tool : {};
	const poetry = isObj(tool.poetry) ? tool.poetry : {};
	const tables: unknown[] = [poetry.dependencies, poetry["dev-dependencies"]];
	if (isObj(poetry.group)) {
		for (const g of Object.values(poetry.group)) {
			if (isObj(g)) tables.push(g.dependencies);
		}
	}
	for (const t of tables) {
		if (!isObj(t)) continue;
		for (const key of Object.keys(t)) {
			if (key.toLowerCase() !== "python") names.add(normalizePypiName(key));
		}
	}
	return names;
}

export function parsePoetryLock(
	text: string,
	pyproject?: Record<string, unknown>,
): PyDep[] {
	const doc = tomlOf(text, "poetry.lock");
	const list = doc.package;
	if (!Array.isArray(list)) return [];
	const direct = poetryDirectNames(pyproject);
	const out: PyDep[] = [];
	for (const raw of list) {
		if (!isObj(raw) || typeof raw.name !== "string") continue;
		const version = typeof raw.version === "string" ? raw.version : "";
		const source = raw.source;
		const publicSource =
			source === undefined ||
			(isObj(source) && source.type === "legacy" && isPublicIndex(source.url));
		out.push({
			paquete: raw.name,
			version,
			directa: direct.has(normalizePypiName(raw.name)),
			consultar: publicSource && version !== "",
		});
	}
	return out;
}

// ---------- manifest discovery ----------

const REQUIREMENTS_FILE = /^requirements[A-Za-z0-9._-]*\.txt$/;

export interface PythonManifests {
	uvLock: boolean;
	poetryLock: boolean;
	requirements: string[];
	pyproject: boolean;
	/** setup.py or Pipfile: a dependency manifest this audit does not parse. */
	otherManifest: boolean;
}

/**
 * True when a manifest exists as a regular file; false when it does not exist.
 * A manifest that is a symlink or not a regular file fails closed (LIC-005).
 */
async function isFile(path: string): Promise<boolean> {
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw fileError("No se pudo inspeccionar un archivo de dependencias");
	}
	if (st.isSymbolicLink() || !st.isFile()) {
		throw fileError(
			"Un archivo de dependencias debe ser regular y sin enlaces",
		);
	}
	return true;
}

/** Python manifests at the root of `workDir` (LIC-005). */
export async function findPythonManifests(
	workDir: string,
): Promise<PythonManifests> {
	let names: string[] = [];
	try {
		names = await readdir(workDir);
	} catch {
		names = [];
	}
	const requirements: string[] = [];
	for (const n of names.sort()) {
		if (REQUIREMENTS_FILE.test(n) && (await isFile(join(workDir, n)))) {
			requirements.push(n);
		}
	}
	return {
		uvLock: await isFile(join(workDir, "uv.lock")),
		poetryLock: await isFile(join(workDir, "poetry.lock")),
		requirements,
		pyproject: await isFile(join(workDir, "pyproject.toml")),
		otherManifest:
			(await isFile(join(workDir, "setup.py"))) ||
			(await isFile(join(workDir, "Pipfile"))),
	};
}

export function hasPythonManifest(m: PythonManifests): boolean {
	return (
		m.uvLock ||
		m.poetryLock ||
		m.requirements.length > 0 ||
		m.pyproject ||
		m.otherManifest
	);
}

// ---------- bounded search outside the manifests (LIC-005, LIC-006) ----------

const SCAN_SKIPPED = new Set(["node_modules", ".git", ".venv"]);
const SCAN_MAX_DEPTH = 3;
const SCAN_MAX_READS = 200;
const SCAN_MAX_VISITS = 5_000;
const SCAN_MAX_FILE_BYTES = 1_000_000;
const MAX_NESTED = 50;

const INDEX_TEXT =
	/--index-url|--extra-index-url|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL/i;
const INDEX_VAR_NAME = /^PIP_(?:EXTRA_)?INDEX_URL$/i;
const INDEX_CANDIDATE =
	/^(?:Dockerfile.*|.*\.ya?ml|Makefile|tox\.ini|setup\.cfg|\.env\.example)$/;
const VAR_NAME_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/gm;

interface ScanFile {
	rel: string;
	abs: string;
	name: string;
	depth: number;
	size: number;
}

/** Walks to depth 3 without following links; `visit` returns true to stop. */
async function scanTree(
	root: string,
	visit: (file: ScanFile) => Promise<boolean>,
	visitDir?: (name: string) => boolean,
): Promise<void> {
	let visits = 0;
	let stop = false;
	async function walk(rel: string, depth: number): Promise<void> {
		let items: import("node:fs").Dirent[];
		try {
			items = await readdir(join(root, rel), { withFileTypes: true });
		} catch {
			return;
		}
		items.sort((a, b) => compare(a.name, b.name));
		for (const item of items) {
			if (stop || ++visits > SCAN_MAX_VISITS) return;
			if (item.isSymbolicLink()) continue;
			const path = rel === "" ? item.name : `${rel}/${item.name}`;
			if (item.isDirectory()) {
				if (visitDir?.(item.name) === true) {
					stop = true;
					return;
				}
				if (depth < SCAN_MAX_DEPTH && !SCAN_SKIPPED.has(item.name)) {
					await walk(path, depth + 1);
				}
			} else if (item.isFile()) {
				const abs = join(root, path);
				let size = 0;
				try {
					size = (await lstat(abs)).size;
				} catch {
					continue;
				}
				if (await visit({ rel: path, abs, name: item.name, depth, size })) {
					stop = true;
					return;
				}
			}
		}
	}
	await walk("", 0);
}

async function readSmall(file: ScanFile): Promise<string | undefined> {
	if (file.size > SCAN_MAX_FILE_BYTES) return undefined;
	try {
		return await readFile(file.abs, "utf8");
	} catch {
		return undefined;
	}
}

/**
 * LIC-005: true when a private index is configured outside requirements (pip.conf,
 * pip.ini, .pip/, or an index option/variable in Dockerfile*, YAML, Makefile, tox.ini,
 * setup.cfg, .env.example, or a variable NAME in quarantine). Bounded: depth 3, 200
 * reads, files up to 1 MB, no links. Quarantine is read for names only, never values.
 */
export async function detectPrivateIndexOutside(
	workDir: string,
	quarantineDir?: string,
): Promise<boolean> {
	let reads = 0;
	let found = false;
	await scanTree(
		workDir,
		async (file) => {
			if (file.name === "pip.conf" || file.name === "pip.ini") {
				found = true;
				return true;
			}
			if (!INDEX_CANDIDATE.test(file.name) || reads >= SCAN_MAX_READS) {
				return false;
			}
			reads++;
			const text = await readSmall(file);
			if (text !== undefined && INDEX_TEXT.test(text)) {
				found = true;
				return true;
			}
			return false;
		},
		(dirName) => {
			if (dirName === ".pip") found = true;
			return found;
		},
	);
	if (found || quarantineDir === undefined) return found;
	let qReads = 0;
	await scanTree(quarantineDir, async (file) => {
		if (qReads >= SCAN_MAX_READS) return false;
		qReads++;
		const text = await readSmall(file);
		if (text === undefined) return false;
		for (const m of text.matchAll(VAR_NAME_LINE)) {
			if (INDEX_VAR_NAME.test(m[1] ?? "")) {
				found = true;
				return true;
			}
		}
		return false;
	});
	return found;
}

const NODE_NESTED = new Set([
	"package.json",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
]);
const PYTHON_NESTED = new Set(["pyproject.toml", "uv.lock", "poetry.lock"]);

/**
 * Dependency manifests below the root (depth 1 to 3) as POSIX relative paths (LIC-005,
 * LIC-006). `python` limits the search to requirements*.txt, pyproject.toml and python locks.
 */
export async function findNestedManifests(
	workDir: string,
	kind: "python" | "all",
): Promise<string[]> {
	const out: string[] = [];
	await scanTree(workDir, async (file) => {
		if (file.depth === 0) return false;
		const python =
			PYTHON_NESTED.has(file.name) || REQUIREMENTS_FILE.test(file.name);
		if (python || (kind === "all" && NODE_NESTED.has(file.name))) {
			out.push(file.rel.slice(0, 200));
		}
		return out.length >= MAX_NESTED;
	});
	return out;
}

// ---------- audit ----------

function merge(list: readonly PyDep[]): PyDep[] {
	const byId = new Map<string, PyDep>();
	for (const dep of list) {
		const id = `${normalizePypiName(dep.paquete)}@${dep.version}`;
		const prev = byId.get(id);
		if (!prev) {
			byId.set(id, { ...dep });
			continue;
		}
		prev.directa = prev.directa || dep.directa;
		prev.consultar = prev.consultar && dep.consultar;
	}
	if (byId.size > MAX_PACKAGES) {
		throw fileError("El árbol de dependencias es demasiado grande", {
			maximo: MAX_PACKAGES,
		});
	}
	return [...byId.values()];
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

async function collectRaw(
	workDir: string,
	m: PythonManifests,
	pyproject: Record<string, unknown> | undefined,
): Promise<PyDep[]> {
	if (m.uvLock) {
		return parseUvLock((await readRegularFile(join(workDir, "uv.lock"))) ?? "");
	}
	if (m.poetryLock) {
		return parsePoetryLock(
			(await readRegularFile(join(workDir, "poetry.lock"))) ?? "",
			pyproject,
		);
	}
	if (m.requirements.length > 0) {
		const all: PyDep[] = [];
		for (const file of m.requirements) {
			const chain = await loadRequirements(workDir, file, new Set(), 0);
			all.push(
				...(chain.privateIndex
					? chain.deps.map((d) => ({ ...d, consultar: false }))
					: chain.deps),
			);
		}
		return all;
	}
	if (pyproject) {
		const project = isObj(pyproject.project) ? pyproject.project : {};
		const deps = project.dependencies;
		if (!Array.isArray(deps)) return [];
		return deps
			.filter((d): d is string => typeof d === "string")
			.map((d) => parseRequirement(d.trim()))
			.filter((d) => d.paquete !== "");
	}
	return [];
}

/** True when pyproject.toml configures an index or source other than pypi.org. */
export function pyprojectUsesPrivateSource(
	pyproject: Record<string, unknown> | undefined,
): boolean {
	if (!pyproject || !isObj(pyproject.tool)) return false;
	const risky = /index|source|find-links|no-index/i;
	const walk = (node: unknown, depth: number): boolean => {
		if (depth > 32) return true; // fail closed on absurd nesting
		if (Array.isArray(node)) return node.some((n) => walk(n, depth + 1));
		if (!isObj(node)) return false;
		return Object.entries(node).some(
			([key, value]) => risky.test(key) || walk(value, depth + 1),
		);
	};
	return walk(pyproject.tool, 0);
}

async function collect(workDir: string, m: PythonManifests): Promise<PyDep[]> {
	const pyprojectText = m.pyproject
		? await readRegularFile(join(workDir, "pyproject.toml"))
		: undefined;
	const pyproject =
		pyprojectText !== undefined
			? tomlOf(pyprojectText, "pyproject.toml")
			: undefined;
	const deps = await collectRaw(workDir, m, pyproject);
	return pyprojectUsesPrivateSource(pyproject)
		? deps.map((d) => ({ ...d, consultar: false }))
		: deps;
}

const vacio = (v: unknown): boolean =>
	v === undefined ||
	(Array.isArray(v) && v.length === 0) ||
	(isObj(v) && Object.keys(v).length === 0);

/**
 * LIC-005: true only when the project positively declares nothing to install, so the
 * missing-lockfile entry can be skipped. Anything unparsed, dynamic, grouped, private
 * or unreadable counts as declaring (fail closed).
 */
async function declaraNada(
	workDir: string,
	m: PythonManifests,
): Promise<boolean> {
	if (m.otherManifest || m.uvLock || m.poetryLock) return false;
	for (const file of m.requirements) {
		const chain = await loadRequirements(workDir, file, new Set(), 0);
		if (chain.privateIndex || chain.deps.length > 0) return false;
	}
	if (!m.pyproject) return true;
	const text = await readRegularFile(join(workDir, "pyproject.toml"));
	if (text === undefined) return false;
	let doc: Record<string, unknown>;
	try {
		doc = tomlOf(text, "pyproject.toml");
	} catch {
		return false;
	}
	const project = isObj(doc.project) ? doc.project : {};
	if (
		Array.isArray(project.dynamic) &&
		project.dynamic.includes("dependencies")
	)
		return false;
	if (
		project.dependencies !== undefined &&
		!Array.isArray(project.dependencies)
	)
		return false;
	if (!vacio(project.dependencies) || !vacio(project["optional-dependencies"]))
		return false;
	if (!vacio(doc["dependency-groups"])) return false;
	const tool = isObj(doc.tool) ? doc.tool : {};
	const poetry = isObj(tool.poetry) ? tool.poetry : {};
	const poetryDeps = isObj(poetry.dependencies) ? poetry.dependencies : {};
	if (Object.keys(poetryDeps).some((k) => k !== "python")) return false;
	if (!vacio(poetry.group) || !vacio(poetry["dev-dependencies"])) return false;
	const pdm = isObj(tool.pdm) ? tool.pdm : {};
	const uv = isObj(tool.uv) ? tool.uv : {};
	if (!vacio(pdm["dev-dependencies"]) || !vacio(uv["dev-dependencies"]))
		return false;
	return true;
}

/** Full Python dependency audit (LIC-005). */
export async function auditPython(
	options: PythonAuditOptions,
): Promise<PythonAuditResult> {
	const manifests = await findPythonManifests(options.workDir);
	const outside =
		options.offline === true
			? false
			: await detectPrivateIndexOutside(options.workDir, options.quarantineDir);
	const collected = await collect(options.workDir, manifests);
	const deps = merge(
		outside ? collected.map((d) => ({ ...d, consultar: false })) : collected,
	);
	const nested = await findNestedManifests(options.workDir, "python");
	const fetchFn: FetchLike = options.fetch ?? ((url, init) => fetch(url, init));
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
	const mctVersion = options.mctVersion ?? "0.0.0";
	const deadline = Date.now() + (options.maxTotalMs ?? DEFAULT_MAX_TOTAL_MS);
	let queries = Math.max(0, options.maxRegistryQueries ?? DEFAULT_MAX_QUERIES);
	let skipped = 0;
	const spdxOf = new Map<PyDep, string | undefined>();

	await pool(
		deps,
		Math.min(options.concurrency ?? DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
		async (dep) => {
			if (
				options.offline === true ||
				!dep.consultar ||
				!isValidPypiName(dep.paquete) ||
				!isValidPypiVersion(dep.version)
			) {
				return;
			}
			const remaining = deadline - Date.now();
			if (queries <= 0 || remaining <= 0) {
				skipped++;
				return;
			}
			queries--;
			spdxOf.set(
				dep,
				await fetchPypiSpdx(dep.paquete, dep.version, {
					fetch: fetchFn,
					timeoutMs,
					maxBytes,
					mctVersion,
					remainingMs: remaining,
				}),
			);
		},
	);

	const allow = options.allow ?? [];
	const entries: LicenseEntry[] = deps
		.map((dep) =>
			judgePackage(
				{
					paquete: dep.paquete,
					version: dep.version,
					spdx: spdxOf.get(dep) ?? null,
					origen: dep.directa ? "directa" : "transitiva",
				},
				allow,
			),
		)
		.sort(
			(a, b) => compare(a.paquete, b.paquete) || compare(a.version, b.version),
		);
	const anyManifest = hasPythonManifest(manifests);
	// LIC-005: without a lock, the transitive tree is unknown only if something is
	// declared; setup.py/Pipfile are not parsed, so they always count as declaring.
	const declara =
		deps.length > 0 || !(await declaraNada(options.workDir, manifests));
	if (anyManifest && declara && !manifests.uvLock && !manifests.poetryLock) {
		entries.unshift(syntheticEntry(SIN_LOCKFILE, options.sinLock));
	}
	if (manifests.poetryLock && !manifests.uvLock) {
		entries.unshift(syntheticEntry(POETRY_SIN_LOCK, options.sinLock));
	}
	for (const ruta of nested) {
		entries.push(syntheticEntry(subcarpetaLabel(ruta), options.sinLock));
	}
	const avisos: string[] = [];
	if (!anyManifest && nested.length === 0) avisos.push("sin-gestor");
	if (outside) avisos.push(AVISO_INDICE_PRIVADO);
	return {
		entries,
		resumen: summarize(entries),
		sinPresupuesto: skipped,
		avisos,
	};
}
