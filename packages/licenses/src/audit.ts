import { lstat, readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { MctError } from "@mct/contract/errors";
import { parseAllDocuments } from "yaml";
import {
	judgePackage,
	type LicenseAllow,
	type LicenseEntry,
} from "./verdict.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface ExtraPackage {
	paquete: string;
	version: string;
}

export interface AuditOptions {
	/** Directory with the lockfile (`.mct/work`). */
	lockDir: string;
	/** Root of the origin project: its `node_modules` is read, never written (LIC-004 b). */
	originDir?: string;
	/** Picks one lockfile when several are present; otherwise several = blocked. */
	lockfile?: "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock";
	/** Skips the registry (LIC-004 c). */
	offline?: boolean;
	/** Packages that have no lockfile (n8n community nodes); they use the registry. */
	extra?: readonly ExtraPackage[];
	allow?: readonly LicenseAllow[];
	fetch?: FetchLike;
	/** Per-package registry timeout (default 10 s). */
	timeoutMs?: number;
	/** Parallel registry requests (default and ceiling: 8). */
	concurrency?: number;
	/** Global budget: registry requests per audit (default 500). The rest stay in revisar. */
	maxRegistryQueries?: number;
	/** Global budget: package.json reads under the origin per audit (default 100 000). */
	maxOriginReads?: number;
	/** Global wall-clock budget for the whole audit's network use (default 300 000 ms). */
	maxTotalMs?: number;
	/** Largest registry body accepted (default 5 MB). */
	maxBodyBytes?: number;
}

export interface AuditSummary {
	paquetes: number;
	bloquea: number;
	revisar: number;
	overrides: number;
}

export interface AuditResult {
	entries: LicenseEntry[];
	resumen: AuditSummary;
	/** Packages whose SPDX lookup was skipped because a global budget ran out (stay revisar). */
	sinPresupuesto: number;
}

const REGISTRY = "https://registry.npmjs.org";
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CONCURRENCY = 8;
const MAX_CONCURRENCY = 8;
const DEFAULT_MAX_REGISTRY_QUERIES = 500;
const DEFAULT_MAX_ORIGIN_READS = 100_000;
const DEFAULT_MAX_TOTAL_MS = 300_000;
const DEFAULT_MAX_BODY = 5_000_000;
const MAX_LOCK_BYTES = 64_000_000;
const MAX_PACKAGE_JSON_BYTES = 1_000_000;
const MAX_PACKAGES = 50_000;
const MAX_SPDX_LENGTH = 200;

// Linear patterns: no nested quantifiers. A name can never start with "." (no "..").
const NAME =
	/^(?:@[A-Za-z0-9_~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]*$/;
const SEGMENT = /^@?[A-Za-z0-9_~-][A-Za-z0-9._~-]*$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]*$/;

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

const validName = (n: string): boolean => n.length <= 214 && NAME.test(n);
const validVersion = (v: string): boolean => v.length <= 128 && VERSION.test(v);

function lockError(mensaje: string, detalle?: Record<string, unknown>) {
	return new MctError("VALIDACION", mensaje, {
		accion: "Regenera el lockfile con tu gestor de paquetes",
		...(detalle !== undefined && { detalle }),
	});
}

interface Pkg {
	paquete: string;
	version: string;
	directa: boolean;
	license: string | undefined;
	/** Candidate package directories under the origin (segments). */
	rutas: string[][];
	/** True only when the entry was resolved from the npm registry (source (c) is valid). */
	registro: boolean;
}

/**
 * What the project declares: `names` for "is it direct", `checked` for "the lockfile must
 * account for it" (optional peers are never installed), `nopeer` (yarn v1 never installs peers).
 */
interface Declared {
	names: Map<string, string>;
	checked: Map<string, string>;
	nopeer: Map<string, string>;
}

/** What a lockfile says: packages, every name it accounts for, and what the project declares. */
interface Tree {
	pkgs: Pkg[];
	known: Set<string>;
	declared: Map<string, string>;
}

const REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

function isRegistryUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === "https:" && REGISTRY_HOSTS.has(url.hostname);
	} catch {
		return false;
	}
}

/** `https://registry.../<name>/-/<file>.tgz` gives the real package name. */
function nameFromRegistryUrl(value: string): string | undefined {
	try {
		const path = new URL(value).pathname;
		const cut = path.indexOf("/-/");
		if (cut <= 1) return undefined;
		return decodeURIComponent(path.slice(1, cut));
	} catch {
		return undefined;
	}
}

// ---------- license value ----------

function oneLicense(v: unknown): string | undefined {
	if (typeof v === "string") {
		const t = v.trim();
		return t === "" || t.length > MAX_SPDX_LENGTH ? undefined : t;
	}
	if (isObj(v)) return oneLicense(v.type);
	return undefined;
}

/** `license` as a string, `{ type }` or the legacy `licenses` array. */
function licenseOf(doc: Record<string, unknown>): string | undefined {
	const direct = oneLicense(doc.license);
	if (direct !== undefined) return direct;
	const legacy = doc.license ?? doc.licenses;
	if (Array.isArray(legacy)) {
		const ids = legacy.map(oneLicense);
		if (ids.length === 0 || ids.some((id) => id === undefined))
			return undefined;
		return ids.length === 1 ? ids[0] : `(${ids.join(" OR ")})`;
	}
	return undefined;
}

// ---------- files ----------

async function readRegular(
	path: string,
	maxBytes: number,
): Promise<string | undefined> {
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw lockError("No se pudo inspeccionar un archivo de dependencias");
	}
	if (st.isSymbolicLink() || !st.isFile() || st.size > maxBytes) {
		throw lockError("El lockfile debe ser un archivo regular (sin enlaces)");
	}
	try {
		return await readFile(path, "utf8");
	} catch {
		throw lockError("No se pudo leer un archivo de dependencias");
	}
}

function parseJson(text: string, que: string): unknown {
	try {
		return JSON.parse(text.replace(/^﻿/, ""));
	} catch {
		throw lockError(`${que} no es JSON válido`);
	}
}

const DEP_FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
] as const;

type DepMode = "names" | "checked" | "nopeer";

function isOptionalPeer(doc: Record<string, unknown>, name: string): boolean {
	const meta = doc.peerDependenciesMeta;
	if (!isObj(meta)) return false;
	const one = meta[name];
	return isObj(one) && one.optional === true;
}

function depSpecs(doc: unknown, mode: DepMode): Map<string, string> {
	const out = new Map<string, string>();
	if (!isObj(doc)) return out;
	for (const field of DEP_FIELDS) {
		if (field === "peerDependencies" && mode === "nopeer") continue;
		const block = doc[field];
		if (!isObj(block)) continue;
		for (const [name, spec] of Object.entries(block)) {
			if (
				field === "peerDependencies" &&
				mode === "checked" &&
				isOptionalPeer(doc, name)
			) {
				continue;
			}
			out.set(name, typeof spec === "string" ? spec : "");
		}
	}
	return out;
}

const trimSlashes = (p: string): string => {
	let end = p.length;
	while (end > 1 && p[end - 1] === "/") end--;
	return p.slice(0, end);
};

const MAX_WORKSPACE_PATTERNS = 1_000;

/** `workspaces` of the root package: an array or `{ packages: [...] }`. Deduplicated. */
function workspacePatterns(root: unknown): string[] | undefined {
	if (!isObj(root)) return [];
	const w = root.workspaces;
	const list = Array.isArray(w) ? w : isObj(w) ? w.packages : undefined;
	if (!Array.isArray(list)) return [];
	const out = new Set<string>();
	for (const p of list) {
		if (typeof p !== "string" || p.length > 200) continue;
		// Split the negation first so `!./x` normalizes like `./x`.
		const negated = p.startsWith("!");
		const body = trimSlashes(posix.normalize(negated ? p.slice(1) : p));
		out.add(negated ? `!${body}` : body);
		// Too many patterns: the caller audits every link instead of matching.
		if (out.size > MAX_WORKSPACE_PATTERNS) return undefined;
	}
	return [...out];
}

const MAX_GLOB_SEGMENTS = 64;

function segmentMatches(pattern: string, segment: string): boolean {
	if (pattern === segment) return true;
	// Wildcards never reach hidden folders, `.` or `..`.
	if (segment.startsWith(".") || !pattern.includes("*")) return false;
	if (pattern === "*") return true;
	const star = pattern.indexOf("*");
	if (pattern.indexOf("*", star + 1) >= 0) return false;
	const head = pattern.slice(0, star);
	const tail = pattern.slice(star + 1);
	return (
		segment.length >= head.length + tail.length &&
		segment.startsWith(head) &&
		segment.endsWith(tail)
	);
}

/** Iterative O(n*m) matcher: `**` runs are collapsed and no recursion is used. */
function globMatch(
	rawPattern: readonly string[],
	path: readonly string[],
): boolean {
	const pattern = rawPattern.filter(
		(seg, i) => !(seg === "**" && rawPattern[i - 1] === "**"),
	);
	const n = pattern.length;
	const m = path.length;
	// reach[j]: pattern[0..i) matches path[0..j)
	let reach = new Array<boolean>(m + 1).fill(false);
	reach[0] = true;
	for (let i = 0; i < n; i++) {
		const head = pattern[i] as string;
		const next = new Array<boolean>(m + 1).fill(false);
		if (head === "**") {
			next[0] = reach[0] as boolean;
			for (let j = 0; j <= m; j++) {
				if (reach[j]) next[j] = true;
				if (j > 0 && next[j - 1] && !(path[j - 1] as string).startsWith(".")) {
					next[j] = true;
				}
			}
		} else {
			for (let j = 1; j <= m; j++) {
				next[j] =
					(reach[j - 1] as boolean) &&
					segmentMatches(head, path[j - 1] as string);
			}
		}
		reach = next;
	}
	return reach[m] as boolean;
}

interface WorkspaceMatcher {
	literals: Set<string>;
	globs: string[][];
	negLiterals: Set<string>;
	negGlobs: string[][];
}

/** Compiled once per lockfile. `undefined` patterns = unusable list: nothing is covered. */
function compileWorkspaces(
	patterns: readonly string[] | undefined,
): WorkspaceMatcher | undefined {
	if (patterns === undefined) return undefined;
	const m: WorkspaceMatcher = {
		literals: new Set(),
		globs: [],
		negLiterals: new Set(),
		negGlobs: [],
	};
	for (const raw of patterns) {
		const neg = raw.startsWith("!");
		const p = neg ? raw.slice(1) : raw;
		if (p === "") continue;
		if (p.includes("*")) (neg ? m.negGlobs : m.globs).push(p.split("/"));
		else (neg ? m.negLiterals : m.literals).add(p);
	}
	return m;
}

function isWorkspacePath(
	matcher: WorkspaceMatcher | undefined,
	target: string,
): boolean {
	if (matcher === undefined) return false;
	const joined = trimSlashes(posix.normalize(target));
	const path = joined.split("/");
	if (path.length > MAX_GLOB_SEGMENTS) return false;
	if (path.some((s) => s === "." || s === ".." || s === "")) return false;
	if (matcher.negLiterals.has(joined)) return false;
	if (matcher.negGlobs.some((g) => globMatch(g, path))) return false;
	return (
		matcher.literals.has(joined) ||
		matcher.globs.some((g) => globMatch(g, path))
	);
}

/** Names the project declares itself (`work/package.json`); absent file = none. */
async function declaredDeps(lockDir: string): Promise<Declared> {
	const text = await readRegular(join(lockDir, "package.json"), MAX_LOCK_BYTES);
	const doc = text === undefined ? undefined : parseJson(text, "package.json");
	return {
		names: depSpecs(doc, "names"),
		checked: depSpecs(doc, "checked"),
		nopeer: depSpecs(doc, "nopeer"),
	};
}

// ---------- package-lock.json ----------

function parsePackageLock(text: string, declared: Declared): Tree {
	const doc = parseJson(text, "package-lock.json");
	if (!isObj(doc) || !isObj(doc.packages)) {
		throw lockError(
			"package-lock.json sin `packages`: se necesita lockfileVersion 2 o 3",
		);
	}
	const rootEntry = doc.packages[""];
	const checked = new Map([
		...declared.checked,
		...depSpecs(rootEntry, "checked"),
	]);
	const direct = new Set([
		...declared.names.keys(),
		...depSpecs(rootEntry, "names").keys(),
	]);
	const workspaces = compileWorkspaces(workspacePatterns(rootEntry));
	const known = new Set<string>();
	const out: Pkg[] = [];
	for (const [key, entry] of Object.entries(doc.packages)) {
		if (key === "" || !isObj(entry)) continue;
		const marker = key.lastIndexOf("node_modules/");
		if (marker !== 0 && !key.includes("/node_modules/")) continue;
		const fromKey = key.slice(marker + "node_modules/".length);
		if (key === `node_modules/${fromKey}`) known.add(fromKey);
		if (entry.link === true) {
			// A link outside `workspaces` is local code the project ships: audit its folder.
			const target = typeof entry.resolved === "string" ? entry.resolved : "";
			if (target !== "" && isWorkspacePath(workspaces, target)) continue;
			const found = target === "" ? undefined : doc.packages[target];
			const folder = isObj(found) ? found : undefined;
			out.push({
				paquete: fromKey,
				version:
					typeof folder?.version === "string" && folder.version !== ""
						? folder.version
						: "0.0.0-local",
				directa: key === `node_modules/${fromKey}` && direct.has(fromKey),
				license: folder === undefined ? undefined : licenseOf(folder),
				rutas: [],
				registro: false,
			});
			continue;
		}
		const name = typeof entry.name === "string" ? entry.name : fromKey;
		if (typeof entry.version !== "string" || entry.version === "") {
			throw lockError("Una entrada de package-lock.json no trae versión");
		}
		const segments = key.split("/");
		const safe = segments.every((s) => s === "node_modules" || SEGMENT.test(s));
		out.push({
			paquete: name,
			version: entry.version,
			directa: key === `node_modules/${name}` && direct.has(name),
			license: licenseOf(entry),
			rutas: safe ? [segments] : [],
			registro:
				entry.resolved === undefined ||
				(typeof entry.resolved === "string" && isRegistryUrl(entry.resolved)),
		});
	}
	return { pkgs: out, known, declared: checked };
}

// ---------- YAML lockfiles (pnpm-lock.yaml, yarn berry) ----------

const MAX_YAML_BYTES = 16_000_000;

type YMap = Map<unknown, unknown>;

/**
 * Safe `yaml` options: failsafe schema (every scalar stays a string, no coercion or custom
 * tags), maps as `Map` (no prototype keys), no merge keys, no aliases at all, duplicate keys
 * are errors (multiple documents are checked by the caller: only the pnpm env lockfile has two). Anything the library rejects is a lockfile error.
 */
const YAML_OPTIONS = {
	schema: "failsafe",
	version: "1.2",
	merge: false,
	maxAliasCount: 0,
	uniqueKeys: true,
	mapAsMap: true,
	logLevel: "error",
	prettyErrors: false,
} as const;

/** Every YAML document of the text as strict maps; any parse error is a lockfile error. */
function parseYamlDocs(text: string, que: string): YMap[] {
	if (Buffer.byteLength(text, "utf8") > MAX_YAML_BYTES) {
		throw lockError(`${que} es demasiado grande`, { maximo: MAX_YAML_BYTES });
	}
	const out: YMap[] = [];
	try {
		const docs = parseAllDocuments(text.replace(/^﻿/, ""), YAML_OPTIONS);
		for (const doc of Array.isArray(docs) ? docs : [docs]) {
			if (doc.errors.length > 0) throw new Error("yaml");
			const value: unknown = doc.toJS(YAML_OPTIONS);
			if (!(value instanceof Map)) {
				throw lockError(`${que} debe ser un mapa YAML`);
			}
			out.push(value);
		}
	} catch (cause) {
		if (cause instanceof MctError) throw cause;
		throw lockError(`${que} no es YAML válido`);
	}
	if (out.length === 0) throw lockError(`${que} debe ser un mapa YAML`);
	return out;
}

function parseYamlLock(text: string, que: string): YMap {
	const docs = parseYamlDocs(text, que);
	if (docs.length !== 1) throw lockError(`${que} no es YAML válido`);
	return docs[0] as YMap;
}

const asMap = (v: unknown): YMap | undefined =>
	v instanceof Map ? v : undefined;

const asStr = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;

/** A section that is present must be a map: a scalar or list there is a lockfile error. */
function sectionMap(parent: YMap, key: string, que: string): YMap | undefined {
	const v = parent.get(key);
	if (v === undefined) return undefined;
	const m = asMap(v);
	if (m === undefined) throw lockError(`${que} trae \`${key}\` mal formado`);
	return m;
}

function unquote(v: string): string {
	const t = v.trim();
	const q = t[0];
	if ((q === "'" || q === '"') && t.length >= 2 && t.endsWith(q)) {
		return t.slice(1, -1);
	}
	return t;
}

function splitPnpmKey(
	rawKey: string,
	legacy: boolean,
): { name: string; version: string } | undefined {
	let key = rawKey.startsWith("/") ? rawKey.slice(1) : rawKey;
	const paren = key.indexOf("(");
	if (paren >= 0) key = key.slice(0, paren);
	if (legacy) {
		const slash = key.lastIndexOf("/");
		if (slash <= 0) return undefined;
		const version = key.slice(slash + 1);
		const underscore = version.indexOf("_");
		return {
			name: key.slice(0, slash),
			version: underscore >= 0 ? version.slice(0, underscore) : version,
		};
	}
	const at = key.lastIndexOf("@");
	if (at <= 0) return undefined;
	return { name: key.slice(0, at), version: key.slice(at + 1) };
}

interface PnpmDirect {
	declared: Map<string, string>;
	/** `link:` targets that are not importers: local code outside the workspace. */
	links: string[];
}

function pnpmDirect(root: YMap): PnpmDirect {
	const importers = sectionMap(root, "importers", "pnpm-lock.yaml");
	const known = new Set<string>(
		[".", ...(importers?.keys() ?? [])].map(String),
	);
	const declared = new Map<string, string>();
	const links: string[] = [];
	const addFrom = (node: YMap | undefined, base: string) => {
		if (!node) return;
		for (const field of DEP_FIELDS) {
			const block = node.get(field);
			if (block === undefined) continue;
			const deps = asMap(block);
			if (deps === undefined) {
				throw lockError(`pnpm-lock.yaml trae \`${field}\` mal formado`);
			}
			for (const [rawName, dep] of deps) {
				if (typeof rawName !== "string") {
					throw lockError(
						"pnpm-lock.yaml trae un nombre de dependencia ilegible",
					);
				}
				const depMap = asMap(dep);
				const version = unquote(
					(depMap === undefined ? asStr(dep) : asStr(depMap.get("version"))) ??
						"",
				);
				const spec = unquote(asStr(depMap?.get("specifier")) ?? "");
				if (!version.startsWith("link:")) {
					declared.set(rawName, spec);
					continue;
				}
				const target = posix.normalize(posix.join(base, version.slice(5)));
				if (known.has(target)) {
					declared.set(rawName, "workspace:");
				} else {
					declared.set(rawName, version);
					links.push(rawName);
				}
			}
		}
	};
	addFrom(root, ".");
	for (const [path, importer] of importers ?? []) {
		if (typeof path !== "string") {
			throw lockError("pnpm-lock.yaml trae un importer ilegible");
		}
		addFrom(asMap(importer), path);
	}
	return { declared, links };
}

/**
 * Registry only when `resolution` is a map with nothing but `integrity` and a registry
 * `tarball`. Missing, scalar, git, directory or any unknown key is not a registry package.
 */
function pnpmFromRegistry(pkgNode: YMap | undefined): boolean {
	const res = asMap(pkgNode?.get("resolution"));
	if (!res) return false;
	for (const key of res.keys()) {
		if (key !== "integrity" && key !== "tarball") return false;
	}
	const tarball = res.get("tarball");
	if (tarball === undefined) return true;
	return typeof tarball === "string" && isRegistryUrl(tarball);
}

const ENV_TOP_KEYS = new Set([
	"lockfileVersion",
	"importers",
	"packages",
	"snapshots",
]);
const ENV_IMPORTER_KEYS = new Set([
	"configDependencies",
	"packageManagerDependencies",
]);

/** The package manager itself: `pnpm` and the `@pnpm/exe.*` binaries. */
function isManagerKey(rawKey: unknown): boolean {
	if (typeof rawKey !== "string") return false;
	const id = splitPnpmKey(rawKey, false);
	return (
		id !== undefined && (id.name === "pnpm" || id.name.startsWith("@pnpm/exe."))
	);
}

/**
 * pnpm 12 env lockfile: a first document that only pins the package manager (and config
 * dependencies). Anything beyond the exact known shape is refused. Its packages are tooling
 * of the manager, not project dependencies: they never enter the license tree.
 */
function assertEnvLockDocument(doc: YMap): void {
	const bad = () =>
		lockError(
			"pnpm-lock.yaml: el primer documento no es un env lockfile válido",
		);
	for (const key of doc.keys()) {
		if (typeof key !== "string" || !ENV_TOP_KEYS.has(key)) throw bad();
	}
	if (asStr(doc.get("lockfileVersion")) === undefined) throw bad();
	const importers = asMap(doc.get("importers"));
	if (importers === undefined || importers.size !== 1 || !importers.has(".")) {
		throw bad();
	}
	const dot = asMap(importers.get("."));
	if (dot === undefined) throw bad();
	for (const [key, value] of dot) {
		if (typeof key !== "string" || !ENV_IMPORTER_KEYS.has(key)) throw bad();
		if (asMap(value) === undefined) throw bad();
	}
	for (const section of ["packages", "snapshots"]) {
		const node = doc.get(section);
		if (node === undefined) continue;
		const map = asMap(node);
		if (map === undefined) throw bad();
		for (const key of map.keys()) if (!isManagerKey(key)) throw bad();
	}
}

/** One document, or exactly two where the first is a valid env lockfile. */
function pnpmRoot(text: string): YMap {
	const docs = parseYamlDocs(text, "pnpm-lock.yaml");
	if (docs.length === 1) return docs[0] as YMap;
	if (docs.length === 2) {
		assertEnvLockDocument(docs[0] as YMap);
		return docs[1] as YMap;
	}
	throw lockError("pnpm-lock.yaml trae más documentos de los permitidos");
}

function parsePnpmLock(text: string, declared: Declared): Tree {
	const root = pnpmRoot(text);
	const version = Number.parseFloat(
		unquote(asStr(root.get("lockfileVersion")) ?? ""),
	);
	if (Number.isNaN(version))
		throw lockError("pnpm-lock.yaml sin lockfileVersion");
	const fromLock = pnpmDirect(root);
	const checked = new Map([...declared.checked, ...fromLock.declared]);
	const direct = new Set([
		...declared.names.keys(),
		...fromLock.declared.keys(),
	]);
	const out: Pkg[] = [];
	const packages = sectionMap(root, "packages", "pnpm-lock.yaml");
	for (const [rawKey, pkgNode] of packages ?? []) {
		const id =
			typeof rawKey === "string"
				? splitPnpmKey(rawKey, version < 6)
				: undefined;
		if (!id)
			throw lockError("pnpm-lock.yaml trae una clave de paquete ilegible");
		const dir = `${id.name.replace("/", "+")}@${id.version}`;
		const nameSegments = id.name.split("/");
		const safe = validName(id.name) && validVersion(id.version);
		out.push({
			paquete: id.name,
			version: id.version,
			directa: direct.has(id.name),
			license: undefined,
			rutas: safe
				? [
						["node_modules", ...nameSegments],
						["node_modules", ".pnpm", dir, "node_modules", ...nameSegments],
					]
				: [],
			registro: pnpmFromRegistry(asMap(pkgNode)),
		});
	}
	for (const name of fromLock.links) {
		out.push({
			paquete: name,
			version: "0.0.0-local",
			directa: true,
			license: undefined,
			rutas: [],
			registro: false,
		});
	}
	return {
		pkgs: out,
		known: new Set(out.map((p) => p.paquete)),
		declared: checked,
	};
}

// ---------- yarn.lock (v1 text format and berry YAML) ----------

function nameBefore(descriptor: string): string | undefined {
	const at = descriptor.indexOf("@", 1);
	return at > 0 ? descriptor.slice(0, at) : undefined;
}

interface YarnBlock {
	name: string;
	descriptors: string[];
	version?: string;
	resolution?: string;
	resolved?: string;
}

/** Shared by v1 and berry: turns one block into a package (workspaces are skipped). */
function yarnPackage(block: YarnBlock, declared: Declared): Pkg | undefined {
	const { name, version, resolution, resolved } = block;
	if (version === undefined) {
		throw lockError("yarn.lock tiene un bloque sin versión");
	}
	if (resolution?.includes("@workspace:")) return undefined;
	let real = name;
	let registro = false;
	if (resolution) {
		real = nameBefore(resolution) ?? name;
		registro = resolution.includes("@npm:");
	} else if (resolved !== undefined && isRegistryUrl(resolved)) {
		const fromUrl = nameFromRegistryUrl(resolved);
		if (fromUrl !== undefined) {
			real = fromUrl;
			registro = true;
		}
	}
	return {
		paquete: real,
		version,
		directa: declared.names.has(real) || declared.names.has(name),
		license: undefined,
		rutas: validName(real) ? [["node_modules", ...real.split("/")]] : [],
		registro,
	};
}

function parseYarnBerry(text: string, declared: Declared): Tree {
	const root = parseYamlLock(text, "yarn.lock");
	const out: Pkg[] = [];
	const known = new Set<string>();
	for (const [rawKey, value] of root) {
		if (typeof rawKey !== "string") {
			throw lockError("yarn.lock tiene un bloque ilegible");
		}
		if (rawKey === "__metadata") continue;
		const entry = asMap(value);
		if (entry === undefined) {
			throw lockError("yarn.lock tiene un bloque ilegible");
		}
		const descriptors = rawKey.split(",").map((d) => unquote(d.trim()));
		const name = nameBefore(descriptors[0] ?? "");
		if (name === undefined) {
			throw lockError("yarn.lock tiene un bloque ilegible");
		}
		for (const d of descriptors) {
			const n = nameBefore(d);
			if (n !== undefined) known.add(n);
		}
		const version = asStr(entry.get("version"));
		const resolution = asStr(entry.get("resolution"));
		const pkg = yarnPackage(
			{
				name,
				descriptors,
				...(version !== undefined && { version }),
				...(resolution !== undefined && { resolution }),
			},
			declared,
		);
		if (pkg) out.push(pkg);
	}
	return { pkgs: out, known, declared: declared.nopeer };
}

function parseYarnV1(text: string, declared: Declared): Tree {
	const out: Pkg[] = [];
	const known = new Set<string>();
	let current: YarnBlock | undefined;
	const flush = () => {
		if (!current) return;
		const block = current;
		current = undefined;
		for (const d of block.descriptors) {
			const n = nameBefore(d);
			if (n !== undefined) known.add(n);
		}
		const pkg = yarnPackage(block, declared);
		if (pkg) out.push(pkg);
	};
	for (const raw of text.replace(/^﻿/, "").split("\n")) {
		const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
		if (line.trim() === "" || line.startsWith("#")) continue;
		if (line.startsWith(" ")) {
			// Only first-level fields (exactly two spaces) belong to the block.
			if (!current || !/^ {2}\S/.test(line)) continue;
			const body = line.trim();
			const sep = body.search(/[ :]/);
			if (sep <= 0) continue;
			const field = body.slice(0, sep);
			const value = unquote(body.slice(sep).replace(/^:/, ""));
			if (field === "version") current.version = value;
			else if (field === "resolved") current.resolved = value;
			continue;
		}
		flush();
		if (!line.endsWith(":"))
			throw lockError("yarn.lock tiene una línea ilegible");
		const descriptors = line
			.slice(0, -1)
			.split(",")
			.map((d) => unquote(d.trim()));
		const name = nameBefore(descriptors[0] ?? "");
		if (name === undefined)
			throw lockError("yarn.lock tiene un bloque ilegible");
		current = { name, descriptors };
	}
	flush();
	return { pkgs: out, known, declared: declared.nopeer };
}

/** `__metadata:` is the berry marker; anything with it must be strict YAML. */
function parseYarnLock(text: string, declared: Declared): Tree {
	return /^__metadata:/m.test(text)
		? parseYarnBerry(text, declared)
		: parseYarnV1(text, declared);
}

// ---------- tree ----------

const LOCKFILES = [
	["package-lock.json", parsePackageLock],
	["pnpm-lock.yaml", parsePnpmLock],
	["yarn.lock", parseYarnLock],
] as const;

type LockName = (typeof LOCKFILES)[number][0];

function gateError(mensaje: string, detalle?: Record<string, unknown>) {
	return new MctError("PUERTA_BLOQUEADA", mensaje, {
		accion: "Deja un solo lockfile o elige uno de forma explícita",
		...(detalle !== undefined && { detalle }),
	});
}

/** A declared name that the tree does not account for means the lockfile is stale or partial. */
function missingDeclared(tree: Tree): string[] {
	const names = new Set(tree.pkgs.map((p) => p.paquete));
	const found = (name: string, spec: string): boolean => {
		if (names.has(name) || tree.known.has(name)) return true;
		if (spec.startsWith("workspace:")) return true;
		if (spec.startsWith("npm:")) {
			const target = nameBefore(spec.slice(4));
			return target !== undefined && names.has(target);
		}
		return false;
	};
	return [...tree.declared]
		.filter(([name, spec]) => !found(name, spec))
		.map(([name]) => name)
		.sort(compare);
}

async function readTree(
	lockDir: string,
	choice?: LockName,
): Promise<Pkg[] | undefined> {
	const present: {
		file: LockName;
		text: string;
		parse: (typeof LOCKFILES)[number][1];
	}[] = [];
	for (const [file, parse] of LOCKFILES) {
		const text = await readRegular(join(lockDir, file), MAX_LOCK_BYTES);
		if (text !== undefined) present.push({ file, text, parse });
	}
	if (present.length === 0) return undefined;
	let picked = present[0] as (typeof present)[number] | undefined;
	if (choice !== undefined) {
		picked = present.find((p) => p.file === choice);
		if (picked === undefined) {
			throw gateError("El lockfile elegido no existe", { archivo: choice });
		}
	} else if (present.length > 1) {
		throw gateError("Hay más de un lockfile y no se sabe cuál es el real", {
			archivos: present.map((p) => p.file),
		});
	}
	if (picked === undefined) return undefined;
	const tree = picked.parse(picked.text, await declaredDeps(lockDir));
	const missing = missingDeclared(tree);
	if (missing.length > 0) {
		throw gateError(
			"El lockfile no trae dependencias que el proyecto declara: no se puede auditar el árbol completo",
			{ faltan: missing.slice(0, 20), total: missing.length },
		);
	}
	return tree.pkgs;
}

function mergePackages(list: readonly Pkg[]): Pkg[] {
	const byId = new Map<string, Pkg>();
	for (const pkg of list) {
		const id = `${pkg.paquete}@${pkg.version}#${pkg.registro ? "r" : "l"}`;
		const prev = byId.get(id);
		if (!prev) {
			byId.set(id, { ...pkg, rutas: [...pkg.rutas] });
			continue;
		}
		prev.directa = prev.directa || pkg.directa;
		prev.license = prev.license ?? pkg.license;
		prev.rutas.push(...pkg.rutas);
	}
	if (byId.size > MAX_PACKAGES) {
		throw lockError("El árbol de dependencias es demasiado grande", {
			maximo: MAX_PACKAGES,
		});
	}
	return [...byId.values()];
}

// ---------- source (b): node_modules of the origin ----------

/** Shared by every worker of one audit; spending is synchronous so it never overshoots. */
interface Budget {
	registry: number;
	reads: number;
	deadline: number;
	/** Packages that needed a lookup the budget could not pay for. */
	skipped: number;
}

async function readFromOrigin(
	originDir: string,
	pkg: Pkg,
	budget: Budget,
): Promise<string | undefined> {
	if (!validName(pkg.paquete) || !validVersion(pkg.version)) return undefined;
	const fallback = ["node_modules", ...pkg.paquete.split("/")];
	for (const segments of [...pkg.rutas, fallback]) {
		if (budget.reads <= 0) {
			budget.skipped++;
			return undefined;
		}
		budget.reads--;
		const doc = await readPackageJson(originDir, segments);
		if (doc && doc.name === pkg.paquete && doc.version === pkg.version) {
			const found = licenseOf(doc);
			if (found !== undefined) return found;
		}
	}
	return undefined;
}

/** Read-only, no links: every directory on the way and the file must be real. */
async function readPackageJson(
	originDir: string,
	segments: readonly string[],
): Promise<Record<string, unknown> | undefined> {
	try {
		let dir = originDir;
		for (const segment of segments) {
			dir = join(dir, segment);
			const st = await lstat(dir);
			if (st.isSymbolicLink() || !st.isDirectory()) return undefined;
		}
		const file = join(dir, "package.json");
		const st = await lstat(file);
		if (
			st.isSymbolicLink() ||
			!st.isFile() ||
			st.size > MAX_PACKAGE_JSON_BYTES
		) {
			return undefined;
		}
		const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
		return isObj(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
}

// ---------- source (c): registry ----------

async function readBody(
	res: Response,
	maxBytes: number,
): Promise<string | undefined> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > maxBytes) return undefined;
	const reader = res.body?.getReader();
	if (!reader) return undefined;
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			return undefined;
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks).toString("utf8");
}

/** Any failure (timeout, network, status, size, shape) is "no SPDX": the package stays in revisar. */
async function readFromRegistry(
	pkg: Pkg,
	fetchFn: FetchLike,
	timeoutMs: number,
	maxBytes: number,
	budget: Budget,
): Promise<string | undefined> {
	if (!pkg.registro) return undefined;
	if (!validName(pkg.paquete) || !validVersion(pkg.version)) return undefined;
	const remaining = budget.deadline - Date.now();
	if (budget.registry <= 0 || remaining <= 0) {
		budget.skipped++;
		return undefined;
	}
	budget.registry--;
	const url = `${REGISTRY}/${pkg.paquete.replace("/", "%2F")}/${pkg.version}`;
	try {
		const res = await fetchFn(url, {
			method: "GET",
			headers: { accept: "application/json" },
			redirect: "error",
			credentials: "omit",
			signal: AbortSignal.timeout(Math.min(timeoutMs, remaining)),
		});
		if (!res.ok) return undefined;
		const body = await readBody(res, maxBytes);
		if (body === undefined) return undefined;
		const doc: unknown = JSON.parse(body);
		return isObj(doc) ? licenseOf(doc) : undefined;
	} catch {
		return undefined;
	}
}

async function pool<T>(
	items: readonly T[],
	limit: number,
	fn: (item: T) => Promise<void>,
): Promise<void> {
	let next = 0;
	const worker = async () => {
		while (next < items.length) {
			const item = items[next++] as T;
			await fn(item);
		}
	};
	const size = Math.max(1, Math.min(limit, items.length));
	await Promise.all(Array.from({ length: size }, worker));
}

export function summarize(entries: readonly LicenseEntry[]): AuditSummary {
	return {
		paquetes: entries.length,
		bloquea: entries.filter((e) => e.veredicto === "bloquea").length,
		revisar: entries.filter((e) => e.veredicto === "revisar").length,
		overrides: entries.filter((e) => e.override !== undefined).length,
	};
}

/**
 * Full dependency tree audit (LIC-004). SPDX order: lockfile, then the origin's
 * node_modules (read-only), then the npm registry (skipped with `offline`).
 */
export async function auditLicenses(
	options: AuditOptions,
): Promise<AuditResult> {
	const tree = await readTree(options.lockDir, options.lockfile);
	if (tree === undefined && options.extra === undefined) {
		throw new MctError(
			"PUERTA_BLOQUEADA",
			"El proyecto Node no trae lockfile (package-lock.json, pnpm-lock.yaml o yarn.lock)",
			{ accion: "Genera el lockfile en el origen y vuelve a correr init" },
		);
	}
	const extras: Pkg[] = (options.extra ?? []).map((e) => ({
		paquete: e.paquete,
		version: e.version,
		directa: true,
		license: undefined,
		rutas: [],
		registro: true,
	}));
	const packages = mergePackages([...(tree ?? []), ...extras]);
	const fetchFn: FetchLike = options.fetch ?? ((url, init) => fetch(url, init));
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
	const spdxOf = new Map<Pkg, string | undefined>();
	const budget: Budget = {
		registry: Math.max(
			0,
			options.maxRegistryQueries ?? DEFAULT_MAX_REGISTRY_QUERIES,
		),
		reads: Math.max(0, options.maxOriginReads ?? DEFAULT_MAX_ORIGIN_READS),
		deadline: Date.now() + (options.maxTotalMs ?? DEFAULT_MAX_TOTAL_MS),
		skipped: 0,
	};

	await pool(
		packages,
		Math.min(options.concurrency ?? DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
		async (pkg) => {
			let spdx = pkg.license;
			if (spdx === undefined && options.originDir !== undefined) {
				spdx = await readFromOrigin(options.originDir, pkg, budget);
			}
			if (spdx === undefined && options.offline !== true) {
				spdx = await readFromRegistry(
					pkg,
					fetchFn,
					timeoutMs,
					maxBytes,
					budget,
				);
			}
			spdxOf.set(pkg, spdx);
		},
	);

	const allow = options.allow ?? [];
	const entries = packages
		.map((pkg) =>
			judgePackage(
				{
					paquete: pkg.paquete,
					version: pkg.version,
					spdx: spdxOf.get(pkg) ?? null,
					origen: pkg.directa ? "directa" : "transitiva",
				},
				allow,
			),
		)
		.sort(
			(a, b) => compare(a.paquete, b.paquete) || compare(a.version, b.version),
		);
	return {
		entries,
		resumen: summarize(entries),
		sinPresupuesto: budget.skipped,
	};
}
