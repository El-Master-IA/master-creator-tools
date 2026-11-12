import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type {
	Adapter,
	Analysis,
	Change,
	PackageHints,
	Rule,
	VerifySpec,
	Workspace,
} from "@mct/contract/types";

const NODE_IMAGE = "node:22-slim";
const DEFAULT_TIMEOUT_MIN = 10;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_LOCKFILE_BYTES = 50 * 1024 * 1024;
const SKIP_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	"coverage",
	".next",
]);
const SOURCE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte)$/;
const LOCKFILES: readonly [string, Gestor][] = [
	["pnpm-lock.yaml", "pnpm"],
	["yarn.lock", "yarn"],
	["package-lock.json", "npm"],
	["npm-shrinkwrap.json", "npm"],
];
const STACK_HINTS: Readonly<Record<string, string>> = {
	react: "react",
	vue: "vue",
	svelte: "svelte",
	next: "next",
	express: "express",
	fastify: "fastify",
	hono: "hono",
	typescript: "typescript",
};

type Gestor = "npm" | "pnpm" | "yarn";

export type RegistryIssueType =
	| "registro-privado"
	| "git-privado"
	| "credenciales-en-url"
	| "credenciales-en-npmrc";

/** A registry finding. It never carries the matched value (SCAN-012). */
export interface RegistryIssue {
	tipo: RegistryIssueType;
	archivo: string;
	zona: "work" | "quarantine";
	linea: number;
}

// Anchored on "://" with bounded quantifiers: no ReDoS on hostile lockfiles (SEG-004).
// "git@" alone is the normal ssh user, not a credential.
const RE_URL_CREDENTIALS =
	/:\/\/(?!git@)[^\s:@/'"]{1,100}(?::([^\s@/'"]{1,200}))?@[\w.-]{1,255}/i;
const RE_PRIVATE_REGISTRY =
	/["']?(?:resolved|tarball|registry)["']?(?:\s{0,10}[:=]\s{0,10}|\s{1,10})["']?(https?:\/\/(?![^\s"'/]{0,200}@)(?!(?:registry\.npmjs\.org|registry\.yarnpkg\.com)(?:[/:\s"'?#]|$))[^\s"']{1,2000})/i;
const RE_PRIVATE_GIT =
	/(git\+(?:ssh|https?):\/\/[^\s"']{1,500}|ssh:\/\/git@[^\s"']{1,500}|git@[^\s"':@]{1,255}:[^\s"']{1,500}\.git)/i;
const RE_NPMRC_CREDENTIALS =
	/(?:_authToken|_auth|_password)\s*=\s*"?(?!\$)([^\s"]+)/;

const RULES: readonly Rule[] = [
	{
		id: "node-url-credenciales",
		tipo: "secreto",
		severidad: "critico",
		patron: RE_URL_CREDENTIALS,
	},
	{
		id: "node-npmrc-credenciales",
		tipo: "secreto",
		severidad: "critico",
		patron: RE_NPMRC_CREDENTIALS,
	},
	{
		id: "node-registro-privado",
		tipo: "estructura",
		severidad: "alto",
		patron: RE_PRIVATE_REGISTRY,
	},
	{
		id: "node-git-privado",
		tipo: "estructura",
		severidad: "alto",
		patron: RE_PRIVATE_GIT,
	},
];

interface PackageJson {
	name?: string;
	main?: string;
	bin?: string | Record<string, string>;
	scripts?: Record<string, string>;
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
	packageManager?: string;
	engines?: { node?: string };
}

async function exists(path: string): Promise<boolean> {
	try {
		await stat(path);
		return true;
	} catch {
		return false;
	}
}

async function readText(path: string): Promise<string | null> {
	try {
		const info = await stat(path);
		if (!info.isFile() || info.size > MAX_FILE_BYTES) return null;
		return (await readFile(path, "utf8")).replace(/\r\n/g, "\n");
	} catch {
		return null;
	}
}

/** Reads a file that must be readable if it exists; fails closed (never skips). */
async function readRequired(path: string, label: string): Promise<string> {
	const fail = (motivo: string, cause?: unknown): MctError =>
		new MctError(
			"WORKSPACE_INVALIDO",
			`No se pudo leer ${label}: no se puede dar por limpio un archivo ilegible.`,
			{
				etapa: "sanitize",
				accion:
					"Revisa que el archivo exista como archivo normal y pese menos de 50 MB.",
				detalle: { motivo, archivo: label },
				...(cause === undefined ? {} : { cause }),
			},
		);
	let info: Awaited<ReturnType<typeof stat>>;
	try {
		info = await stat(path);
	} catch (e) {
		throw fail("ilegible", e);
	}
	if (!info.isFile()) throw fail("no-es-archivo");
	if (info.size > MAX_LOCKFILE_BYTES) throw fail("demasiado-grande");
	try {
		return (await readFile(path, "utf8")).replace(/\r\n/g, "\n");
	} catch (e) {
		throw fail("ilegible", e);
	}
}

/** Raw file content (no EOL normalization) so offsets match the file on disk. */
async function readRaw(path: string): Promise<string | null> {
	try {
		const info = await stat(path);
		if (!info.isFile() || info.size > MAX_FILE_BYTES) return null;
		return await readFile(path, "utf8");
	} catch {
		return null;
	}
}

async function readPackage(dir: string): Promise<PackageJson | null> {
	const text = await readText(join(dir, "package.json"));
	if (text === null) return null;
	try {
		const parsed: unknown = JSON.parse(text);
		if (parsed === null || typeof parsed !== "object") return null;
		return parsed as PackageJson;
	} catch {
		return null;
	}
}

/** Relative file paths under `root` (with `/`), skipping heavy directories. */
async function walk(
	root: string,
	dir = "",
	keepAnyNamed?: ReadonlySet<string>,
	strict = false,
): Promise<string[]> {
	let entries: import("node:fs").Dirent[];
	try {
		entries = await readdir(join(root, dir), { withFileTypes: true });
	} catch (e) {
		if (!strict) return [];
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"No se pudo recorrer un directorio: no se puede dar por limpio un árbol ilegible.",
			{
				etapa: "sanitize",
				accion: "Revisa que el directorio exista y tenga permisos de lectura.",
				detalle: { motivo: "directorio-ilegible", archivo: dir || "." },
				cause: e,
			},
		);
	}
	const out: string[] = [];
	for (const entry of entries) {
		const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
		if (keepAnyNamed?.has(entry.name)) {
			// Any entry with a lockfile/.npmrc name is kept so that a non-regular
			// one fails closed in readRequired instead of being skipped.
			out.push(rel);
		} else if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) {
				out.push(...(await walk(root, rel, keepAnyNamed, strict)));
			}
		} else if (entry.isFile()) {
			out.push(rel);
		}
	}
	return out;
}

function baseName(rel: string): string {
	return rel.slice(rel.lastIndexOf("/") + 1);
}

function isEnvFile(rel: string): boolean {
	return baseName(rel).startsWith(".env");
}

async function detectGestor(
	work: string,
	pkg: PackageJson | null,
): Promise<Gestor> {
	for (const [file, gestor] of LOCKFILES) {
		if (await exists(join(work, file))) return gestor;
	}
	const declared = pkg?.packageManager?.split("@")[0];
	if (declared === "pnpm" || declared === "yarn" || declared === "npm") {
		return declared;
	}
	return "npm";
}

async function hasLockfile(work: string): Promise<boolean> {
	for (const [file] of LOCKFILES) {
		if (await exists(join(work, file))) return true;
	}
	return false;
}

function installCommand(gestor: Gestor, locked: boolean): string {
	if (gestor === "pnpm") return "pnpm install --frozen-lockfile";
	if (gestor === "yarn") return "yarn install --frozen-lockfile";
	return locked ? "npm ci" : "npm install";
}

function binTargets(pkg: PackageJson): string[] {
	const raw =
		typeof pkg.bin === "string"
			? [pkg.bin]
			: pkg.bin && typeof pkg.bin === "object"
				? Object.values(pkg.bin)
				: [];
	return raw
		.filter((b): b is string => typeof b === "string" && b !== "")
		.map((b) => b.replace(/^\.\//, ""));
}

function parsePort(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const n = Number(value);
	return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : undefined;
}

function portFromScript(script: string): number | undefined {
	const m =
		/\bPORT=(\d{2,5})\b/.exec(script) ??
		/--port[ =](\d{2,5})\b/.exec(script) ??
		/\s-p[ =]?(\d{2,5})\b/.exec(script);
	return parsePort(m?.[1]);
}

function addVar(
	vars: Map<string, boolean>,
	name: string,
	required: boolean,
): void {
	vars.set(name, (vars.get(name) ?? false) || required);
}

const RE_CODE_ENV =
	/(?:process\.env|import\.meta\.env)(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\])(\s*(?:\|\||\?\?))?/g;
const RE_ENV_DESTRUCTURE =
	/(?:const|let|var)\s*\{([^}]{1,2000})\}\s*=\s*(?:process\.env|import\.meta\.env)\b/g;
const RE_PORT_DEFAULT =
	/(?:const|let|var)\s+([A-Za-z_]\w{0,60})\s*=\s*(?:Number\(|parseInt\()?\s*(?:process\.env|import\.meta\.env)\.[A-Za-z_]\w*\s*(?:\|\||\?\?)\s*["']?(\d{2,5})\b/g;
const RE_LISTEN_DIRECT =
	/\.listen\(\s*(?:Number\(|parseInt\()?\s*(?:process\.env|import\.meta\.env)\.[A-Za-z_]\w*\s*(?:\|\||\?\?)\s*["']?(\d{2,5})\b/;
const RE_LISTEN_VAR = /\.listen\(\s*([A-Za-z_]\w{0,60})\s*[,)]/g;
const RE_DOTENV_NAME = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

function listenPortOf(text: string): number | undefined {
	const literal = parsePort(/\.listen\(\s*(\d{2,5})\b/.exec(text)?.[1]);
	if (literal !== undefined) return literal;
	const direct = parsePort(RE_LISTEN_DIRECT.exec(text)?.[1]);
	if (direct !== undefined) return direct;
	const defaults = new Map<string, number>();
	for (const m of text.matchAll(RE_PORT_DEFAULT)) {
		const port = parsePort(m[2]);
		if (m[1] && port !== undefined) defaults.set(m[1], port);
	}
	for (const m of text.matchAll(RE_LISTEN_VAR)) {
		const port = m[1] === undefined ? undefined : defaults.get(m[1]);
		if (port !== undefined) return port;
	}
	return undefined;
}

async function analyzeProject(ws: Workspace): Promise<Analysis> {
	const pkg = await readPackage(ws.work);
	const gestor = await detectGestor(ws.work, pkg);
	const locked = await hasLockfile(ws.work);
	const vars = new Map<string, boolean>();
	let puerto = portFromScript(pkg?.scripts?.start ?? "");
	let listenPort: number | undefined;
	let envPort: number | undefined;

	for (const rel of await walk(ws.work)) {
		const isEnv = isEnvFile(rel);
		if (!isEnv && !SOURCE_EXT.test(rel)) continue;
		const text = await readText(join(ws.work, rel));
		if (text === null) continue;
		if (isEnv) {
			envPort ??= readEnvFile(text, vars);
			continue;
		}
		for (const m of text.matchAll(RE_CODE_ENV)) {
			const name = m[1] ?? m[2];
			if (name) addVar(vars, name, m[3] === undefined);
		}
		for (const d of text.matchAll(RE_ENV_DESTRUCTURE)) {
			for (const part of (d[1] ?? "").split(",")) {
				const item = part.trim();
				if (item.startsWith("...")) continue;
				const name = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(item)?.[1];
				if (name) addVar(vars, name, !item.includes("="));
			}
		}
		listenPort ??= listenPortOf(text);
	}

	for (const rel of await walk(ws.quarantine)) {
		if (!isEnvFile(rel)) continue;
		const text = await readText(join(ws.quarantine, rel));
		if (text !== null) envPort ??= readEnvFile(text, vars);
	}
	puerto ??= envPort ?? listenPort;

	const scripts = pkg?.scripts ?? {};
	const bins = pkg ? binTargets(pkg) : [];
	const comandos: Analysis["comandos"] = {};
	let install = installCommand(gestor, locked);
	if (typeof scripts.build === "string") {
		comandos.build = `${gestor} run build`;
		install = `${install} && ${comandos.build}`;
	}
	comandos.install = install;
	if (typeof scripts.start === "string") {
		comandos.start = `${gestor} start`;
	} else if (bins[0] !== undefined) {
		comandos.start = `node ${bins[0]} --version`;
	}

	const entrypoints = new Set<string>();
	if (typeof pkg?.main === "string") {
		entrypoints.add(pkg.main.replace(/^\.\//, ""));
	}
	for (const b of bins) entrypoints.add(b);
	const viaNode = /\bnode\s+(?:--\S+\s+)*(\S+\.[cm]?[jt]s)\b/.exec(
		scripts.start ?? "",
	);
	if (viaNode?.[1]) entrypoints.add(viaNode[1].replace(/^\.\//, ""));

	const allDeps = { ...pkg?.devDependencies, ...pkg?.dependencies };
	const stack = ["node"];
	for (const [dep, label] of Object.entries(STACK_HINTS)) {
		if (dep in allDeps) stack.push(label);
	}

	const analysis: Analysis = {
		stack,
		entrypoints: [...entrypoints],
		envVars: [...vars].map(([nombre, obligatoria]) => ({
			nombre,
			obligatoria,
		})),
		deps: Object.entries(pkg?.dependencies ?? {}).map(([nombre, version]) => ({
			nombre,
			version: String(version),
		})),
		gestor,
		comandos,
	};
	if (puerto !== undefined) analysis.puerto = puerto;
	return analysis;
}

/** Adds the variable names of a `.env*` file; returns PORT if declared. Values are never kept. */
function readEnvFile(
	text: string,
	vars: Map<string, boolean>,
): number | undefined {
	let port: number | undefined;
	for (const line of text.split("\n")) {
		const name = RE_DOTENV_NAME.exec(line)?.[1];
		if (!name) continue;
		addVar(vars, name, false);
		if (name === "PORT") {
			port = parsePort(/=\s*["']?(\d{2,5})["']?\s*$/.exec(line)?.[1]);
		}
	}
	return port;
}

/**
 * Looks for private registries, private git dependencies and credentials in
 * lockfiles (work/) and `.npmrc` (quarantine/). Reports file and line only:
 * the matched value is never returned (SCAN-012).
 */
export async function findRegistryIssues(
	ws: Workspace,
): Promise<RegistryIssue[]> {
	const issues: RegistryIssue[] = [];
	const targets: { zona: "work" | "quarantine"; archivo: string }[] = [];
	const lockNames = new Set(LOCKFILES.map(([file]) => file));
	for (const rel of await walk(ws.work, "", lockNames, true)) {
		if (lockNames.has(baseName(rel))) {
			targets.push({ zona: "work", archivo: rel });
		}
	}
	for (const rel of await walk(ws.quarantine, "", new Set([".npmrc"]), true)) {
		if (baseName(rel) === ".npmrc") {
			targets.push({ zona: "quarantine", archivo: rel });
		}
	}

	for (const { zona, archivo } of targets) {
		const base = zona === "work" ? ws.work : ws.quarantine;
		{
			const text = await readRequired(join(base, archivo), archivo);
			const lines = text.split("\n");
			for (const [i, line] of lines.entries()) {
				const found: RegistryIssueType[] = [];
				if (RE_URL_CREDENTIALS.test(line)) found.push("credenciales-en-url");
				if (RE_PRIVATE_REGISTRY.test(line)) found.push("registro-privado");
				if (RE_PRIVATE_GIT.test(line)) found.push("git-privado");
				if (baseName(archivo) === ".npmrc" && RE_NPMRC_CREDENTIALS.test(line)) {
					found.push("credenciales-en-npmrc");
				}
				for (const tipo of found) {
					issues.push({ tipo, archivo, zona, linea: i + 1 });
				}
			}
		}
	}
	return issues;
}

function detectIndent(text: string): string | number {
	return /^([ \t]+)"/m.exec(text)?.[1] ?? 2;
}

function withEol(text: string, original: string): string {
	return original.includes("\r\n") ? text.replace(/\n/g, "\r\n") : text;
}

const STRIPPED_FIELDS = ["author", "repository", "homepage", "bugs"] as const;

export const nodeAdapter: Adapter = {
	id: "node",

	async detect(dir: string): Promise<number> {
		const pkg = await readPackage(dir);
		if (pkg === null) return 0;
		let score = 0.5;
		if (await hasLockfile(dir)) score += 0.2;
		if (pkg.scripts?.start || pkg.main || pkg.bin) score += 0.2;
		return Math.min(score, 0.9);
	},

	analyze: analyzeProject,

	rules(): Rule[] {
		return RULES.map((r) => ({ ...r }));
	},

	async generalize(ws: Workspace): Promise<Change[]> {
		const original = await readRaw(join(ws.dist, "package.json"));
		if (original === null) return [];
		let parsed: Record<string, unknown>;
		try {
			const value: unknown = JSON.parse(original);
			if (value === null || typeof value !== "object" || Array.isArray(value)) {
				return [];
			}
			parsed = value as Record<string, unknown>;
		} catch {
			return [];
		}
		if (!STRIPPED_FIELDS.some((f) => f in parsed)) return [];
		for (const f of STRIPPED_FIELDS) delete parsed[f];
		return [
			{
				tipo: "editar",
				ruta: "package.json",
				desde: 0,
				hasta: original.length,
				texto: withEol(
					`${JSON.stringify(parsed, null, detectIndent(original))}\n`,
					original,
				),
			},
		];
	},

	packageHints(a: Analysis): PackageHints {
		const instalacion: string[] = [];
		if (a.comandos.install) instalacion.push(a.comandos.install);
		const uso: string[] = [];
		if (a.comandos.start) uso.push(a.comandos.start);
		return {
			instalacion,
			uso,
			variables: a.envVars.map((v) => ({
				nombre: v.nombre,
				descripcion: v.obligatoria
					? "Obligatoria."
					: "Opcional (tiene valor por defecto o es de ejemplo).",
				obligatoria: v.obligatoria,
			})),
			requisitos: ["Node >= 22"],
		};
	},

	verifyCommand(a: Analysis): VerifySpec {
		const start = a.comandos.start;
		if (!start) {
			throw new MctError(
				"PUERTA_BLOQUEADA",
				"El proyecto node no tiene script start ni bin: no hay forma de arrancarlo para verificar.",
				{
					etapa: "verify",
					accion:
						"Agrega un script start o un campo bin a package.json y vuelve a correr init.",
					detalle: { motivo: "sin-arranque" },
				},
			);
		}
		// corepack enable needs root; the container is non-root (VER-001), so call
		// the package manager through "corepack <gestor>" instead.
		const viaCorepack = (cmd: string): string =>
			a.gestor === "npm"
				? cmd
				: cmd.replace(/(^|&&\s*)(pnpm|yarn)\b/g, "$1corepack $2");
		const isBinFallback = /^node \S+ --version$/.test(start);
		const install = a.comandos.install;
		const spec: VerifySpec = {
			imagen: NODE_IMAGE,
			start: viaCorepack(start).split(/\s+/).filter(Boolean),
			healthcheck:
				a.puerto === undefined || isBinFallback
					? { tipo: "salida-cero" }
					: { tipo: "http", puerto: a.puerto },
			timeoutMin: DEFAULT_TIMEOUT_MIN,
		};
		if (install) {
			// Scripts like "pnpm -r run build" call the bare package manager: a corepack
			// shim in $HOME (no root needed) puts it on PATH for the install step.
			const shim =
				a.gestor === "npm"
					? ""
					: `mkdir -p "$HOME/.mct-bin" && corepack enable --install-directory "$HOME/.mct-bin" ${a.gestor} && export PATH="$HOME/.mct-bin:$PATH" && `;
			spec.install = ["sh", "-c", `${shim}${viaCorepack(install)}`];
		}
		return spec;
	},
};
