import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { UV_VERSION } from "@mct/contract/pins";
import type { Analysis, Workspace } from "@mct/contract/types";
import { parse } from "smol-toml";
import { readDotenv, scanPythonEnv } from "./env.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_LOCK_BYTES = 50 * 1024 * 1024;
const SKIP_DIRS = new Set([
	"node_modules",
	".git",
	".venv",
	"venv",
	"__pycache__",
	"dist",
	"build",
	".mct",
]);
const ROOT_ENTRYPOINTS = ["__main__.py", "main.py", "app.py", "manage.py"];
const FRAMEWORKS = ["fastapi", "flask", "django"] as const;

type Toml = Record<string, unknown>;

export async function readText(
	path: string,
	max = MAX_FILE_BYTES,
): Promise<string | null> {
	try {
		const info = await stat(path);
		if (!info.isFile() || info.size > max) return null;
		return (await readFile(path, "utf8")).replace(/\r\n/g, "\n");
	} catch {
		return null;
	}
}

/** Relative file paths (with `/`) under `root`, skipping heavy directories. */
export async function walk(root: string, dir = ""): Promise<string[]> {
	let entries: import("node:fs").Dirent[];
	try {
		entries = await readdir(join(root, dir), { withFileTypes: true });
	} catch {
		return [];
	}
	const out: string[] = [];
	for (const entry of entries) {
		const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) out.push(...(await walk(root, rel)));
		} else if (entry.isFile()) {
			out.push(rel);
		}
	}
	return out;
}

/** The parser message can quote file content, so it is dropped on purpose. */
function invalid(archivo: string): MctError {
	return new MctError(
		"VALIDACION",
		`${archivo} no es TOML válido o no se pudo leer.`,
		{
			etapa: "init",
			accion: `Revisa la sintaxis de ${archivo}.`,
			detalle: { motivo: "toml-invalido", archivo },
		},
	);
}

function asTable(value: unknown): Toml {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Toml)
		: {};
}

export interface PythonFiles {
	pyproject: Toml | null;
	hasPyproject: boolean;
	hasUvLock: boolean;
	hasPoetryLock: boolean;
	hasSetupPy: boolean;
	hasPipfile: boolean;
	requirements: string[];
}

/** Manifests at the root of `dir`. Strict mode validates the TOML files (PY-001). */
export async function readPythonFiles(
	dir: string,
	opts: { strict: boolean },
): Promise<PythonFiles> {
	let names: string[] = [];
	try {
		names = await readdir(dir);
	} catch {
		names = [];
	}
	const has = (n: string): boolean => names.includes(n);
	let pyproject: Toml | null = null;
	for (const file of ["pyproject.toml", "uv.lock", "poetry.lock"]) {
		if (!has(file)) continue;
		const max = file === "pyproject.toml" ? MAX_FILE_BYTES : MAX_LOCK_BYTES;
		const text = await readText(join(dir, file), max);
		if (text === null) {
			if (opts.strict) throw invalid(file);
			continue;
		}
		try {
			const parsed = parse(text) as Toml;
			if (file === "pyproject.toml") pyproject = parsed;
		} catch {
			if (opts.strict) throw invalid(file);
		}
	}
	return {
		pyproject,
		hasPyproject: has("pyproject.toml"),
		hasUvLock: has("uv.lock"),
		hasPoetryLock: has("poetry.lock"),
		hasSetupPy: has("setup.py"),
		hasPipfile: has("Pipfile"),
		requirements: names.filter((n) => /^requirements.*\.txt$/.test(n)).sort(),
	};
}

export function hasManifest(f: PythonFiles): boolean {
	return (
		f.hasPyproject ||
		f.hasUvLock ||
		f.hasPoetryLock ||
		f.hasSetupPy ||
		f.hasPipfile ||
		f.requirements.length > 0
	);
}

export function scriptNames(pyproject: Toml | null): string[] {
	return Object.keys(asTable(asTable(pyproject?.project).scripts));
}

export async function rootEntrypoints(dir: string): Promise<string[]> {
	let names: string[] = [];
	try {
		names = await readdir(dir);
	} catch {
		return [];
	}
	return ROOT_ENTRYPOINTS.filter((n) => names.includes(n));
}

/** Name, extras, version spec and marker split from a PEP 508 line. */
function parseRequirement(
	line: string,
): { nombre: string; version: string } | null {
	const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(
		line.trim(),
	);
	if (!m?.[1]) return null;
	let spec = (m[2] ?? "").split(";")[0] ?? "";
	spec = spec.replace(/^\(|\)$/g, "").trim();
	if (spec.startsWith("@")) spec = "";
	return {
		nombre: m[1],
		version: spec === "" ? "*" : spec.replace(/\s+/g, ""),
	};
}

function parseRequirementsTxt(
	text: string,
): { nombre: string; version: string }[] {
	const out: { nombre: string; version: string }[] = [];
	for (const raw of text.split("\n")) {
		const line = (raw.split(/\s#/)[0] ?? "").trim();
		if (line === "" || line.startsWith("#") || line.startsWith("-")) continue;
		if (/^(?:git\+|https?:|\.|\/|file:)/.test(line)) continue;
		const dep = parseRequirement(line);
		if (dep) out.push(dep);
	}
	return out;
}

function poetryPythonSpec(value: unknown): string | undefined {
	const raw =
		typeof value === "string"
			? value
			: typeof asTable(value).version === "string"
				? String(asTable(value).version)
				: undefined;
	if (raw === undefined) return undefined;
	const v = raw.trim();
	const caret = /^\^(\d+)(?:\.(\d+))?/.exec(v);
	if (caret) {
		const base = caret[2] === undefined ? caret[1] : `${caret[1]}.${caret[2]}`;
		return `>=${base},<${Number(caret[1]) + 1}`;
	}
	const tilde = /^~=?\s*(\d+)\.(\d+)/.exec(v);
	if (tilde) {
		return `>=${tilde[1]}.${tilde[2]},<${tilde[1]}.${Number(tilde[2]) + 1}`;
	}
	return v;
}

/** Python pin from `.python-version` as a specifier (`3.12` becomes `==3.12.*`). */
async function pythonVersionSpec(dir: string): Promise<string | undefined> {
	const text = await readText(join(dir, ".python-version"));
	const m = /^\s*(\d+)\.(\d+)/.exec(text ?? "");
	return m ? `==${m[1]}.${m[2]}.*` : undefined;
}

const RE_PORT_UVICORN = /uvicorn[^\n]{0,200}?--port[ =](\d{2,5})\b/;
const RE_PORT_RUN = /\.run\([^)]{0,300}?\bport\s*=\s*(\d{2,5})\b/;
const RE_PORT_RUNSERVER = /runserver\s+(?:[\w.]*:)?(\d{2,5})\b/;
const RE_PORT_DEFAULT =
	/(?:environ\.get|getenv)\(\s*["']PORT["']\s*,\s*["']?(\d{2,5})\b/;

function portOf(text: string): number | undefined {
	for (const re of [
		RE_PORT_UVICORN,
		RE_PORT_RUN,
		RE_PORT_RUNSERVER,
		RE_PORT_DEFAULT,
	]) {
		const n = Number(re.exec(text)?.[1]);
		if (Number.isInteger(n) && n >= 1 && n <= 65535) return n;
	}
	return undefined;
}

/** Install precedence of PY-003: uv.lock > poetry.lock+build-system > requirements.txt > pip install . */
export function installCommand(f: PythonFiles): string | undefined {
	if (f.hasUvLock) {
		return `pip install uv==${UV_VERSION} && uv export --frozen --format requirements-txt --no-emit-project -o /tmp/mct-requirements.txt && pip install -r /tmp/mct-requirements.txt`;
	}
	const buildSystem = f.pyproject !== null && "build-system" in f.pyproject;
	if (f.hasPoetryLock && buildSystem) return "pip install .";
	if (f.requirements.includes("requirements.txt")) {
		return "pip install -r requirements.txt";
	}
	if (f.hasPyproject || f.hasSetupPy) return "pip install .";
	return undefined;
}

export async function analyzeProject(ws: Workspace): Promise<Analysis> {
	const files = await readPythonFiles(ws.work, { strict: true });
	const project = asTable(files.pyproject?.project);
	const poetry = asTable(asTable(files.pyproject?.tool).poetry);

	const deps = new Map<string, { nombre: string; version: string }>();
	const addDep = (nombre: string, version: string): void => {
		const key = nombre.toLowerCase().replace(/[-_.]+/g, "-");
		if (!deps.has(key)) deps.set(key, { nombre, version });
	};
	if (Array.isArray(project.dependencies)) {
		for (const d of project.dependencies) {
			const dep = typeof d === "string" ? parseRequirement(d) : null;
			if (dep) addDep(dep.nombre, dep.version);
		}
	}
	for (const [nombre, value] of Object.entries(asTable(poetry.dependencies))) {
		if (nombre.toLowerCase() === "python") continue;
		const spec = typeof value === "string" ? value : asTable(value).version;
		addDep(nombre, typeof spec === "string" && spec !== "" ? spec : "*");
	}
	for (const rel of files.requirements) {
		const text = await readText(join(ws.work, rel));
		if (text === null) continue;
		for (const dep of parseRequirementsTxt(text)) {
			addDep(dep.nombre, dep.version);
		}
	}

	let requiresPython =
		typeof project["requires-python"] === "string"
			? String(project["requires-python"]).trim()
			: poetryPythonSpec(asTable(poetry.dependencies).python);
	const pin = await pythonVersionSpec(ws.work);
	if (pin !== undefined) {
		requiresPython = requiresPython ? `${requiresPython},${pin}` : pin;
	}

	const vars = new Map<string, boolean>();
	let puerto: number | undefined;
	for (const rel of await walk(ws.work)) {
		const base = rel.slice(rel.lastIndexOf("/") + 1);
		if (base.startsWith(".env")) {
			const t = await readText(join(ws.work, rel));
			if (t !== null) readDotenv(t, vars);
			continue;
		}
		if (!rel.endsWith(".py")) continue;
		const text = await readText(join(ws.work, rel));
		if (text === null) continue;
		scanPythonEnv(text, vars);
		puerto ??= portOf(text);
	}
	for (const rel of await walk(ws.quarantine)) {
		if (!rel.slice(rel.lastIndexOf("/") + 1).startsWith(".env")) continue;
		const t = await readText(join(ws.quarantine, rel));
		if (t !== null) readDotenv(t, vars);
	}

	const entrypoints = [
		...scriptNames(files.pyproject),
		...(await rootEntrypoints(ws.work)),
	];
	const stack = ["python"];
	for (const fw of FRAMEWORKS) if (deps.has(fw)) stack.push(fw);

	const comandos: Analysis["comandos"] = {};
	const install = installCommand(files);
	if (install !== undefined) comandos.install = install;
	const first = entrypoints[0];
	if (first !== undefined) {
		comandos.start = first.endsWith(".py") ? `python ${first}` : first;
	}

	const analysis: Analysis = {
		stack,
		entrypoints,
		envVars: [...vars].map(([nombre, obligatoria]) => ({
			nombre,
			obligatoria,
		})),
		deps: [...deps.values()],
		gestor: files.hasUvLock ? "uv" : files.hasPoetryLock ? "poetry" : "pip",
		lenguaje: "python",
		comandos,
	};
	if (requiresPython) analysis.requiresPython = requiresPython;
	if (puerto !== undefined) analysis.puerto = puerto;
	return analysis;
}
