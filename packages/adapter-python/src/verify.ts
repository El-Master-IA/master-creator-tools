import { MctError } from "@mct/contract/errors";
import { PYTHON_IMAGE_REFS } from "@mct/contract/pins";
import type { Analysis, VerifySpec, VerifyStep } from "@mct/contract/types";

const DEFAULT_TIMEOUT_MIN = 15;
/** 3.14 first, then the highest that fits. */
const CANDIDATES = [14, 15, 13] as const;
const SAMPLE_PATCHES = [0, 99];

type Version = [number, number, number];

function parseVersion(
	text: string,
): { v: Version; wildcard: boolean; len: number } | null {
	const m = /^(\d+(?:\.\d+)*)(\.\*)?$/.exec(text);
	if (!m?.[1]) return null;
	const parts = m[1].split(".").map(Number);
	return {
		v: [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0],
		wildcard: m[2] !== undefined,
		len: parts.length,
	};
}

function cmp(a: Version, b: Version): number {
	for (let i = 0; i < 3; i++) {
		const d = (a[i] ?? 0) - (b[i] ?? 0);
		if (d !== 0) return d;
	}
	return 0;
}

function prefixEq(s: Version, v: Version, len: number): boolean {
	for (let i = 0; i < Math.min(len, 2); i++) if (s[i] !== v[i]) return false;
	return true;
}

function clauseHolds(clause: string, s: Version): boolean {
	const m = /^(~=|===|==|!=|>=|<=|>|<)?\s*(.+)$/.exec(clause.trim());
	const parsed = m?.[2] ? parseVersion(m[2].trim()) : null;
	// Unknown syntax: it cannot be proven to fail.
	if (!m || !parsed) return true;
	const op = m[1] ?? "==";
	const { v, wildcard, len } = parsed;
	switch (op) {
		case ">=":
			return cmp(s, v) >= 0;
		case ">":
			return cmp(s, v) > 0;
		case "<=":
			return cmp(s, v) <= 0;
		case "<":
			return cmp(s, v) < 0;
		case "~=": {
			const upper: Version = len <= 2 ? [v[0] + 1, 0, 0] : [v[0], v[1] + 1, 0];
			return cmp(s, v) >= 0 && cmp(s, upper) < 0;
		}
		case "!=":
			if (wildcard) return !prefixEq(s, v, len);
			return len >= 3 ? true : cmp(s, v) !== 0;
		default:
			return wildcard || len >= 3 ? prefixEq(s, v, len) : cmp(s, v) === 0;
	}
}

/** True if some 3.<minor>.x release satisfies every clause. */
function satisfies(spec: string | undefined, minor: number): boolean {
	if (!spec) return true;
	const clauses = spec.split(",").filter((c) => c.trim() !== "");
	return SAMPLE_PATCHES.some((patch) =>
		clauses.every((c) => clauseHolds(c, [3, minor, patch])),
	);
}

/** 3.14 if it fits `requires-python` and `.python-version`, else the highest that does (PY-003). */
export function pickPythonImage(requiresPython?: string): string {
	for (const minor of CANDIDATES) {
		if (satisfies(requiresPython, minor)) {
			return PYTHON_IMAGE_REFS[
				`3.${minor}-slim` as keyof typeof PYTHON_IMAGE_REFS
			];
		}
	}
	throw new MctError(
		"PUERTA_BLOQUEADA",
		"Ninguna imagen de Python fijada (3.13, 3.14, 3.15) cumple la versión que declara el proyecto.",
		{
			etapa: "verify",
			accion:
				"Ajusta requires-python o .python-version a una versión entre 3.13 y 3.15.",
			detalle: { motivo: "version-python" },
		},
	);
}

function globToRegex(glob: string): string {
	let out = "";
	const g = glob.replace(/^\.\//, "");
	for (let i = 0; i < g.length; i++) {
		const c = g[i] as string;
		if (c === "*") {
			if (g[i + 1] === "*") {
				out += ".*";
				i++;
			} else out += "[^/]*";
		} else if (c === "?") out += "[^/]";
		else out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
	}
	return `(?:^|/)${out}(?:/|$)`;
}

/** `verify.*` overrides from mct.config.json (they require `verify.motivo`). */
export interface PythonVerifyOptions {
	modo?: "compilar";
	ignorar?: string[];
}

/** Builds the PY-003 spec; `opts` carries the overrides. */
export function buildVerifySpec(
	a: Analysis,
	opts: PythonVerifyOptions = {},
): VerifySpec {
	const imagen = pickPythonImage(a.requiresPython);
	const compile = ["python", "-m", "compileall", "-q"];
	if (opts.ignorar && opts.ignorar.length > 0) {
		compile.push("-x", opts.ignorar.map(globToRegex).join("|"));
	}
	compile.push(".");
	const pipCheck: string[] | VerifyStep =
		opts.modo === "compilar"
			? { argv: ["pip", "check"], avisoSiFalla: "verify.pipCheck" }
			: ["pip", "check"];
	const start: Array<string[] | VerifyStep> = [compile, pipCheck];

	const entry = a.entrypoints[0];
	const serve =
		a.puerto !== undefined && opts.modo !== "compilar" && entry !== undefined;
	if (serve) {
		start.push(
			entry === "manage.py"
				? [
						"python",
						"manage.py",
						"runserver",
						`0.0.0.0:${a.puerto}`,
						"--noreload",
					]
				: entry.endsWith(".py")
					? ["python", entry]
					: [entry],
		);
	}

	const spec: VerifySpec = {
		imagen,
		start,
		healthcheck:
			serve && a.puerto !== undefined
				? {
						tipo: "http",
						puerto: a.puerto,
						ruta: "/",
						aceptar: ["2xx", "3xx", 404],
					}
				: { tipo: "salida-cero" },
		timeoutMin: DEFAULT_TIMEOUT_MIN,
	};
	const install = a.comandos.install;
	if (install) {
		spec.install = [
			"sh",
			"-c",
			`python -m venv /tmp/venv && . /tmp/venv/bin/activate && ${install}`,
		];
	}
	if (a.gestor === "poetry" && install === "pip install .") {
		spec.avisos = ["verify.poetrySinLock"];
	}
	return spec;
}
