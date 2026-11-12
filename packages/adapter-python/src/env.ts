/** Environment variable discovery for Python sources (PY-002). Values are never kept. */

const RE_ENVIRON_INDEX =
	/\benviron\[\s*["']([A-Za-z_]\w*)["']\s*\](?!\s*=(?!=))/g;
const RE_ENV_GET =
	/\b(?:os\.)?(?:environ\.get|getenv)\(\s*["']([A-Za-z_]\w*)["']([^)]*)\)/g;
const RE_FIELD = /\bField\(([^)]*)\)/g;
const RE_FIELD_NAME =
	/\b(?:env|alias|validation_alias)\s*=\s*["']([A-Za-z_]\w*)["']/g;
const RE_DOTENV_NAME = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

export function addVar(
	vars: Map<string, boolean>,
	name: string,
	required: boolean,
): void {
	vars.set(name, (vars.get(name) ?? false) || required);
}

function fieldHasDefault(args: string): boolean {
	if (/\bdefault(?:_factory)?\s*=/.test(args)) return true;
	const first = (args.split(",")[0] ?? "").trim();
	if (first === "" || first === "...") return false;
	return !/^\w+\s*=(?!=)/.test(first);
}

/** Collects variables read by Python code; required means read without a default. */
export function scanPythonEnv(text: string, vars: Map<string, boolean>): void {
	for (const m of text.matchAll(RE_ENVIRON_INDEX)) {
		if (m[1]) addVar(vars, m[1], true);
	}
	for (const m of text.matchAll(RE_ENV_GET)) {
		if (!m[1]) continue;
		const rest = (m[2] ?? "").trim();
		addVar(vars, m[1], rest === "" || /^,\s*None$/.test(rest));
	}
	if (!text.includes("BaseSettings")) return;
	for (const f of text.matchAll(RE_FIELD)) {
		const args = f[1] ?? "";
		const required = !fieldHasDefault(args);
		for (const n of args.matchAll(RE_FIELD_NAME)) {
			if (n[1]) addVar(vars, n[1], required);
		}
	}
}

/** Adds the variable names of a `.env*` file as optional; never reads values. */
export function readDotenv(text: string, vars: Map<string, boolean>): void {
	for (const line of text.split("\n")) {
		const name = RE_DOTENV_NAME.exec(line)?.[1];
		if (name) addVar(vars, name, false);
	}
}
