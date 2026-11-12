import { open, readdir, readFile, stat } from "node:fs/promises";
import { extname, join } from "node:path";
import type {
	Adapter,
	Analysis,
	PackageHints,
	Workspace,
} from "@mct/contract/types";

const CONFIDENCE = 0.1;
const MAX_ENV_BYTES = 2 * 1024 * 1024;
const SNIFF_BYTES = 8192;
const SKIP_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	"coverage",
	".next",
]);

/** Closed table of GEN-001: extension -> language name. */
const LANGUAGES: Readonly<Record<string, string>> = {
	".php": "php",
	".liquid": "liquid",
	".sh": "shell",
	".bash": "shell",
	".ps1": "powershell",
	".psm1": "powershell",
	".cs": "csharp",
	".go": "go",
	".rb": "ruby",
	".rs": "rust",
	".java": "java",
	".kt": "kotlin",
	".c": "c",
	".h": "c",
	".cpp": "cpp",
	".cc": "cpp",
	".hpp": "cpp",
	".swift": "swift",
	".dart": "dart",
	".lua": "lua",
	".js": "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
	".ts": "typescript",
	".py": "python",
	".html": "html",
	".htm": "html",
	".css": "css",
};

const RE_ENV_NAME = /^[A-Z][A-Z0-9_]{1,63}$/;
const RE_DOTENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

/** Relative file paths under `root`, skipping heavy directories. */
async function walk(root: string, dir = ""): Promise<string[]> {
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

async function isText(path: string): Promise<boolean> {
	let handle: Awaited<ReturnType<typeof open>> | undefined;
	try {
		handle = await open(path, "r");
		const buf = Buffer.alloc(SNIFF_BYTES);
		const { bytesRead } = await handle.read(buf, 0, SNIFF_BYTES, 0);
		return !buf.subarray(0, bytesRead).includes(0);
	} catch {
		return false;
	} finally {
		await handle?.close();
	}
}

async function dominantLanguage(work: string): Promise<string> {
	const bytes = new Map<string, number>();
	for (const rel of await walk(work)) {
		const path = join(work, rel);
		let size: number;
		try {
			size = (await stat(path)).size;
		} catch {
			continue;
		}
		if (size === 0 || !(await isText(path))) continue;
		const ext = extname(rel).toLowerCase();
		bytes.set(ext, (bytes.get(ext) ?? 0) + size);
	}
	let best: string | undefined;
	let bestBytes = 0;
	for (const [ext, total] of [...bytes].sort(([a], [b]) =>
		a.localeCompare(b),
	)) {
		if (total > bestBytes) {
			best = ext;
			bestBytes = total;
		}
	}
	return (best !== undefined ? LANGUAGES[best] : undefined) ?? "otro";
}

/** Adds only the names (never values) of a `.env*` file that match the closed regex. */
async function readEnvNames(root: string, names: Set<string>): Promise<void> {
	for (const rel of await walk(root)) {
		const base = rel.slice(rel.lastIndexOf("/") + 1);
		if (!base.startsWith(".env")) continue;
		let text: string;
		try {
			const path = join(root, rel);
			if ((await stat(path)).size > MAX_ENV_BYTES) continue;
			text = await readFile(path, "utf8");
		} catch {
			continue;
		}
		for (const line of text.split(/\r?\n/)) {
			const name = RE_DOTENV_LINE.exec(line)?.[1];
			if (name !== undefined && RE_ENV_NAME.test(name)) names.add(name);
		}
	}
}

export const genericAdapter: Adapter = {
	id: "generico",

	async detect(dir: string): Promise<number> {
		try {
			// A loose file only admits n8n.
			return (await stat(dir)).isDirectory() ? CONFIDENCE : 0;
		} catch {
			return 0;
		}
	},

	async analyze(ws: Workspace): Promise<Analysis> {
		const names = new Set<string>();
		await readEnvNames(ws.work, names);
		await readEnvNames(ws.quarantine, names);
		return {
			stack: ["generico"],
			entrypoints: [],
			envVars: [...names].map((nombre) => ({ nombre, obligatoria: false })),
			deps: [],
			lenguaje: await dominantLanguage(ws.work),
			comandos: {},
		};
	},

	rules: () => [],

	packageHints(a: Analysis): PackageHints {
		return {
			instalacion: [],
			uso: [],
			variables: a.envVars.map((v) => ({
				nombre: v.nombre,
				descripcion: v.obligatoria
					? "Obligatoria."
					: "Opcional (tiene valor por defecto o es de ejemplo).",
				obligatoria: v.obligatoria,
			})),
			requisitos: ["ver el código"],
		};
	},

	verifyCommand: () => null,
};
