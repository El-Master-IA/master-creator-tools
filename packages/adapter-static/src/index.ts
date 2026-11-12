import { readdir, readFile, stat } from "node:fs/promises";
import { join, posix } from "node:path";
import { MctError } from "@mct/contract/errors";
import type {
	Adapter,
	Analysis,
	PackageHints,
	VerifySpec,
	Workspace,
} from "@mct/contract/types";
import { buildVerifySpec, localResources } from "./verify.js";

const SITE_DIRS = ["", "public", "site", "docs", "www", "dist"] as const;
const SKIP_DIRS = new Set(["node_modules", ".git"]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const RE_ENV_NAME = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/;

// verifyCommand(a) only receives the Analysis: the local resources of the
// index.html travel next to the analysis object that analyze() returned.
const resourcesByAnalysis = new WeakMap<Analysis, string[]>();

async function isFile(path: string): Promise<boolean> {
	try {
		return (await stat(path)).isFile();
	} catch {
		return false;
	}
}

/** The index.html that detects the site: root first, then public/, site/, docs/, www/, dist/. */
async function findIndex(dir: string): Promise<string | null> {
	for (const sub of SITE_DIRS) {
		const rel = sub === "" ? "index.html" : `${sub}/index.html`;
		if (await isFile(join(dir, rel))) return rel;
	}
	return null;
}

async function readText(path: string): Promise<string | null> {
	try {
		const info = await stat(path);
		if (!info.isFile() || info.size > MAX_FILE_BYTES) return null;
		return await readFile(path, "utf8");
	} catch {
		return null;
	}
}

async function envNames(
	root: string,
	dir: string,
	into: Set<string>,
): Promise<void> {
	let entries: import("node:fs").Dirent[];
	try {
		entries = await readdir(join(root, dir), { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) await envNames(root, rel, into);
		} else if (entry.isFile() && entry.name.startsWith(".env")) {
			const text = await readText(join(root, rel));
			if (text === null) continue;
			// Names only: values are never read into the result.
			for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
				const name = RE_ENV_NAME.exec(line)?.[1];
				if (name) into.add(name);
			}
		}
	}
}

export const staticAdapter: Omit<Adapter, "verifyCommand"> & {
	verifyCommand(a: Analysis): VerifySpec;
} = {
	id: "estatico",

	// DET-001: 0.4 with an index.html in the root or in public/, site/, docs/, www/, dist/.
	async detect(dir: string): Promise<number> {
		return (await findIndex(dir)) === null ? 0 : 0.4;
	},

	async analyze(ws: Workspace): Promise<Analysis> {
		const names = new Set<string>();
		await envNames(ws.work, "", names);
		await envNames(ws.quarantine, "", names);
		const entry = (await findIndex(ws.dist)) ?? (await findIndex(ws.work));
		const analysis: Analysis = {
			stack: ["estatico"],
			entrypoints: entry === null ? [] : [entry],
			envVars: [...names].map((nombre) => ({ nombre, obligatoria: false })),
			deps: [],
			lenguaje: "html",
			comandos: {},
		};
		if (entry !== null) {
			const base = (await isFile(join(ws.dist, entry))) ? ws.dist : ws.work;
			const html = (await readText(join(base, entry))) ?? "";
			resourcesByAnalysis.set(analysis, localResources(html));
		}
		return analysis;
	},

	rules: () => [],

	packageHints(a: Analysis): PackageHints {
		const entry = a.entrypoints[0];
		const dir = entry === undefined ? "." : posix.dirname(entry);
		const uso =
			dir === "."
				? ["Abre index.html en el navegador."]
				: [`Ejecuta \`python -m http.server\` en la carpeta ${dir}.`];
		return {
			instalacion: [],
			uso,
			variables: a.envVars.map((v) => ({
				nombre: v.nombre,
				descripcion: v.obligatoria ? "Obligatoria." : "Opcional.",
				obligatoria: v.obligatoria,
			})),
			requisitos: ["Un navegador"],
		};
	},

	verifyCommand(a: Analysis): VerifySpec {
		const entry = a.entrypoints[0];
		if (entry === undefined) {
			throw new MctError(
				"PUERTA_BLOQUEADA",
				"El sitio estático no tiene index.html: no hay nada que servir para verificar.",
				{
					etapa: "verify",
					accion: "Agrega un index.html y vuelve a correr init.",
					detalle: { motivo: "sin-index" },
				},
			);
		}
		return buildVerifySpec(entry, resourcesByAnalysis.get(a) ?? []);
	},
};
