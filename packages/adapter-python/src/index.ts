import { join } from "node:path";
import type { Adapter, Analysis, Rule, VerifySpec } from "@mct/contract/types";
import {
	analyzeProject,
	hasManifest,
	readPythonFiles,
	readText,
	rootEntrypoints,
	scriptNames,
	walk,
} from "./analyze.js";
import { pythonPackageHints } from "./hints.js";
import { buildVerifySpec } from "./verify.js";

/** Language by extension (GEN-001 table). */
const EXT_LANGUAGE: Readonly<Record<string, string>> = {
	php: "php",
	liquid: "liquid",
	sh: "shell",
	bash: "shell",
	ps1: "powershell",
	psm1: "powershell",
	cs: "csharp",
	go: "go",
	rb: "ruby",
	rs: "rust",
	java: "java",
	kt: "kotlin",
	c: "c",
	h: "c",
	cpp: "cpp",
	cc: "cpp",
	hpp: "cpp",
	swift: "swift",
	dart: "dart",
	lua: "lua",
	js: "javascript",
	mjs: "javascript",
	cjs: "javascript",
	ts: "typescript",
	py: "python",
	html: "html",
	htm: "html",
	css: "css",
};

const RULES: readonly Rule[] = [
	{
		id: "python-index-url-credenciales",
		tipo: "secreto",
		severidad: "critico",
		patron:
			/(?:--(?:extra-)?index-url|\s-i)[ =]\s{0,5}https?:\/\/[^\s:@/'"]{1,100}:([^\s@/'"]{1,200})@[\w.-]{1,255}/i,
	},
	{
		id: "python-django-secret-key",
		tipo: "secreto",
		severidad: "critico",
		patron: /\bSECRET_KEY\s{0,5}=\s{0,5}["']([^"'\s]{16,200})["']/,
	},
];

/** Python by files: two or more .py and .py is the language with most bytes. */
async function pythonByFiles(dir: string): Promise<boolean> {
	const bytes = new Map<string, number>();
	let pyCount = 0;
	for (const rel of await walk(dir)) {
		const dot = rel.lastIndexOf(".");
		const lang =
			dot < 0 ? undefined : EXT_LANGUAGE[rel.slice(dot + 1).toLowerCase()];
		if (lang === undefined) continue;
		if (lang === "python") pyCount++;
		const text = await readText(join(dir, rel));
		const size = text === null ? 0 : Buffer.byteLength(text);
		bytes.set(lang, (bytes.get(lang) ?? 0) + size);
	}
	if (pyCount < 2) return false;
	const py = bytes.get("python") ?? 0;
	return [...bytes].every(([lang, n]) => lang === "python" || py > n);
}

/** These adapters always verify: the narrower type spares callers a null check. */
export const pythonAdapter: Omit<Adapter, "verifyCommand"> & {
	verifyCommand(a: Analysis): VerifySpec;
} = {
	id: "python",

	async detect(dir: string): Promise<number> {
		const files = await readPythonFiles(dir, { strict: false });
		if (!hasManifest(files)) return (await pythonByFiles(dir)) ? 0.35 : 0;
		let score = 0.6;
		if (files.hasUvLock || files.hasPoetryLock) score += 0.15;
		if (
			scriptNames(files.pyproject).length > 0 ||
			(await rootEntrypoints(dir)).length > 0
		) {
			score += 0.15;
		}
		return Math.min(score, 0.9);
	},

	analyze: analyzeProject,

	rules(): Rule[] {
		return RULES.map((r) => ({ ...r }));
	},

	packageHints: (a: Analysis) => pythonPackageHints(a),

	verifyCommand: (a: Analysis): VerifySpec => buildVerifySpec(a),
};
