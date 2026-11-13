import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding, ReadmeConfig } from "@mct/contract/types";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signApproval } from "../src/approval.js";
import { stagePackage } from "../src/package.js";
import { stageScan } from "../src/stage-scan.js";
import { createWorkspace, readState, updateState } from "../src/workspace.js";

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pkg-readme-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	await mkdir(join(home, ".mct"), { recursive: true });
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	await writeFile(args[args.indexOf("--report-path") + 1] as string, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};
const gitleaks = () => ({
	binary: process.execPath,
	installDir: join(base, "bin"),
	tmpDir: join(raiz, "tmp"),
	run: okRunner,
});

const contenido = (prompt = "Instala mct y libera este repo.") => ({
	promesa: "Libera tu repo privado sin filtrar secretos.",
	porQueExiste: "Publicar a mano deja pasar llaves.",
	queObtienes: ["Escaneo de secretos"],
	prompt,
	queNecesitas: [],
	comoFunciona: "Copia, revisa y empaqueta.",
	faq: [],
	siAlgoSaleMal: [],
	buenasPracticas: [],
	creditos: [],
});

async function empaqueta(readme?: ReadmeConfig) {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "demo-app" },
		adapter: "node",
	});
	const files: Record<string, string> = {
		"package.json": JSON.stringify({
			name: "demo-app",
			scripts: { start: "node index.js" },
		}),
		"index.js": "console.info('hola')\n",
		"README.md": "# viejo\n",
		"README.es.md": "# viejo es\n",
	};
	for (const [rel, data] of Object.entries(files)) {
		await writeFile(join(ws.work, rel), data);
	}
	await stageScan(raiz, { home, gitleaks: gitleaks() }).catch((e: unknown) => {
		if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA") throw e;
	});
	const doc = JSON.parse(
		await readFile(join(raiz, "findings.json"), "utf8"),
	) as {
		hallazgos: Finding[];
	};
	await updateState(raiz, (s) => ({
		...s,
		etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
	}));
	await signApproval({
		raiz,
		hallazgos: doc.hallazgos,
		gitleaksVersion: "8.30.1",
		mctVersion: "0.0.0",
	});
	return stagePackage(raiz, {
		holder: "El Máster IA",
		year: 2026,
		home,
		gitleaks: gitleaks(),
		...(readme !== undefined && { readme }),
	});
}

describe("PKG-008 / PKG-009 package con readme", { timeout: 60_000 }, () => {
	it("PKG-008 con el-master-ia deja README.md en español, README.en.md y quita README.es.md", async () => {
		const r = await empaqueta({
			plantilla: "el-master-ia",
			contenido: contenido(),
		});
		const es = await readFile(join(r.dist, "README.md"), "utf8");
		const en = await readFile(join(r.dist, "README.en.md"), "utf8");
		expect(es.startsWith("# demo-app\n")).toBe(true);
		expect(es).toContain("## Por qué existe");
		expect(en).toContain("## Why it exists");
		expect(es).not.toContain("# viejo");
		const raiz1 = await readdir(r.dist);
		expect(raiz1).not.toContain("README.es.md");
		// "Qué trae" lists the first level of dist/, templates included.
		const queTrae = es.split("## Qué trae\n\n")[1] ?? "";
		for (const e of [
			"LICENSE",
			"docs/",
			"index.js",
			"package.json",
			"README.md",
		]) {
			expect(queTrae).toContain(e);
		}
		expect(queTrae).not.toContain("README.es.md");
	});

	it("PKG-002 sin readme el dist es el estándar de siempre", async () => {
		const r = await empaqueta();
		const archivos = await readdir(r.dist);
		expect(archivos).toContain("README.es.md");
		expect(archivos).not.toContain("README.en.md");
		expect(await readFile(join(r.dist, "README.md"), "utf8")).toContain(
			"## Installation",
		);
	});

	it("PKG-009 un secreto en el contenido del README bloquea package sin mostrar el valor", async () => {
		const token = ["ghp", "_", "a1B2c3D4e5F6g7H8i9J0", "k1L2m3N4o5P6q7"].join(
			"",
		);
		let err: unknown;
		try {
			await empaqueta({
				plantilla: "el-master-ia",
				contenido: contenido(`Usa la llave ${token} para entrar.`),
			});
		} catch (e) {
			err = e;
		}
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect(
			JSON.stringify({
				m: (err as Error).message,
				d: (err as MctError).detalle,
			}),
		).not.toContain(token);
		expect((err as MctError).detalle).toEqual({
			campo: "readme.contenido.prompt",
		});
		expect((await readState(raiz)).etapas.package?.estado).not.toBe("ok");
		const findings = await readFile(join(raiz, "findings.json"), "utf8");
		expect(findings).not.toContain(token);
	});

	it("PKG-009 un término del diccionario con & o marcas Markdown bloquea igual", async () => {
		const termino = ["Smith", " & ", "Co"].join("");
		await writeFile(join(home, ".mct", "sensible.txt"), `${termino}\n`);
		for (const texto of [
			`Lo usa ${termino} a diario.`,
			`Lo usa ${["Sm", "*ith*", " & Co"].join("")} a diario.`,
		]) {
			let err: unknown;
			try {
				await rm(raiz, { recursive: true, force: true });
				await empaqueta({
					plantilla: "el-master-ia",
					contenido: { ...contenido(), comoFunciona: texto },
				});
			} catch (e) {
				err = e;
			}
			expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
			expect((err as Error).message).not.toContain("Smith");
		}
	});
});
