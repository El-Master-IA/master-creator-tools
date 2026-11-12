import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeAdapter } from "@mct/adapter-node/index";
import { MctError } from "@mct/contract/errors";
import type { Change, Finding } from "@mct/contract/types";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signApproval } from "../src/approval.js";
import { hashTree } from "../src/hash.js";
import {
	applyChanges,
	resolveInside,
	type StagePackageOptions,
	stagePackage,
} from "../src/package.js";
import { type StageScanOptions, stageScan } from "../src/stage-scan.js";
import { createWorkspace, readState, updateState } from "../src/workspace.js";

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-package-"));
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
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

function gitleaks(): StageScanOptions["gitleaks"] {
	return {
		binary: process.execPath,
		installDir: join(base, "bin"),
		tmpDir: join(raiz, "tmp"),
		run: okRunner,
	};
}

function opts(over: Partial<StagePackageOptions> = {}): StagePackageOptions {
	return {
		holder: "Acme Labs",
		year: 2026,
		home,
		gitleaks: gitleaks(),
		...over,
	};
}

async function approved() {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "demo-app" },
		adapter: "node",
	});
	await writeFile(
		join(ws.work, "package.json"),
		'{"name":"demo","version":"1.0.0"}\n',
	);
	await stageScan(raiz, { home, gitleaks: gitleaks() });
	const doc = JSON.parse(
		await readFile(join(raiz, "findings.json"), "utf8"),
	) as { hallazgos: Finding[] };
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
	return ws;
}

async function codigoDe(p: Promise<unknown>): Promise<string> {
	try {
		await p;
	} catch (e) {
		if (e instanceof MctError) return e.codigo;
		throw e;
	}
	return "NINGUNO";
}

const ESCAPES: [string, Change][] = [
	["hacia work", { tipo: "crear", ruta: "../work/x.txt", contenido: "x" }],
	["padre", { tipo: "crear", ruta: "../../fuera.txt", contenido: "x" }],
	["absoluta", { tipo: "crear", ruta: "/etc/x.txt", contenido: "x" }],
	["unidad", { tipo: "crear", ruta: "C:/x.txt", contenido: "x" }],
	["barra invertida", { tipo: "crear", ruta: "a\\..\\..\\x", contenido: "x" }],
	["segmento punto", { tipo: "crear", ruta: "a/./b.txt", contenido: "x" }],
	["nul", { tipo: "crear", ruta: "a\0b.txt", contenido: "x" }],
	["borrar fuera", { tipo: "borrar", ruta: "../work/package.json" }],
	[
		"editar fuera",
		{
			tipo: "editar",
			ruta: "../work/package.json",
			desde: 0,
			hasta: 1,
			texto: "",
		},
	],
];

describe("PKG-005 los Change quedan dentro de dist", {
	timeout: 60_000,
}, () => {
	it.each(ESCAPES)(
		"PKG-005 CUANDO un Change sale de dist (%s) EL SISTEMA DEBE rechazar la etapa sin aplicar nada",
		async (_n, cambio) => {
			const ws = await approved();
			await writeFile(join(ws.dist, "previo.txt"), "intacto\n");
			const antesWork = await hashTree(ws.work);
			const antesDist = await hashTree(ws.dist);
			const hostil = {
				...nodeAdapter,
				generalize: async (): Promise<Change[]> => [
					{ tipo: "crear", ruta: "valido.txt", contenido: "ok\n" },
					cambio,
				],
			};
			expect(
				await codigoDe(stagePackage(raiz, opts({ adapters: [hostil] }))),
			).toBe("VALIDACION");
			expect(await hashTree(ws.work)).toBe(antesWork);
			expect(await hashTree(ws.dist)).toBe(antesDist);
			await expect(stat(join(raiz, "dist.new"))).rejects.toThrow();
			await expect(stat(join(ws.work, "x.txt"))).rejects.toThrow();
			expect((await readState(raiz)).etapas.package.estado).not.toBe("ok");
		},
	);

	it("PKG-005 CUANDO un Change de la lista falla ninguno de los válidos se aplica", async () => {
		const dir = join(base, "d");
		await mkdir(dir);
		await writeFile(join(dir, "a.txt"), "hola");
		const code = await codigoDe(
			applyChanges(dir, [
				{ tipo: "editar", ruta: "a.txt", desde: 0, hasta: 4, texto: "adiós" },
				{ tipo: "crear", ruta: "b.txt", contenido: "b" },
				{ tipo: "editar", ruta: "a.txt", desde: 2, hasta: 99, texto: "" },
			]),
		);
		expect(code).toBe("VALIDACION");
		expect(await readFile(join(dir, "a.txt"), "utf8")).toBe("hola");
		await expect(stat(join(dir, "b.txt"))).rejects.toThrow();
	});

	it("PKG-005 CUANDO los Change son válidos EL SISTEMA DEBE aplicarlos sobre el contenido crudo", async () => {
		const dir = join(base, "d");
		await mkdir(dir);
		await writeFile(join(dir, "a.txt"), "uno dos tres");
		await applyChanges(dir, [
			{ tipo: "editar", ruta: "a.txt", desde: 0, hasta: 3, texto: "1" },
			{ tipo: "editar", ruta: "a.txt", desde: 8, hasta: 12, texto: "3" },
			{ tipo: "crear", ruta: "sub/b.txt", contenido: "b" },
		]);
		expect(await readFile(join(dir, "a.txt"), "utf8")).toBe("1 dos 3");
		expect(await readFile(join(dir, "sub/b.txt"), "utf8")).toBe("b");
	});

	it("PKG-005 resolveInside acepta rutas normales y rechaza vacías o con ..", () => {
		expect(resolveInside(base, "a/b.txt")).toContain("b.txt");
		expect(() => resolveInside(base, "")).toThrow(MctError);
		expect(() => resolveInside(base, "a/../b")).toThrow(MctError);
		expect(() => resolveInside(base, 7)).toThrow(MctError);
	});
});
