import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Rule } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/gitleaks.js";
import { type ScanOptions, scan as scanConClave } from "../src/scan.js";
import { CLAVE_PRUEBA } from "./clave.js";

const scan = (options: ScanOptions) =>
	scanConClave({ clave: CLAVE_PRUEBA, ...options });

import { buildFixture } from "./fixtures/build.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const c of cleanups.splice(0)) await c();
});

/** gitleaks falso: reporta cada ocurrencia literal de las agujas, con --redact. */
function fakeGitleaks(needles: readonly string[]): Runner {
	return async (_cmd, args) => {
		if (args.includes("version")) {
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		}
		const target = args[args.indexOf("dir") + 1] as string;
		const reportPath = args[args.indexOf("--report-path") + 1] as string;
		const out: unknown[] = [];
		const entries = await readdir(target, {
			recursive: true,
			withFileTypes: true,
		});
		for (const e of entries) {
			if (!e.isFile()) continue;
			const file = join(e.parentPath, e.name);
			const lines = (await readFile(file, "utf8")).split("\n");
			lines.forEach((line, i) => {
				for (const n of needles) {
					const at = line.indexOf(n);
					if (at >= 0) {
						// Semántica real de gitleaks 8.30.1 (detect/location.go): columnas
						// en bytes, base 1, y +1 de desfase fuera de la primera línea.
						const shift = i > 0 ? 1 : 0;
						const start = Buffer.byteLength(line.slice(0, at));
						out.push({
							RuleID: "generic-api-key",
							File: file,
							StartLine: i + 1,
							EndLine: i + 1,
							StartColumn: start + 1 + shift,
							EndColumn: start + Buffer.byteLength(n) + shift,
						});
					}
				}
			});
		}
		await writeFile(reportPath, JSON.stringify(out));
		return {
			code: out.length > 0 ? 2 : 0,
			signal: null,
			stdout: "",
			timedOut: false,
		};
	};
}

async function tmpDirs(): Promise<{ tmpDir: string; installDir: string }> {
	const base = await mkdtemp(join(tmpdir(), "mct-scan-"));
	cleanups.push(() => rm(base, { recursive: true, force: true }));
	await mkdir(join(base, "tmp"), { recursive: true });
	return { tmpDir: join(base, "tmp"), installDir: join(base, "bin") };
}

async function snapshot(root: string): Promise<string> {
	const entries = await readdir(root, { recursive: true, withFileTypes: true });
	const parts: string[] = [];
	for (const e of entries.sort((a, b) =>
		(a.parentPath + a.name).localeCompare(b.parentPath + b.name),
	)) {
		const p = join(e.parentPath, e.name);
		parts.push(e.isFile() ? `${p}\n${await readFile(p, "utf8")}` : p);
	}
	return parts.join("\n--\n");
}

async function treeWith(
	files: Record<string, string | Buffer>,
	quarantine: Record<string, string | Buffer> = {},
) {
	const base = await mkdtemp(join(tmpdir(), "mct-mut-"));
	cleanups.push(() => rm(base, { recursive: true, force: true }));
	for (const [zone, set] of [
		["work", files],
		["quarantine", quarantine],
	] as const) {
		await mkdir(join(base, zone), { recursive: true });
		for (const [rel, content] of Object.entries(set)) {
			await writeFile(join(base, zone, rel), content);
		}
	}
	return { work: join(base, "work"), quarantine: join(base, "quarantine") };
}

const VERSION_OK = {
	code: 0,
	signal: null,
	stdout: "8.30.1\n",
	timedOut: false,
};

describe("mutaciones, cuarentena y fail closed", () => {
	it("SCAN-003 los hallazgos de quarantine quedan aislados y nada se escribe", async () => {
		const fx = await buildFixture("node");
		cleanups.push(() => fx.cleanup());
		const dirs = await tmpDirs();
		const before = await snapshot(fx.root);
		const { hallazgos } = await scan({
			work: fx.work,
			quarantine: fx.quarantine,
			gitleaks: {
				binary: process.execPath,
				...dirs,
				run: fakeGitleaks(fx.truth.secrets.map((s) => s.value)),
			},
		});
		const q = hallazgos.filter((f) => f.zona === "quarantine");
		expect(q.length).toBeGreaterThan(0);
		expect(q.every((f) => f.estado === "aislado")).toBe(true);
		expect(
			hallazgos
				.filter((f) => f.zona === "work")
				.every((f) => f.estado !== "aislado"),
		).toBe(true);
		expect(await snapshot(fx.root)).toBe(before);
		expect(await readdir(dirs.tmpDir)).toEqual([]);
		const dump = JSON.stringify(hallazgos);
		for (const s of fx.truth.secrets) {
			expect(dump).not.toContain(s.value);
			expect(dump).not.toContain(Buffer.from(s.value).toString("base64"));
		}
		for (const f of hallazgos) {
			expect(f.fragmento.replace(/\*+$/, "").length).toBeLessThanOrEqual(4);
			expect(f.archivo).not.toContain("\\");
			expect(Object.keys(f)).not.toContain("value");
		}
	});

	it("SCAN-005 un término del diccionario se reporta como dict-match sin escribir el término", async () => {
		const term = ["ac", "me", "-", "cli", "ent"].join("");
		const tree = await treeWith(
			{ "notes.txt": `hola\ncliente ${term} aquí\n` },
			{ ".env": `X=${term}\n` },
		);
		const dirs = await tmpDirs();
		const { hallazgos } = await scan({
			...tree,
			dictionary: [term],
			gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
		});
		const dict = hallazgos.filter((f) => f.regla === "dict-match");
		expect(
			dict.map((f) => [f.zona, f.archivo, f.linea, f.fragmento, f.estado]),
		).toEqual([
			["quarantine", ".env", 1, "[dic:0]", "aislado"],
			["work", "notes.txt", 2, "[dic:0]", "abierto"],
		]);
		expect(JSON.stringify(hallazgos)).not.toContain(term);
	});

	it("SCAN-003 un binario, uno UTF-16 y uno sobre el límite son hallazgos abiertos", async () => {
		const tree = await treeWith({
			"logo.png": Buffer.from([
				0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 1,
			]),
			"wide.txt": Buffer.from("﻿hola mundo", "utf16le"),
			"big.txt": "a".repeat(200),
		});
		const dirs = await tmpDirs();
		const { hallazgos } = await scan({
			...tree,
			maxBytes: 100,
			gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
		});
		const by = Object.fromEntries(hallazgos.map((f) => [f.archivo, f]));
		expect(by["logo.png"]).toMatchObject({
			tipo: "binario",
			regla: "binary-image",
			estado: "abierto",
		});
		expect(by["wide.txt"]).toMatchObject({
			tipo: "binario",
			regla: "binary-utf16",
			estado: "abierto",
		});
		expect(by["big.txt"]).toMatchObject({
			tipo: "binario",
			regla: "binary-oversize",
			estado: "abierto",
		});
	});

	it("SCAN-003 las reglas del adaptador y los avisos de registro entran como estructura", async () => {
		const secret = ["pin", "Data", "-", "abcdef123456"].join("");
		const tree = await treeWith({
			"flow.json": `{"x": "${secret}"}\n`,
			"package-lock.json": "{}\n",
		});
		const rules: Rule[] = [
			{
				id: "demo-rule",
				tipo: "estructura",
				severidad: "medio",
				patron: /"x": "(pinData-[a-z0-9]+)"/,
			},
		];
		const dirs = await tmpDirs();
		const { hallazgos } = await scan({
			...tree,
			rules,
			registryIssues: [
				{
					tipo: "registro-privado",
					archivo: "package-lock.json",
					zona: "work",
					linea: 1,
				},
			],
			gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
		});
		expect(hallazgos.find((f) => f.regla === "demo-rule")).toMatchObject({
			tipo: "estructura",
			severidad: "medio",
			archivo: "flow.json",
			linea: 1,
			fragmento: "pinD****",
		});
		expect(hallazgos.find((f) => f.regla === "registro-privado")).toMatchObject(
			{
				tipo: "estructura",
				archivo: "package-lock.json",
				linea: 1,
				fragmento: "****",
			},
		);
		expect(JSON.stringify(hallazgos)).not.toContain(secret);
	});

	it("SCAN-001 un fallo de gitleaks propaga MOTOR_NO_DISPONIBLE sin resultados", async () => {
		const tree = await treeWith({ "a.txt": "hola\n" });
		const dirs = await tmpDirs();
		const run: Runner = async (_c, args) =>
			args.includes("version")
				? VERSION_OK
				: { code: 9, signal: null, stdout: "", timedOut: false };
		await expect(
			scan({ ...tree, gitleaks: { binary: process.execPath, ...dirs, run } }),
		).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
	});

	it("SCAN-001 si no se recupera la posición de un hallazgo de gitleaks falla cerrado", async () => {
		const tree = await treeWith({ "a.txt": "hola\n" });
		const dirs = await tmpDirs();
		const run: Runner = async (_c, args) => {
			if (args.includes("version")) return VERSION_OK;
			const target = args[args.indexOf("dir") + 1] as string;
			const report = args[args.indexOf("--report-path") + 1] as string;
			await writeFile(
				report,
				JSON.stringify([
					{
						RuleID: "r",
						File: join(target, "a.txt"),
						StartLine: 7,
						EndLine: 7,
						StartColumn: 3,
						EndColumn: 5,
					},
				]),
			);
			return { code: 2, signal: null, stdout: "", timedOut: false };
		};
		await expect(
			scan({ ...tree, gitleaks: { binary: process.execPath, ...dirs, run } }),
		).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
	});

	it("SCAN-001 un fallo del detector propio propaga MOTOR_NO_DISPONIBLE", async () => {
		const tree = await treeWith({ "a.txt": "hola\n" });
		const dirs = await tmpDirs();
		await expect(
			scan({
				...tree,
				dictionary: ["x".repeat(300)],
				gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
			}),
		).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
	});

	it("SCAN-001 si falta el binario instala la descarga fijada", async () => {
		const tree = await treeWith({ "a.txt": "hola\n" });
		const dirs = await tmpDirs();
		const asked: string[] = [];
		const { gitleaksVersion } = await scan({
			...tree,
			gitleaks: {
				...dirs,
				run: fakeGitleaks([]),
				install: async (o) => {
					asked.push(o.destDir);
					return process.execPath;
				},
			},
		});
		expect(asked).toEqual([dirs.installDir]);
		expect(gitleaksVersion).toBe("8.30.1");
	});
});

/** gitleaks falso que devuelve un reporte fijo (formato real de 8.30.1). */
function reportRunner(items: readonly Record<string, unknown>[]): Runner {
	return async (_c, args) => {
		if (args.includes("version")) return VERSION_OK;
		const target = args[args.indexOf("dir") + 1] as string;
		const report = args[args.indexOf("--report-path") + 1] as string;
		await writeFile(
			report,
			JSON.stringify(
				items.map((i) => ({ ...i, File: join(target, `${i.File}`) })),
			),
		);
		return { code: 2, signal: null, stdout: "", timedOut: false };
	};
}

describe("reglas de solo ruta de gitleaks", () => {
	const pathOnly = {
		RuleID: "pkcs12-file",
		File: "certs/k.p12",
		StartLine: 0,
		EndLine: 0,
		StartColumn: 0,
		EndColumn: 0,
		Match: "file detected: certs/k.p12",
	};

	async function certTree(content: string) {
		const tree = await treeWith({});
		await mkdir(join(tree.work, "certs"), { recursive: true });
		await writeFile(join(tree.work, "certs", "k.p12"), content);
		return tree;
	}

	it("SCAN-001 una regla de solo ruta da un hallazgo de archivo en línea 0 y columna 0", async () => {
		const tree = await certTree("uno");
		const dirs = await tmpDirs();
		const { hallazgos } = await scan({
			...tree,
			gitleaks: {
				binary: process.execPath,
				...dirs,
				run: reportRunner([pathOnly]),
			},
		});
		const gl = hallazgos.filter((f) => f.motor === "gitleaks");
		expect(gl).toHaveLength(1);
		expect(gl[0]).toMatchObject({
			regla: "pkcs12-file",
			tipo: "secreto",
			zona: "work",
			archivo: "certs/k.p12",
			linea: 0,
			columna: 0,
			fragmento: "****",
			estado: "abierto",
		});
	});

	it("SCAN-009 el hallazgo de solo ruta cambia de ID si cambia el contenido del archivo", async () => {
		const ids: string[] = [];
		for (const content of ["uno", "uno", "dos"]) {
			const { hallazgos } = await scan({
				...(await certTree(content)),
				gitleaks: {
					binary: process.execPath,
					...(await tmpDirs()),
					run: reportRunner([pathOnly]),
				},
			});
			ids.push(hallazgos.find((f) => f.motor === "gitleaks")?.id ?? "");
		}
		expect(ids[0]).toMatch(/^[0-9a-f]{64}$/);
		expect(ids[1]).toBe(ids[0]);
		expect(ids[2]).not.toBe(ids[0]);
	});

	it("SCAN-004 línea 0 con columna distinta de 0 sigue siendo un reporte inválido", async () => {
		const tree = await certTree("uno");
		await expect(
			scan({
				...tree,
				gitleaks: {
					binary: process.execPath,
					...(await tmpDirs()),
					run: reportRunner([{ ...pathOnly, StartColumn: 3 }]),
				},
			}),
		).rejects.toMatchObject({
			codigo: "MOTOR_NO_DISPONIBLE",
			detalle: { motivo: "reporte-invalido" },
		});
	});
});

describe("rutas como superficie de escaneo (SEG-001, SCAN-005)", () => {
	const aws = ["AK", "IA", "ABCDEFGHIJKLMNOP"].join("");
	const email = ["ana.perez", "@", "example", ".org"].join("");
	const term = ["Acme", "Corp"].join("");

	async function pathTree(
		paths: readonly string[],
		quarantine: readonly string[] = [],
	) {
		const tree = await treeWith({});
		for (const [root, set] of [
			[tree.work, paths],
			[tree.quarantine, quarantine],
		] as const) {
			for (const p of set) {
				if (p.endsWith("/")) {
					await mkdir(join(root, p), { recursive: true });
				} else {
					await mkdir(dirname(join(root, p)), { recursive: true });
					await writeFile(join(root, p), "hola\n");
				}
			}
		}
		return tree;
	}

	async function run(
		tree: { work: string; quarantine: string },
		dictionary?: string[],
	) {
		return scan({
			...tree,
			...(dictionary === undefined ? {} : { dictionary }),
			gitleaks: {
				binary: process.execPath,
				...(await tmpDirs()),
				run: fakeGitleaks([]),
			},
		});
	}

	it("SEG-001 un secreto en el nombre de un archivo se reporta en línea 0 con fragmento enmascarado", async () => {
		const tree = await pathTree([`keys/${aws}.txt`]);
		const { hallazgos } = await run(tree);
		const hit = hallazgos.filter((f) => f.regla === "aws-access-key");
		expect(hit).toHaveLength(1);
		expect(hit[0]).toMatchObject({
			tipo: "secreto",
			zona: "work",
			archivo: `keys/${aws}.txt`,
			linea: 0,
			columna: 0,
			fragmento: "AKIA****",
		});
		expect(hit[0]?.fragmento).not.toContain(aws);
	});

	it("SEG-001 un secreto en el nombre de una carpeta se reporta una sola vez, en la carpeta", async () => {
		const tree = await pathTree([`${aws}/uno.txt`, `${aws}/dos.txt`, "vacia/"]);
		const { hallazgos } = await run(tree);
		const hit = hallazgos.filter((f) => f.regla === "aws-access-key");
		expect(hit.map((f) => f.archivo)).toEqual([aws]);
		expect(hit[0]).toMatchObject({ linea: 0, columna: 0 });
	});

	it("SEG-001 los datos personales en la ruta (también en cuarentena) se reportan enmascarados", async () => {
		const tree = await pathTree([], [`export/${email}.csv`]);
		const { hallazgos } = await run(tree);
		const hit = hallazgos.filter((f) => f.tipo === "pii" && f.linea === 0);
		expect(hit).toHaveLength(1);
		expect(hit[0]).toMatchObject({
			zona: "quarantine",
			estado: "aislado",
			archivo: `export/${email}.csv`,
			columna: 0,
		});
		expect(hit[0]?.fragmento).not.toContain(email);
		expect(hit[0]?.fragmento.length).toBeLessThanOrEqual(8);
	});

	it("SCAN-005 un término del diccionario en una carpeta es dict-match sin exponer el término", async () => {
		const tree = await pathTree([`${term}-proyecto/notas.txt`]);
		const { hallazgos } = await run(tree, [term]);
		const hit = hallazgos.filter((f) => f.regla === "dict-match");
		expect(hit).toHaveLength(1);
		expect(hit[0]).toMatchObject({
			tipo: "pii",
			linea: 0,
			columna: 0,
			fragmento: "[dic:0]",
			archivo: "[dic:0]-proyecto",
		});
		expect(JSON.stringify(hallazgos).toLowerCase()).not.toContain(
			term.toLowerCase(),
		);
	});

	it("SCAN-005 el ID del dict-match de ruta es estable y depende de la ruta real", async () => {
		const a = await run(await pathTree([`${term}-uno/x.txt`]), [term]);
		const b = await run(await pathTree([`${term}-uno/x.txt`]), [term]);
		const c = await run(await pathTree([`${term}-dos/x.txt`]), [term]);
		const id = (r: typeof a) =>
			r.hallazgos.find((f) => f.regla === "dict-match")?.id;
		expect(id(a)).toMatch(/^[0-9a-f]{64}$/);
		expect(id(b)).toBe(id(a));
		expect(id(c)).not.toBe(id(a));
	});

	it("SCAN-005 las rutas comunes no producen hallazgos", async () => {
		const tree = await pathTree(["src/index.js", "docs/readme.md", "vacia/"]);
		const { hallazgos } = await run(tree, [term]);
		expect(hallazgos).toEqual([]);
	});
});
