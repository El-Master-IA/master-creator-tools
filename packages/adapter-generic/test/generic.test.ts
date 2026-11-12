import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Analysis, Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { genericAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-generic-"));
	roots.push(raiz);
	for (const [zone, files] of [
		["work", work],
		["quarantine", quarantine],
		["dist", {}],
	] as const) {
		await mkdir(join(raiz, zone), { recursive: true });
		for (const [rel, content] of Object.entries(files)) {
			const target = join(raiz, zone, rel);
			await mkdir(dirname(target), { recursive: true });
			await writeFile(target, content, "utf8");
		}
	}
	return {
		raiz,
		work: join(raiz, "work"),
		quarantine: join(raiz, "quarantine"),
		dist: join(raiz, "dist"),
		estado: () => Promise.reject(new Error("no usado")),
	};
}

afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
	);
});

describe("GEN-001 lenguaje por bytes", () => {
	it("GEN-001 solo .php reporta lenguaje php y stack generico", async () => {
		const ws = await makeWs({ "index.php": "<?php echo 1;", "a/b.php": "x" });
		const a = await genericAdapter.analyze(ws);
		expect(a.lenguaje).toBe("php");
		expect(a.stack).toEqual(["generico"]);
	});

	it("GEN-001 gana la extension con mas bytes, no la de mas archivos", async () => {
		const ws = await makeWs({
			"a.py": "x".repeat(10),
			"b.py": "x".repeat(10),
			"c.php": "x".repeat(500),
		});
		expect((await genericAdapter.analyze(ws)).lenguaje).toBe("php");
	});

	it("GEN-001 mapea .liquid, .ps1 y .cc a su nombre de la tabla", async () => {
		for (const [file, nombre] of [
			["t.liquid", "liquid"],
			["s.ps1", "powershell"],
			["m.psm1", "powershell"],
			["x.cc", "cpp"],
			["x.h", "c"],
			["x.bash", "shell"],
			["x.mjs", "javascript"],
		] as const) {
			const ws = await makeWs({ [file]: "contenido" });
			expect((await genericAdapter.analyze(ws)).lenguaje).toBe(nombre);
		}
	});

	it("GEN-001 extension fuera de la tabla o sin archivos da otro", async () => {
		const fuera = await makeWs({ "a.xyz": "x".repeat(100), "b.php": "x" });
		expect((await genericAdapter.analyze(fuera)).lenguaje).toBe("otro");
		const vacio = await makeWs({});
		expect((await genericAdapter.analyze(vacio)).lenguaje).toBe("otro");
	});

	it("GEN-001 ignora node_modules y archivos binarios", async () => {
		const ws = await makeWs({
			"node_modules/x/big.js": "x".repeat(5000),
			"img.go": `ab\u0000${"x".repeat(5000)}`,
			"main.rb": "puts 1",
		});
		expect((await genericAdapter.analyze(ws)).lenguaje).toBe("ruby");
	});
});

describe("GEN-001 variables de .env*", () => {
	it("GEN-001 solo nombres que cumplen la regex, sin valores", async () => {
		const ws = await makeWs(
			{
				".env.example": [
					"API_URL=",
					"export DB_HOST=algo",
					"minuscula=1",
					"A=1",
					"X_".concat("1".repeat(70), "=1"),
					"# COMENTARIO=1",
				].join("\n"),
			},
			{ ".env": "SECRET_NAME=valor-que-no-debe-salir" },
		);
		const a = await genericAdapter.analyze(ws);
		const nombres = a.envVars.map((v) => v.nombre).sort();
		expect(nombres).toEqual(["API_URL", "DB_HOST", "SECRET_NAME"]);
		expect(JSON.stringify(a)).not.toContain("valor-que-no-debe-salir");
		expect(a.envVars.every((v) => v.obligatoria === false)).toBe(true);
	});
});

describe("GEN-001 detect y verifyCommand", () => {
	it("GEN-001 detect devuelve 0.1 en un directorio", async () => {
		const ws = await makeWs({ "a.php": "x" });
		expect(await genericAdapter.detect(ws.work)).toBe(0.1);
	});

	it("GEN-001 detect devuelve 0 en un archivo suelto", async () => {
		const ws = await makeWs({ "a.json": "{}" });
		expect(await genericAdapter.detect(join(ws.work, "a.json"))).toBe(0);
	});

	it("GEN-001 verifyCommand devuelve null", async () => {
		const ws = await makeWs({ "a.php": "x" });
		const a = await genericAdapter.analyze(ws);
		expect(genericAdapter.verifyCommand(a)).toBeNull();
	});
});

describe("PKG-007 packageHints genericos", () => {
	it("PKG-007 requisitos 'ver el codigo', sin instalacion ni uso inventados", () => {
		const a: Analysis = {
			stack: ["generico"],
			entrypoints: [],
			envVars: [
				{ nombre: "API_URL", obligatoria: false },
				{ nombre: "DB_HOST", obligatoria: false },
			],
			deps: [],
			comandos: {},
		};
		const h = genericAdapter.packageHints(a);
		expect(h.requisitos).toEqual(["ver el código"]);
		expect(h.instalacion).toEqual([]);
		expect(h.uso).toEqual([]);
		expect(h.variables.map((v) => v.nombre)).toEqual(["API_URL", "DB_HOST"]);
		expect(h.variables.every((v) => v.obligatoria === false)).toBe(true);
	});

	it("PKG-007 rules no aporta reglas propias", () => {
		expect(genericAdapter.rules()).toEqual([]);
	});
});
