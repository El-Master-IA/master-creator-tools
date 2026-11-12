import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initFromSource } from "../src/init.js";

let base: string;

async function put(rel: string, text: string): Promise<void> {
	const full = join(base, "origen", ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, text);
}

const tools = JSON.stringify({
	name: "t",
	devDependencies: { prettier: "1.0.0" },
});
const workflow = JSON.stringify({
	name: "wf",
	nodes: [{ name: "A", type: "n8n-nodes-base.start", parameters: {} }],
	connections: {},
});

async function run(extra: Record<string, unknown> = {}, file?: string) {
	return initFromSource({
		origen: file ?? join(base, "origen"),
		dest: join(base, "dest"),
		isTTY: false,
		mctVersion: "0.0.0",
		home: join(base, "home"),
		env: {},
		...extra,
	});
}

async function adapterOf(extra: Record<string, unknown> = {}, file?: string) {
	await run(extra, file);
	const state = JSON.parse(
		await readFile(join(base, "dest", ".mct", "state.json"), "utf8"),
	) as { adapter: string };
	return state.adapter;
}

async function validation(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	expect((err as MctError).codigo).toBe("VALIDACION");
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c08-"));
	await mkdir(join(base, "origen"), { recursive: true });
	await mkdir(join(base, "dest"), { recursive: true });
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("DET-001 deteccion de adaptadores", () => {
	it("DET-001 pyproject + uv.lock + package.json de herramientas elige python", async () => {
		await put("pyproject.toml", '[project]\nname = "x"\nversion = "1"\n');
		await put("uv.lock", "version = 1\n");
		await put("package.json", tools);
		expect(await adapterOf()).toBe("python");
	});

	it("DET-001 index.html + package.json de herramientas es ambiguo y pide --type", async () => {
		await put("index.html", "<html></html>");
		await put("package.json", tools);
		const err = await validation(run());
		expect(err.detalle).toEqual({
			motivo: "deteccion-ambigua",
			candidatos: [
				{ adapter: "estatico", confianza: 0.4 },
				{ adapter: "node", confianza: 0.3 },
			],
		});
		expect(err.accion).toContain("--type");
		expect(err.message).toContain("--type estatico");
	});

	it("DET-001 con --type estatico resuelve la ambiguedad", async () => {
		await put("index.html", "<html></html>");
		await put("package.json", tools);
		expect(await adapterOf({ type: "estatico" })).toBe("estatico");
	});

	it("DET-001 index.html (1 KiB) + dos .py (2 KiB) sin manifiesto elige estatico", async () => {
		await put("index.html", `<html>${"x".repeat(1024 - 13)}</html>`);
		await put("a.py", "#".repeat(2048));
		await put("b.py", "#".repeat(2048));
		expect(await adapterOf()).toBe("estatico");
	});

	it("DET-001 .php con mas bytes + dos .py sin manifiesto elige generico", async () => {
		await put("a.php", "x".repeat(4096));
		await put("a.py", "#".repeat(100));
		await put("b.py", "#".repeat(100));
		expect(await adapterOf()).toBe("generico");
	});

	it("DET-001 python por archivos con package.json de herramientas es ambiguo", async () => {
		await put("a.py", "#".repeat(300));
		await put("b.py", "#".repeat(300));
		await put("package.json", tools);
		const err = await validation(run());
		expect((err.detalle as { motivo: string }).motivo).toBe(
			"deteccion-ambigua",
		);
	});

	it("DET-001 export n8n valido + requirements.txt elige n8n", async () => {
		await put("flow.json", workflow);
		await put("requirements.txt", "requests==2.0.0\n");
		expect(await adapterOf()).toBe("n8n");
	});

	it("DET-001 Vite con index.html en la raiz y todo en devDependencies elige node", async () => {
		await put("index.html", "<html></html>");
		await put(
			"package.json",
			JSON.stringify({ name: "v", devDependencies: { vite: "1.0.0" } }),
		);
		expect(await adapterOf()).toBe("node");
	});

	it("DET-001 solo .php, .liquid o .ps1 elige generico", async () => {
		await put("a.php", "<?php\n");
		await put("b.liquid", "{{ x }}");
		await put("c.ps1", "Write-Host 1");
		expect(await adapterOf()).toBe("generico");
	});

	it("DET-001 un .json suelto que no es workflow da VALIDACION", async () => {
		await put("suelto.json", JSON.stringify({ a: 1 }));
		await validation(run({}, join(base, "origen", "suelto.json")));
	});

	it("DET-001 empate se decide por el lenguaje con mas bytes", async () => {
		// python 0.6 (requirements.txt) vs node 0.6 (scripts.build): python has more bytes.
		await put("requirements.txt", "requests==2.0.0\n");
		await put(
			"package.json",
			JSON.stringify({ name: "n", scripts: { build: "tsc" } }),
		);
		await put("a.py", "#".repeat(5000));
		await put("a.js", "//");
		expect(await adapterOf()).toBe("python");
	});

	it("DET-001 --type con confianza 0 sale con VALIDACION y la accion de tipos", async () => {
		await put("a.php", "<?php\n");
		const err = await validation(run({ type: "python" }));
		expect(err.accion).toBe(
			"Usa --type n8n, node, python, estatico o generico según el origen.",
		);
	});

	it("DET-001 --type generico fuerza generico aunque haya index.html", async () => {
		await put("index.html", "<html></html>");
		expect(await adapterOf({ type: "generico" })).toBe("generico");
	});
});
