import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashTree } from "../src/hash.js";
import { initFromSource } from "../src/init.js";

let base: string;
let origen: string;

const pkg = JSON.stringify({
	name: "demo",
	version: "1.0.0",
	scripts: { start: "node index.js" },
});
const workflow = JSON.stringify({
	name: "wf",
	nodes: [{ name: "A", type: "n8n-nodes-base.start", parameters: {} }],
	connections: {},
});

function opts(dest: string, extra: Record<string, unknown> = {}) {
	return {
		origen,
		dest,
		isTTY: false,
		mctVersion: "0.0.0",
		home: join(base, "home"),
		env: {},
		...extra,
	};
}

async function expectValidacion(p: Promise<unknown>) {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	expect((err as MctError).codigo).toBe("VALIDACION");
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t17d-"));
	origen = join(base, "origen");
	await mkdir(join(origen, "sub"), { recursive: true });
	await writeFile(join(origen, "package.json"), pkg);
	await writeFile(join(origen, "sub", "a.js"), "export {};\n");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-001 el destino no puede estar dentro del origen", () => {
	it("CLI-001 dest == origen: VALIDACION y el origen queda intacto", async () => {
		const antes = await hashTree(origen);
		const err = await expectValidacion(initFromSource(opts(origen)));
		expect(err.accion).toContain("--dest");
		expect(await hashTree(origen)).toBe(antes);
	});

	it("CLI-001 dest en subcarpeta (existente o no) del origen: VALIDACION sin escribir", async () => {
		const antes = await hashTree(origen);
		await expectValidacion(initFromSource(opts(join(origen, "sub"))));
		await expectValidacion(
			initFromSource(opts(join(origen, "no", "existe", "aun"))),
		);
		expect(await hashTree(origen)).toBe(antes);
	});

	it("CLI-001 compara sin distinguir mayúsculas en Windows y con rutas con ..", async () => {
		const antes = await hashTree(origen);
		await expectValidacion(
			initFromSource(opts(join(origen, "sub", "..", "sub"))),
		);
		if (process.platform === "win32") {
			await expectValidacion(initFromSource(opts(origen.toUpperCase())));
		}
		expect(await hashTree(origen)).toBe(antes);
	});

	it("CLI-001 mensaje y acción en inglés con lang en", async () => {
		const err = await expectValidacion(
			initFromSource(opts(origen, { lang: "en" })),
		);
		expect(err.message).toMatch(/inside the source/i);
		expect(err.accion).toContain("--dest");
	});

	it("CLI-001 un destino hermano del origen sigue funcionando", async () => {
		const r = await initFromSource(opts(join(base, "hermano")));
		expect(r.workspace.raiz).toBe(join(base, "hermano", ".mct"));
		expect(await readFile(join(base, "hermano", ".gitignore"), "utf8")).toBe(
			".mct/\n",
		);
	});

	it("CLI-001 origen .json con su carpeta como destino es válido y no modifica el archivo", async () => {
		const carpeta = join(base, "wf");
		await mkdir(carpeta, { recursive: true });
		const archivo = join(carpeta, "flow.json");
		await writeFile(archivo, workflow);
		const antes = await readFile(archivo, "utf8");
		const r = await initFromSource({
			...opts(carpeta),
			origen: archivo,
		});
		expect(r.adapter).toBe("n8n");
		expect(await readFile(archivo, "utf8")).toBe(antes);
	});
});
