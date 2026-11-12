import {
	chmod,
	lstat,
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
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashTree } from "../src/hash.js";
import { initFromSource } from "../src/init.js";

let base: string;
let origen: string;
let dest: string;

// Fixtures are built from fragments so no secret-looking literal lives in the repo.
const envLine = `${["DB", "PASS"].join("_")}=${"x".repeat(4)}\n`;
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

async function put(root: string, rel: string, text: string): Promise<void> {
	const full = join(root, ...rel.split("/"));
	await mkdir(join(full, ".."), { recursive: true });
	await writeFile(full, text);
}

async function list(root: string, rel = ""): Promise<string[]> {
	const out: string[] = [];
	for (const e of await readdir(join(root, rel), { withFileTypes: true })) {
		const child = rel === "" ? e.name : `${rel}/${e.name}`;
		if (e.isDirectory()) out.push(...(await list(root, child)));
		else out.push(child);
	}
	return out.sort();
}

const exists = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

function opts(extra: Record<string, unknown> = {}) {
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

async function expectCode(p: Promise<unknown>, codigo: string) {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	expect((err as MctError).codigo).toBe(codigo);
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t17-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	await mkdir(origen, { recursive: true });
	await mkdir(dest, { recursive: true });
	await put(origen, "package.json", pkg);
	await put(origen, "src/index.js", "export const uno = 1;\n");
	await put(origen, "src/app.log", "log\n");
	await put(origen, ".git/config", "[core]\n");
	await put(origen, "node_modules/x/index.js", "x\n");
	await put(origen, ".mct/state.json", "{}\n");
	await put(origen, "mct.config.json", "{}\n");
	await put(origen, "sub/mct.config.json", "{}\n");
	await put(origen, ".env", envLine);
	await put(origen, ".env.local", envLine);
	await put(origen, "sub/deep/.npmrc", envLine);
	await put(origen, "sub/.ENV.prod", envLine);
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-001 copia a work y quarantine", () => {
	it("CLI-001 deja el hash del origen igual y separa work de quarantine", async () => {
		const antes = await hashTree(origen);
		const r = await initFromSource(opts());
		expect(await hashTree(origen)).toBe(antes);
		expect(await list(r.workspace.work)).toEqual([
			"package.json",
			"src/app.log",
			"src/index.js",
			"sub/mct.config.json",
		]);
		expect(await list(r.workspace.quarantine)).toEqual([
			".env",
			".env.local",
			"sub/.ENV.prod",
			"sub/deep/.npmrc",
		]);
		expect(await readFile(join(r.workspace.quarantine, ".env"), "utf8")).toBe(
			envLine,
		);
		expect(r.adapter).toBe("node");
		expect(r.confianza).toBeGreaterThan(0);
		expect(r.archivos).toBe(4);
		const st = await r.workspace.estado();
		expect(st.origen.tipo).toBe("carpeta");
		expect(st.etapas.init.estado).toBe("ok");
		expect(st.workSha256).toBe(await hashTree(r.workspace.work));
	});

	it("CLI-001 aplica los globs exclude de mct.config.json de dest", async () => {
		await put(
			dest,
			"mct.config.json",
			JSON.stringify({ exclude: ["**/*.log", "{docs,tmp}"] }),
		);
		await put(origen, "docs/a.md", "a\n");
		await put(origen, "tmp/b.txt", "b\n");
		const r = await initFromSource(opts());
		const work = await list(r.workspace.work);
		expect(work).not.toContain("src/app.log");
		expect(
			work.some((f) => f.startsWith("docs/") || f.startsWith("tmp/")),
		).toBe(false);
		expect(work).toContain("src/index.js");
	});

	it("CLI-001 trata un .json de n8n según su forma real", async () => {
		const file = join(base, "flow.json");
		await writeFile(file, workflow);
		const r = await initFromSource(opts({ origen: file }));
		expect(r.adapter).toBe("n8n");
		expect((await r.workspace.estado()).origen.tipo).toBe("n8n-json");
		expect(await list(r.workspace.work)).toEqual(["flow.json"]);
	});

	it("CLI-001 un .json que no es un export de n8n sale con VALIDACION sin dejar workspace", async () => {
		const file = join(base, "otro.json");
		await writeFile(file, JSON.stringify({ hola: "mundo" }));
		await expectCode(initFromSource(opts({ origen: file })), "VALIDACION");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-001 una carpeta con exports de n8n detecta el adaptador n8n", async () => {
		const o2 = join(base, "flows");
		await put(o2, "a.json", workflow);
		const r = await initFromSource(opts({ origen: o2 }));
		expect(r.adapter).toBe("n8n");
		expect((await r.workspace.estado()).origen.tipo).toBe("carpeta");
	});

	it("CLI-001 --type distinto de lo detectado sale con VALIDACION", async () => {
		await expectCode(initFromSource(opts({ type: "n8n" })), "VALIDACION");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-001 un origen vacío o solo con quarantine sale con VALIDACION", async () => {
		const vacio = join(base, "vacio");
		await mkdir(vacio);
		await put(vacio, ".env", envLine);
		await expectCode(initFromSource(opts({ origen: vacio })), "VALIDACION");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-001 un origen inexistente sale con ORIGEN_NO_ENCONTRADO", async () => {
		await expectCode(
			initFromSource(opts({ origen: join(base, "nada") })),
			"ORIGEN_NO_ENCONTRADO",
		);
	});

	it("CLI-001 agrega .mct/ al .gitignore del destino una sola vez", async () => {
		await put(dest, ".gitignore", "dist\n");
		await initFromSource(opts());
		await rm(join(dest, ".mct"), { recursive: true, force: true });
		await initFromSource(opts());
		expect(await readFile(join(dest, ".gitignore"), "utf8")).toBe(
			"dist\n.mct/\n",
		);
	});

	it("CLI-001 crea el .gitignore si no existe", async () => {
		await initFromSource(opts());
		expect(await readFile(join(dest, ".gitignore"), "utf8")).toBe(".mct/\n");
	});

	it("CLI-001 --dest se crea si no existe", async () => {
		const nuevo = join(base, "nuevo", "dest");
		const r = await initFromSource(opts({ dest: nuevo }));
		expect(r.workspace.raiz).toBe(join(nuevo, ".mct"));
	});
});

describe("CLI-001 workspace existente", () => {
	it("CLI-001 sin --force sale con VALIDACION sin tocar el workspace", async () => {
		await initFromSource(opts());
		const antes = await hashTree(join(dest, ".mct"));
		await put(origen, "extra.txt", "nuevo\n");
		await expectCode(initFromSource(opts()), "VALIDACION");
		expect(await hashTree(join(dest, ".mct"))).toBe(antes);
	});

	it("CLI-008 --force sin TTY sale con CANCELADO y no toca nada", async () => {
		await initFromSource(opts());
		const antes = await hashTree(join(dest, ".mct"));
		await expectCode(initFromSource(opts({ force: true })), "CANCELADO");
		expect(await hashTree(join(dest, ".mct"))).toBe(antes);
	});

	it("CLI-008 solo true confirma --force", async () => {
		await initFromSource(opts());
		const antes = await hashTree(join(dest, ".mct"));
		for (const respuesta of [Symbol("cancel"), "si", 1, undefined]) {
			await expectCode(
				initFromSource(
					opts({
						force: true,
						isTTY: true,
						confirmarForce: async () => respuesta,
					}),
				),
				"CANCELADO",
			);
		}
		expect(await hashTree(join(dest, ".mct"))).toBe(antes);
	});

	it("CLI-008 --force confirmado recrea desde cero y lista lo que se pierde", async () => {
		await initFromSource(opts());
		await put(dest, ".mct/dist/x.txt", "x\n");
		await put(dest, ".mct/approval.json", "{}\n");
		let perdidas: string[] = [];
		const r = await initFromSource(
			opts({
				force: true,
				isTTY: true,
				confirmarForce: async (info: { perdidas: string[] }) => {
					perdidas = info.perdidas;
					return true;
				},
			}),
		);
		expect(perdidas).toEqual(expect.arrayContaining(["dist", "approval.json"]));
		expect(await exists(join(dest, ".mct", "dist", "x.txt"))).toBe(false);
		expect((await r.workspace.estado()).etapas.init.estado).toBe("ok");
	});

	it("CLI-008 no toca mct.config.json de dest al recrear", async () => {
		await put(dest, "mct.config.json", JSON.stringify({ holder: "Ana" }));
		await initFromSource(opts());
		await initFromSource(
			opts({ force: true, isTTY: true, confirmarForce: async () => true }),
		);
		expect(await readFile(join(dest, "mct.config.json"), "utf8")).toBe(
			JSON.stringify({ holder: "Ana" }),
		);
	});
});

describe("CLI-006 y SEC-001 avisos de T41", () => {
	it("CLI-006 destino sincronizado sin TTY sale con CANCELADO sin copiar", async () => {
		await expectCode(
			initFromSource(opts({ env: { OneDrive: base } })),
			"CANCELADO",
		);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-006 destino sincronizado con confirmación true continúa", async () => {
		const r = await initFromSource(
			opts({
				env: { OneDrive: base },
				isTTY: true,
				confirmar: async () => true,
			}),
		);
		expect(r.archivos).toBeGreaterThan(0);
	});

	it("CLI-006 solo true confirma la carpeta sincronizada", async () => {
		await expectCode(
			initFromSource(
				opts({
					env: { OneDrive: base },
					isTTY: true,
					confirmar: async () => Symbol("cancel"),
				}),
			),
			"CANCELADO",
		);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("SEC-001 sin diccionario no hay avisos", async () => {
		await put(dest, "mct.config.json", "{}\n");
		const r = await initFromSource(opts());
		expect(r.avisos).toEqual([]);
	});

	it.skipIf(process.platform === "win32")(
		"SEC-001 diccionario con permisos abiertos avisa con la acción",
		async () => {
			const home = join(base, "home");
			await mkdir(join(home, ".mct"), { recursive: true });
			const dic = join(home, ".mct", "sensible.txt");
			await writeFile(dic, "x\n");
			await chmod(dic, 0o644);
			const r = await initFromSource(opts());
			expect(r.avisos).toHaveLength(1);
			expect(r.avisos[0]?.accion).toContain("chmod 600");
		},
	);
});

describe("CFG-002 config del origen cuando el destino no tiene", () => {
	it("CFG-002 usa los exclude del mct.config.json del origen y lo copia al destino", async () => {
		const cfg = JSON.stringify({ exclude: ["src/app.log"] });
		await put(origen, "mct.config.json", cfg);
		const antes = await hashTree(origen);
		const r = await initFromSource(opts());
		expect(await list(r.workspace.work)).not.toContain("src/app.log");
		expect(
			JSON.parse(await readFile(join(dest, "mct.config.json"), "utf8")),
		).toEqual(JSON.parse(cfg));
		expect(r.avisos.some((a) => a.mensaje.includes("mct.config.json"))).toBe(
			true,
		);
		expect(await hashTree(origen)).toBe(antes);
	});

	it("CFG-002 si el destino ya tiene config, manda la del destino y no la pisa", async () => {
		await put(
			origen,
			"mct.config.json",
			JSON.stringify({ exclude: ["src/app.log"] }),
		);
		await put(dest, "mct.config.json", "{}\n");
		const r = await initFromSource(opts());
		expect(await list(r.workspace.work)).toContain("src/app.log");
		expect(await readFile(join(dest, "mct.config.json"), "utf8")).toBe("{}\n");
	});

	it("CFG-002 una config inválida en el origen falla con VALIDACION sin copiar nada", async () => {
		await put(origen, "mct.config.json", "{ no json");
		const err = await initFromSource(opts()).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("VALIDACION");
		await expect(lstat(join(dest, "mct.config.json"))).rejects.toThrow();
	});
});
