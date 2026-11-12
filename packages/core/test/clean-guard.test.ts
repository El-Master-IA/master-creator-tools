import { mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanWorkspace } from "../src/clean.js";
import { createWorkspace } from "../src/workspace.js";

let base: string;
let raiz: string;

const init = {
	mctVersion: "0.0.0",
	origen: { tipo: "carpeta" as const, ref: "origen" },
	adapter: "node",
};

const exists = (p: string) =>
	stat(p).then(
		() => true,
		() => false,
	);

async function codigo(p: Promise<unknown>): Promise<string> {
	try {
		await p;
	} catch (e) {
		if (e instanceof MctError) return e.codigo;
		throw e;
	}
	return "sin-error";
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t25-"));
	raiz = join(base, ".mct");
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLN-001 guard", () => {
	it("CLN-001 sin state.json sale con WORKSPACE_INVALIDO y no borra nada", async () => {
		await mkdir(join(raiz, "work"), { recursive: true });
		await writeFile(join(raiz, "work", "a.txt"), "x");
		expect(
			await codigo(cleanWorkspace({ raiz, force: true, isTTY: false })),
		).toBe("WORKSPACE_INVALIDO");
		expect(await exists(join(raiz, "work", "a.txt"))).toBe(true);
	});

	it("CLN-001 state.json corrupto sale con WORKSPACE_INVALIDO y no borra nada", async () => {
		await mkdir(raiz, { recursive: true });
		await writeFile(join(raiz, "state.json"), "{no es json");
		await writeFile(join(raiz, "otro.txt"), "x");
		expect(
			await codigo(cleanWorkspace({ raiz, force: true, isTTY: true })),
		).toBe("WORKSPACE_INVALIDO");
		expect(await exists(join(raiz, "otro.txt"))).toBe(true);
	});

	it("CLN-001 un directorio ya borrado sale con WORKSPACE_INVALIDO", async () => {
		expect(
			await codigo(cleanWorkspace({ raiz, force: true, isTTY: false })),
		).toBe("WORKSPACE_INVALIDO");
	});

	it("CLN-001 sin state.json y sin TTY gana WORKSPACE_INVALIDO sobre CANCELADO", async () => {
		await mkdir(raiz, { recursive: true });
		expect(
			await codigo(cleanWorkspace({ raiz, force: false, isTTY: false })),
		).toBe("WORKSPACE_INVALIDO");
	});

	it("CLN-001 rechaza un workspace que es un enlace", async () => {
		const real = join(base, "real");
		await createWorkspace(real, init);
		try {
			await symlink(real, raiz, "junction");
		} catch {
			return;
		}
		expect(
			await codigo(cleanWorkspace({ raiz, force: true, isTTY: false })),
		).toBe("WORKSPACE_INVALIDO");
		expect(await exists(join(real, "state.json"))).toBe(true);
	});

	it("CLN-001 rechaza un enlace dentro del workspace sin borrar nada", async () => {
		await createWorkspace(raiz, init);
		const fuera = join(base, "fuera");
		await mkdir(fuera);
		await writeFile(join(fuera, "f.txt"), "x");
		try {
			await symlink(fuera, join(raiz, "work", "enlace"), "junction");
		} catch {
			return;
		}
		expect(
			await codigo(cleanWorkspace({ raiz, force: true, isTTY: false })),
		).toBe("WORKSPACE_INVALIDO");
		expect(await exists(join(fuera, "f.txt"))).toBe(true);
		expect(await exists(join(raiz, "state.json"))).toBe(true);
	});

	it("CLN-001 sin TTY y sin --force sale con CANCELADO sin borrar", async () => {
		await createWorkspace(raiz, init);
		expect(
			await codigo(cleanWorkspace({ raiz, force: false, isTTY: false })),
		).toBe("CANCELADO");
		expect(await exists(join(raiz, "state.json"))).toBe(true);
	});

	it("CLN-001 con TTY solo un true literal confirma", async () => {
		await createWorkspace(raiz, init);
		for (const respuesta of [false, Symbol("cancel"), "si", undefined]) {
			expect(
				await codigo(
					cleanWorkspace({
						raiz,
						force: false,
						isTTY: true,
						confirmar: async () => respuesta as unknown as boolean,
					}),
				),
			).toBe("CANCELADO");
		}
		expect(await exists(join(raiz, "state.json"))).toBe(true);
		const r = await cleanWorkspace({
			raiz,
			force: false,
			isTTY: true,
			confirmar: async () => true,
		});
		expect(r.borrado).toBe(raiz);
		expect(await exists(raiz)).toBe(false);
	});

	it("CLN-001 con TTY sin confirmar cancela, y confirmar recibe la ruta y el conteo", async () => {
		await createWorkspace(raiz, init);
		expect(
			await codigo(cleanWorkspace({ raiz, force: false, isTTY: true })),
		).toBe("CANCELADO");
		let visto: { ruta: string; archivos: number } | undefined;
		await cleanWorkspace({
			raiz,
			force: false,
			isTTY: true,
			confirmar: async (info) => {
				visto = info;
				return true;
			},
		});
		expect(visto?.ruta).toBe(raiz);
		expect(visto?.archivos).toBe(1);
	});

	it("CLN-001 --force borra sin TTY y no toca mct.config.json", async () => {
		await createWorkspace(raiz, init);
		const cfg = join(base, "mct.config.json");
		await writeFile(cfg, "{}\n");
		const r = await cleanWorkspace({ raiz, force: true, isTTY: false });
		expect(r).toEqual({ borrado: raiz, archivos: 1 });
		expect(await exists(raiz)).toBe(false);
		expect(await exists(cfg)).toBe(true);
	});
});
