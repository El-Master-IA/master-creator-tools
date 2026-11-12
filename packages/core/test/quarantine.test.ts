import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanWorkspace } from "../src/clean.js";
import { createWorkspace, readState } from "../src/workspace.js";

vi.mock("node:fs/promises", async (orig) => {
	const actual = await orig<typeof import("node:fs/promises")>();
	return { ...actual, rm: vi.fn(actual.rm) };
});

let base: string;
let raiz: string;

const exists = (p: string) =>
	stat(p).then(
		() => true,
		() => false,
	);

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t25q-"));
	raiz = join(base, ".mct");
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("SAN-005 clean borra la cuarentena", () => {
	it("SAN-005 clean borra quarantine/ con su contenido y el resto del workspace", async () => {
		const ws = await createWorkspace(raiz, {
			mctVersion: "0.0.0",
			origen: { tipo: "carpeta", ref: "origen" },
			adapter: "node",
		});
		await mkdir(join(ws.quarantine, "sub"), { recursive: true });
		await writeFile(join(ws.quarantine, "sub", "q.env"), "contenido");
		await writeFile(join(ws.work, "w.txt"), "w");
		await writeFile(join(ws.dist, "d.txt"), "d");
		const cfg = join(base, "mct.config.json");
		await writeFile(cfg, "{}\n");

		const r = await cleanWorkspace({ raiz, force: true, isTTY: false });

		expect(r.archivos).toBe(4);
		expect(await exists(ws.quarantine)).toBe(false);
		expect(await exists(ws.work)).toBe(false);
		expect(await exists(ws.dist)).toBe(false);
		expect(await exists(raiz)).toBe(false);
		expect(await exists(cfg)).toBe(true);
	});
});

describe("SAN-005 borrado reintentable", () => {
	it("SAN-005 si quarantine/ no se puede borrar, state.json sigue y el reintento termina", async () => {
		const ws = await createWorkspace(raiz, {
			mctVersion: "0.0.0",
			origen: { tipo: "carpeta", ref: "origen" },
			adapter: "node",
		});
		await writeFile(join(ws.quarantine, "q.env"), "contenido");
		await writeFile(join(ws.work, "w.txt"), "w");

		const real = (
			await vi.importActual<typeof import("node:fs/promises")>(
				"node:fs/promises",
			)
		).rm;
		const mocked = vi.mocked(rm);
		mocked.mockImplementation(async (path, opts) => {
			if (String(path) === ws.quarantine) {
				throw Object.assign(new Error("busy"), { code: "EBUSY" });
			}
			return real(path, opts);
		});

		const fallo = await cleanWorkspace({
			raiz,
			force: true,
			isTTY: false,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect((fallo as { codigo?: string }).codigo).toBe("INTERNO");
		expect((fallo as { accion?: string }).accion).toBeTruthy();
		expect(await exists(join(ws.quarantine, "q.env"))).toBe(true);
		expect(await readState(raiz)).toBeDefined();

		mocked.mockImplementation(real);
		const r = await cleanWorkspace({ raiz, force: true, isTTY: false });
		expect(r.borrado).toBe(raiz);
		expect(await exists(raiz)).toBe(false);
	});
});
