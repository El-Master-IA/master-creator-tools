import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanWorkspace } from "../src/clean.js";
import { createWorkspace } from "../src/workspace.js";

let dest: string;
let raiz: string;

beforeEach(async () => {
	dest = await mkdtemp(join(tmpdir(), "mct-clean-dec-"));
	raiz = join(dest, ".mct");
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: dest },
		adapter: "node",
	});
	await writeFile(join(dest, "decisiones.json"), "{}");
	await writeFile(join(dest, "mct.config.json"), "{}");
});

afterEach(async () => {
	await rm(dest, { recursive: true, force: true });
});

describe("clean borra decisiones.json (SAN-015)", () => {
	it("SAN-015 con --force borra el workspace y <dest>/decisiones.json, y no toca mct.config.json", async () => {
		await cleanWorkspace({ raiz, force: true, isTTY: false });
		await expect(access(raiz)).rejects.toThrow();
		await expect(access(join(dest, "decisiones.json"))).rejects.toThrow();
		await access(join(dest, "mct.config.json"));
	});

	it("SAN-015 tras la confirmacion borra tambien decisiones.json", async () => {
		await cleanWorkspace({
			raiz,
			force: false,
			isTTY: true,
			confirmar: async () => true,
		});
		await expect(access(join(dest, "decisiones.json"))).rejects.toThrow();
	});

	it("SAN-015 si la persona no confirma no se borra nada, tampoco decisiones.json", async () => {
		await expect(
			cleanWorkspace({
				raiz,
				force: false,
				isTTY: true,
				confirmar: async () => false,
			}),
		).rejects.toMatchObject({ codigo: "CANCELADO" });
		await access(join(dest, "decisiones.json"));
		await access(raiz);
	});

	it("SAN-015 sin decisiones.json clean funciona igual", async () => {
		await rm(join(dest, "decisiones.json"));
		await cleanWorkspace({ raiz, force: true, isTTY: false });
		await access(join(dest, "mct.config.json"));
	});

	it("SAN-015 una carpeta llamada decisiones.json no se borra", async () => {
		await rm(join(dest, "decisiones.json"));
		await mkdir(join(dest, "decisiones.json"));
		await cleanWorkspace({ raiz, force: true, isTTY: false });
		await access(join(dest, "decisiones.json"));
	});
});
