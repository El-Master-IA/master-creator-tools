import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { leerArchivoDecisiones } from "../src/decisiones.js";

const ID = "a".repeat(64);
const CONTENIDO = JSON.stringify({
	schemaVersion: 1,
	decisiones: [{ id: ID, accion: "reemplazar" }],
});

let base: string;
let origen: string;
let dest: string;
let raiz: string;

async function crear(ruta: string, modo = 0o600): Promise<string> {
	await mkdir(join(ruta, ".."), { recursive: true });
	await writeFile(ruta, CONTENIDO, { mode: modo });
	await chmod(ruta, modo);
	return ruta;
}

const leer = (ruta: string, tipo = "carpeta") =>
	leerArchivoDecisiones(ruta, { raiz, origen: { tipo, ref: origen } });

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-san015-"));
	origen = join(base, "origen");
	dest = origen;
	raiz = join(dest, ".mct");
	for (const d of ["work", "dist", "quarantine", "tmp"]) {
		await mkdir(join(raiz, d), { recursive: true });
	}
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("ubicacion y permisos del archivo de decisiones (SAN-015)", () => {
	it("SAN-015 <dest>/decisiones.json con destino = origen es la ubicacion recomendada", async () => {
		const ruta = await crear(join(dest, "decisiones.json"));
		const r = await leer(ruta);
		expect(r.entradas).toHaveLength(1);
		expect(r.sha256).toMatch(/^[0-9a-f]{64}$/);
	});

	it("SAN-015 un archivo fuera del origen y de .mct es valido", async () => {
		const ruta = await crear(join(base, "otro", "mis-decisiones.json"));
		await expect(leer(ruta)).resolves.toMatchObject({ entradas: [{ id: ID }] });
	});

	it.each([
		["work", join("work", "decisiones.json")],
		["dist", join("dist", "decisiones.json")],
		["quarantine", join("quarantine", "decisiones.json")],
		["tmp de .mct", join("tmp", "decisiones.json")],
	])("SAN-015 dentro de %s sale con VALIDACION", async (_n, rel) => {
		const ruta = await crear(join(raiz, rel));
		await expect(leer(ruta)).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-015 dentro del origen (fuera de la raiz) sale con VALIDACION", async () => {
		const ruta = await crear(join(origen, "src", "decisiones.json"));
		await expect(leer(ruta)).rejects.toMatchObject({ codigo: "VALIDACION" });
		const otro = await crear(join(origen, "mis-decisiones.json"));
		await expect(leer(otro)).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-015 con destino distinto del origen, <origen>/decisiones.json sale con VALIDACION", async () => {
		const otroDest = join(base, "dest");
		const otraRaiz = join(otroDest, ".mct");
		await mkdir(otraRaiz, { recursive: true });
		const ruta = await crear(join(origen, "decisiones.json"));
		await expect(
			leerArchivoDecisiones(ruta, {
				raiz: otraRaiz,
				origen: { tipo: "carpeta", ref: origen },
			}),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it.skipIf(process.platform === "win32")(
		"SAN-015 en POSIX con modo 0644 sale con VALIDACION",
		async () => {
			const ruta = await crear(join(dest, "decisiones.json"), 0o644);
			await expect(leer(ruta)).rejects.toMatchObject({ codigo: "VALIDACION" });
			await chmod(ruta, 0o400);
			await expect(leer(ruta)).resolves.toBeDefined();
		},
	);
});
