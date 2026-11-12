import { createHash } from "node:crypto";
import {
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
import { afterEach, describe, expect, it } from "vitest";
import { findingId, leerClave } from "../src/finding-id.js";
import type { Runner } from "../src/gitleaks.js";
import { scan } from "../src/scan.js";
import { CLAVE_PRUEBA } from "./clave.js";

const cleanups: string[] = [];
afterEach(async () => {
	for (const d of cleanups.splice(0)) {
		await rm(d, { recursive: true, force: true });
	}
});

const VALOR = ["valor", "-de-", "prueba", "-", "k3m9x2q7"].join("");
const entrada = {
	motor: "mct",
	regla: "high-entropy",
	archivo: "src/a.ts",
	linea: 3,
	value: VALOR,
} as const;

const sha = (t: string) => createHash("sha256").update(t, "utf8").digest("hex");

const runnerVacio: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

/** Un workspace: raiz con `clave`, `work/` y un archivo con un secreto. */
async function workspace(clave: Buffer | null) {
	const raiz = await mkdtemp(join(tmpdir(), "mct-hmac-"));
	cleanups.push(raiz);
	await mkdir(join(raiz, "work"), { recursive: true });
	await mkdir(join(raiz, "tmp"), { recursive: true });
	if (clave !== null) await writeFile(join(raiz, "clave"), clave);
	const token = [
		"gh",
		"p_",
		"A1b2C3d4E5f6G7h8I9j0",
		"K1l2M3n4O5p6Q7r8S9t0",
	].join("");
	await writeFile(join(raiz, "work", "a.txt"), `token = ${token}\n`);
	return raiz;
}

function escanear(raiz: string) {
	return scan({
		work: join(raiz, "work"),
		quarantine: join(raiz, "quarantine"),
		gitleaks: {
			binary: process.execPath,
			installDir: join(raiz, "bin"),
			tmpDir: join(raiz, "tmp"),
			run: runnerVacio,
		},
	});
}

describe("SCAN-015 ids con HMAC", () => {
	it("SCAN-015 el id es HMAC: no coincide con el SHA256 sin clave", () => {
		const id = findingId(entrada, CLAVE_PRUEBA);
		const sinClave = sha(
			[
				entrada.motor,
				entrada.regla,
				entrada.archivo,
				String(entrada.linea),
				sha(entrada.value),
			].join("\n"),
		);
		expect(id).toMatch(/^[0-9a-f]{64}$/);
		expect(id).not.toBe(sinClave);
	});

	it("SCAN-015 calcular el id con otra clave da un valor distinto del id guardado", () => {
		const guardado = findingId(entrada, CLAVE_PRUEBA);
		expect(findingId(entrada, Buffer.alloc(32, 9))).not.toBe(guardado);
		expect(findingId(entrada, CLAVE_PRUEBA)).toBe(guardado);
	});

	it("SCAN-015 una clave que no mide 32 bytes se rechaza", () => {
		expect(() => findingId(entrada, Buffer.alloc(16, 1))).toThrow(MctError);
	});

	it("SCAN-015 dos workspaces con el mismo contenido dan ids distintos", async () => {
		const a = await escanear(await workspace(Buffer.alloc(32, 1)));
		const b = await escanear(await workspace(Buffer.alloc(32, 2)));
		expect(a.hallazgos.length).toBeGreaterThan(0);
		expect(a.hallazgos).toHaveLength(b.hallazgos.length);
		const ids = new Set(a.hallazgos.map((h) => h.id));
		expect(b.hallazgos.some((h) => ids.has(h.id))).toBe(false);
	});

	it("SCAN-015 el mismo workspace da los mismos ids entre re-scans", async () => {
		const raiz = await workspace(Buffer.alloc(32, 3));
		const a = await escanear(raiz);
		const b = await escanear(raiz);
		expect(b.hallazgos.map((h) => h.id)).toEqual(a.hallazgos.map((h) => h.id));
	});

	it("SCAN-015 rotar la clave (init --force) cambia los ids", async () => {
		const raiz = await workspace(Buffer.alloc(32, 4));
		const antes = await escanear(raiz);
		await writeFile(join(raiz, "clave"), Buffer.alloc(32, 5));
		const despues = await escanear(raiz);
		const ids = new Set(antes.hallazgos.map((h) => h.id));
		expect(despues.hallazgos.some((h) => ids.has(h.id))).toBe(false);
	});

	it("SCAN-015 un workspace sin clave sale con WORKSPACE_INVALIDO y la acción mct init --force", async () => {
		const raiz = await workspace(null);
		const error = await escanear(raiz).then(
			() => null,
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(MctError);
		expect(error).toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
			accion: "mct init --force",
		});
		await expect(leerClave(raiz)).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
		});
	});

	it("SCAN-015 una clave de tamaño erróneo en el workspace también es WORKSPACE_INVALIDO", async () => {
		const raiz = await workspace(Buffer.alloc(8, 1));
		await expect(escanear(raiz)).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
		});
	});

	it("SCAN-015 la clave no aparece en el resultado del scan ni se escribe en work/", async () => {
		const clave = Buffer.alloc(32, 6);
		const raiz = await workspace(clave);
		const r = await escanear(raiz);
		const texto = JSON.stringify(r);
		expect(texto).not.toContain(clave.toString("hex"));
		expect(texto).not.toContain(clave.toString("base64"));
		expect(await readdir(join(raiz, "work"))).toEqual(["a.txt"]);
		expect((await readFile(join(raiz, "work", "a.txt"))).includes(clave)).toBe(
			false,
		);
	});
});
