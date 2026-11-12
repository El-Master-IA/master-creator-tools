import { existsSync, readFileSync, renameSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { initFromSource } from "../src/init.js";

let base: string;
let origen: string;
let dest: string;

/** Reports "aborted" from its n-th read on, so every checkpoint can be hit. */
function abortAfter(reads: number, onRead?: () => void): AbortSignal {
	let seen = 0;
	return {
		get aborted() {
			onRead?.();
			seen += 1;
			return seen > reads;
		},
		addEventListener() {},
		removeEventListener() {},
	} as unknown as AbortSignal;
}

const opts = (signal: AbortSignal) => ({
	origen,
	dest,
	isTTY: true,
	mctVersion: "0.0.0",
	home: base,
	env: {},
	signal,
});

async function codeOf(work: Promise<unknown>): Promise<string> {
	try {
		await work;
		return "OK";
	} catch (e) {
		return e instanceof MctError ? e.codigo : "OTRO";
	}
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-interrupt-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(dest);
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "demo", version: "1.0.0" }),
	);
	await writeFile(join(origen, ".env"), "A=1\n");
	await writeFile(join(origen, "src", "a.js"), "export const a = 1;\n");
	await writeFile(join(origen, "src", "b.js"), "export const b = 2;\n");
	await writeFile(join(dest, ".gitignore"), "dist\n");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("Ctrl+C durante init", () => {
	it("CLI-001 en cada punto de corte deja el destino como estaba", async () => {
		let interrupted = 0;
		let completed = false;
		for (let reads = 0; reads < 60 && !completed; reads += 1) {
			const code = await codeOf(initFromSource(opts(abortAfter(reads))));
			if (code === "OK") {
				completed = true;
				break;
			}
			expect(code).toBe("INTERRUMPIDO");
			interrupted += 1;
			expect(existsSync(join(dest, ".mct"))).toBe(false);
			expect(await readFile(join(dest, ".gitignore"), "utf8")).toBe("dist\n");
		}
		expect(completed).toBe(true);
		expect(interrupted).toBeGreaterThanOrEqual(6);
	});

	it("CLI-001 ignora .mct/ antes de copiar la cuarentena", async () => {
		let gitignoreAlCopiar: string | undefined;
		const envCopiado = join(dest, ".mct", "quarantine", ".env");
		const signal = abortAfter(1000, () => {
			if (gitignoreAlCopiar === undefined && existsSync(envCopiado)) {
				gitignoreAlCopiar = readFileSync(join(dest, ".gitignore"), "utf8");
			}
		});
		expect(await codeOf(initFromSource(opts(signal)))).toBe("OK");
		expect(gitignoreAlCopiar).toBe("dist\n.mct/\n");
	});

	it("CLI-001 sin .gitignore previo la interrupción no deja uno nuevo", async () => {
		await rm(join(dest, ".gitignore"));
		expect(await codeOf(initFromSource(opts(abortAfter(3))))).toBe(
			"INTERRUMPIDO",
		);
		expect(existsSync(join(dest, ".gitignore"))).toBe(false);
	});

	it("CLI-001 interrumpir al confirmar --force conserva el workspace previo", async () => {
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe("OK");
		const marca = join(dest, ".mct", "work", "marca.txt");
		await writeFile(marca, "previo");
		const controller = new AbortController();
		const code = await codeOf(
			initFromSource({
				...opts(controller.signal),
				force: true,
				confirmarForce: async () => {
					controller.abort();
					return true;
				},
			}),
		);
		expect(code).toBe("INTERRUMPIDO");
		expect(await readFile(marca, "utf8")).toBe("previo");
	});

	it("CLI-008 --force interrumpido en cualquier punto restaura el workspace previo", async () => {
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe("OK");
		const marca = join(dest, ".mct", "work", "marca.txt");
		await writeFile(marca, "previo");
		const gitignore = await readFile(join(dest, ".gitignore"), "utf8");
		let interrupted = 0;
		for (let reads = 0; reads < 60; reads += 1) {
			const code = await codeOf(
				initFromSource({
					...opts(abortAfter(reads)),
					force: true,
					confirmarForce: async () => true,
				}),
			);
			if (code === "OK") break;
			expect(code).toBe("INTERRUMPIDO");
			interrupted += 1;
			expect(await readFile(marca, "utf8")).toBe("previo");
			expect(existsSync(join(dest, ".mct.previo"))).toBe(false);
			expect(await readFile(join(dest, ".gitignore"), "utf8")).toBe(gitignore);
		}
		expect(interrupted).toBeGreaterThanOrEqual(6);
		expect(existsSync(marca)).toBe(false);
		expect(existsSync(join(dest, ".mct.previo"))).toBe(false);
		expect(await readFile(join(dest, ".gitignore"), "utf8")).toBe(gitignore);
	});

	it("CLI-008 --force que falla sin Ctrl+C también restaura el workspace previo", async () => {
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe("OK");
		const marca = join(dest, ".mct", "work", "marca.txt");
		await writeFile(marca, "previo");
		let confirmado = false;
		const code = await codeOf(
			initFromSource({
				...opts(abortAfter(1000)),
				force: true,
				type: "n8n",
				confirmarForce: async () => {
					confirmado = true;
					return true;
				},
			}),
		);
		expect(code).toBe("VALIDACION");
		expect(confirmado).toBe(true);
		expect(await readFile(marca, "utf8")).toBe("previo");
		expect(existsSync(join(dest, ".mct.previo"))).toBe(false);
	});

	it("CLI-008 si no puede restaurar conserva el código y avisa del residuo", async () => {
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe("OK");
		const previo = join(dest, ".mct.previo");
		const apartado = join(base, "apartado");
		// Takes the backup away mid-run, so the restore step cannot succeed.
		const signal = abortAfter(4, () => {
			if (existsSync(previo)) renameSync(previo, apartado);
		});
		let error: unknown;
		try {
			await initFromSource({
				...opts(signal),
				force: true,
				confirmarForce: async () => true,
			});
		} catch (e) {
			error = e;
		}
		expect(error).toBeInstanceOf(MctError);
		const mct = error as MctError;
		expect(mct.codigo).toBe("INTERRUMPIDO");
		expect(mct.message).toContain(".mct.previo");
		expect(mct.detalle).toEqual({ residuo: true });
		expect(await readFile(join(dest, ".gitignore"), "utf8")).toContain(
			".mct.previo/",
		);
	});

	it("CLI-008 no crea un workspace encima de un respaldo huérfano", async () => {
		await mkdir(join(dest, ".mct.previo"));
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe(
			"VALIDACION",
		);
		expect(existsSync(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-008 un respaldo .mct.previo pendiente no se pisa", async () => {
		expect(await codeOf(initFromSource(opts(abortAfter(1000))))).toBe("OK");
		await mkdir(join(dest, ".mct.previo"));
		await writeFile(join(dest, ".mct.previo", "x"), "guardado");
		const code = await codeOf(
			initFromSource({
				...opts(abortAfter(1000)),
				force: true,
				confirmarForce: async () => true,
			}),
		);
		expect(code).toBe("VALIDACION");
		expect(await readFile(join(dest, ".mct.previo", "x"), "utf8")).toBe(
			"guardado",
		);
	});

	it("CLI-009 interrumpir el clon detiene git y no deja workspace", async () => {
		const controller = new AbortController();
		let killed = false;
		const run: Runner = (_file, _args, runOptions) =>
			new Promise((done) => {
				runOptions.signal.addEventListener("abort", () => {
					killed = true;
					done({ code: 1, stdout: "", stderr: "" });
				});
				controller.abort();
			});
		const code = await codeOf(
			initFromSource({
				...opts(controller.signal),
				origen: "https://github.com/acme/demo",
				clon: { run, gitPath: process.execPath, ghPath: process.execPath },
			}),
		);
		expect(code).toBe("INTERRUMPIDO");
		expect(killed).toBe(true);
		expect(existsSync(join(dest, ".mct"))).toBe(false);
	});
});
