import {
	lstat,
	mkdir,
	mkdtemp,
	open,
	rm,
	truncate,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initFromSource, LIMITES } from "../src/init.js";

let base: string;
let origen: string;
let dest: string;

const MIB = 1024 * 1024;
const pkg = JSON.stringify({ name: "demo", version: "1.0.0", main: "i.js" });

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

async function expectLimit(p: Promise<unknown>, cual: string) {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	expect((err as MctError).codigo).toBe("VALIDACION");
	expect((err as MctError).detalle?.limite).toBe(cual);
	return err as MctError;
}

async function sized(path: string, bytes: number): Promise<void> {
	const fh = await open(path, "w");
	await fh.close();
	await truncate(path, bytes);
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t17l-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	await mkdir(origen, { recursive: true });
	await mkdir(dest, { recursive: true });
	await writeFile(join(origen, "package.json"), pkg);
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-004 límites del origen", () => {
	it("CLI-004 los límites por defecto son 500 MB, 50 MB y 50.000 archivos", () => {
		expect(LIMITES).toEqual({
			total: 500 * MIB,
			archivo: 50 * MIB,
			archivos: 50_000,
		});
	});

	it("CLI-004 un archivo de 50 MB + 1 sale con VALIDACION y dice cuál límite", async () => {
		await sized(join(origen, "grande.bin"), 50 * MIB + 1);
		const err = await expectLimit(initFromSource(opts()), "archivo");
		expect(err.message).toMatch(/50 MB/);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-004 un archivo de exactamente 50 MB entra", async () => {
		await sized(join(origen, "justo.bin"), 50 * MIB);
		const r = await initFromSource(opts());
		expect(r.archivos).toBe(2);
	});

	it("CLI-004 más de 500 MB en total sale con VALIDACION y dice cuál límite", async () => {
		for (let i = 0; i < 11; i++) {
			await sized(join(origen, `p${i}.bin`), 48 * MIB);
		}
		const err = await expectLimit(initFromSource(opts()), "total");
		expect(err.message).toMatch(/500 MB/);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-004 el límite de archivos se aplica con > y dice cuál", async () => {
		for (let i = 0; i < 4; i++) {
			await writeFile(join(origen, `f${i}.txt`), "x");
		}
		// 5 files in total (with package.json): limit 5 passes, limit 4 fails.
		const ok = await initFromSource(opts({ limites: { archivos: 5 } }));
		expect(ok.archivos).toBe(5);
		await rm(join(dest, ".mct"), { recursive: true, force: true });
		const err = await expectLimit(
			initFromSource(opts({ limites: { archivos: 4 } })),
			"archivos",
		);
		expect(err.message).toMatch(/archivos/);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-004 los archivos de quarantine también cuentan", async () => {
		await writeFile(join(origen, ".env"), "A=1\n");
		await expectLimit(
			initFromSource(opts({ limites: { archivos: 1 } })),
			"archivos",
		);
	});

	it("CLI-004 lo excluido (node_modules, globs) no cuenta para los límites", async () => {
		await mkdir(join(origen, "node_modules"));
		await sized(join(origen, "node_modules", "enorme.bin"), 60 * MIB);
		await sized(join(origen, "ruido.bin"), 60 * MIB);
		await writeFile(
			join(dest, "mct.config.json"),
			JSON.stringify({ exclude: ["*.bin"] }),
		);
		const r = await initFromSource(opts());
		expect(r.archivos).toBe(1);
	});
});
