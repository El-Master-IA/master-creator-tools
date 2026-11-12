import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type FetchLike,
	GITLEAKS_DOWNLOAD_TIMEOUT_MS,
	GITLEAKS_RUN_TIMEOUT_MS,
	installGitleaks,
	runGitleaks,
} from "../src/gitleaks.js";

let root: string;
let target: string;
let tmpDir: string;

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "mct-glt-"));
	target = join(root, "work");
	tmpDir = join(root, "tmp");
	await mkdir(target, { recursive: true });
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});

async function motivo(p: Promise<unknown>): Promise<unknown> {
	const e = await p.then(
		() => null,
		(x: unknown) => x,
	);
	expect(e).toBeInstanceOf(MctError);
	expect((e as MctError).codigo).toBe("MOTOR_NO_DISPONIBLE");
	return (e as MctError).detalle?.motivo;
}

describe("tiempos de gitleaks", () => {
	it("TMO-002 los límites por defecto son 300 s de ejecución y 60 s de descarga", () => {
		expect(GITLEAKS_RUN_TIMEOUT_MS).toBe(300_000);
		expect(GITLEAKS_DOWNLOAD_TIMEOUT_MS).toBe(60_000);
	});

	it("TMO-002 una ejecución que no termina se corta con MOTOR_NO_DISPONIBLE", async () => {
		const script = join(root, "slow.cjs");
		await writeFile(
			script,
			'if (process.argv[2] === "version") { console.log("8.30.1"); process.exit(0); }\nsetTimeout(() => {}, 60000);\n',
		);
		const started = Date.now();
		const m = await motivo(
			runGitleaks({
				binary: process.execPath,
				binaryArgs: [script],
				target,
				tmpDir,
				timeoutMs: 400,
			}),
		);
		expect(m).toBe("timeout");
		expect(Date.now() - started).toBeLessThan(20_000);
		expect(await readdir(tmpDir)).toEqual([]);
	});

	it("TMO-002 una descarga que no responde se corta con MOTOR_NO_DISPONIBLE", async () => {
		const hang: FetchLike = (_url, init) =>
			new Promise((_resolve, reject) => {
				init.signal.addEventListener("abort", () => reject(new Error("abort")));
			});
		const dest = join(root, "bin");
		const m = await motivo(
			installGitleaks({
				destDir: dest,
				platform: "linux",
				arch: "x64",
				fetch: hang,
				timeoutMs: 50,
			}),
		);
		expect(m).toBe("timeout");
		expect(await readdir(dest)).toEqual([]);
	});

	it("TMO-002 un cuerpo que se queda a medias también se corta", async () => {
		const stuckBody: FetchLike = async () => ({
			ok: true,
			status: 200,
			arrayBuffer: () => new Promise<ArrayBuffer>(() => {}),
		});
		const m = await motivo(
			installGitleaks({
				destDir: join(root, "bin2"),
				platform: "linux",
				arch: "x64",
				fetch: stuckBody,
				timeoutMs: 50,
			}),
		);
		expect(m).toBe("timeout");
	});
});
