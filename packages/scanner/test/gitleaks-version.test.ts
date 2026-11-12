import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import { GITLEAKS_MAJOR, GITLEAKS_VERSION } from "@mct/contract/pins";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	checkGitleaksVersion,
	type Runner,
	type RunResult,
	runGitleaks,
} from "../src/gitleaks.js";

const ABS_BIN = resolve("gitleaks-fake-bin");

let root: string;
let target: string;
let tmpDir: string;

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "mct-glv-"));
	target = join(root, "work");
	tmpDir = join(root, "tmp");
	await mkdir(target, { recursive: true });
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});

const ok = (stdout: string): RunResult => ({
	code: 0,
	signal: null,
	stdout,
	timedOut: false,
});

function versionRunner(result: RunResult, scans: string[] = []): Runner {
	return async (_c, args) => {
		if (args.includes("dir")) {
			scans.push("dir");
			const i = args.indexOf("--report-path");
			await writeFile(String(args[i + 1]), "[]");
			return ok("");
		}
		return result;
	};
}

async function codigo(p: Promise<unknown>): Promise<string> {
	const e = await p.then(
		() => null,
		(x: unknown) => x,
	);
	expect(e).toBeInstanceOf(MctError);
	return (e as MctError).codigo;
}

describe("versión de gitleaks", () => {
	it("SCAN-013 el pin del contrato es 8.30.1 con mayor 8", () => {
		expect(GITLEAKS_VERSION).toBe("8.30.1");
		expect(GITLEAKS_MAJOR).toBe(8);
	});

	it("SCAN-013 acepta la misma versión mayor y la devuelve", async () => {
		expect(
			await checkGitleaksVersion("g", { run: versionRunner(ok("8.30.1\n")) }),
		).toBe("8.30.1");
		expect(
			await checkGitleaksVersion("g", { run: versionRunner(ok("v8.12.0\n")) }),
		).toBe("8.12.0");
	});

	it("SCAN-013 una versión mayor distinta sale con MOTOR_NO_DISPONIBLE", async () => {
		for (const v of ["9.0.0\n", "7.6.1\n", "10.1.0\n"]) {
			expect(
				await codigo(checkGitleaksVersion("g", { run: versionRunner(ok(v)) })),
			).toBe("MOTOR_NO_DISPONIBLE");
		}
	});

	it("SCAN-013 una versión ilegible o un fallo sale con MOTOR_NO_DISPONIBLE", async () => {
		const cases: RunResult[] = [
			ok(""),
			ok("gitleaks version latest"),
			ok("8.30"),
			{ code: 1, signal: null, stdout: "8.30.1", timedOut: false },
			{
				code: null,
				signal: null,
				stdout: "",
				timedOut: false,
				error: Object.assign(new Error("x"), { code: "ENOENT" }),
			},
		];
		for (const c of cases) {
			expect(
				await codigo(checkGitleaksVersion("g", { run: versionRunner(c) })),
			).toBe("MOTOR_NO_DISPONIBLE");
		}
	});

	it("SCAN-013 con la mayor distinta no se llega a escanear", async () => {
		const scans: string[] = [];
		const run = versionRunner(ok("9.1.0\n"), scans);
		expect(
			await codigo(runGitleaks({ binary: ABS_BIN, target, tmpDir, run })),
		).toBe("MOTOR_NO_DISPONIBLE");
		expect(scans).toEqual([]);
	});

	it("SCAN-013 el resultado del escaneo registra la versión de gitleaks", async () => {
		const run = versionRunner(ok("8.30.1\n"));
		const result = await runGitleaks({ binary: ABS_BIN, target, tmpDir, run });
		expect(result.version).toBe("8.30.1");
		expect(result.findings).toEqual([]);
	});
});
