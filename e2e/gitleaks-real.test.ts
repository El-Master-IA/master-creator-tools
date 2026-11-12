import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
import { GITLEAKS_VERSION } from "../packages/contract/src/pins.js";
import {
	checkGitleaksVersion,
	runGitleaks,
} from "../packages/scanner/src/gitleaks.js";
import { scan } from "../packages/scanner/src/scan.js";
import { CLAVE_PRUEBA } from "../packages/scanner/test/clave.js";
import { dockerGitleaksRunner } from "./support/gitleaks-docker.js";

// Real gitleaks 8.30.1 (official image on the Docker of DOCKER_HOST). No fallback:
// without Docker the suite fails (fail closed), it never skips.
const BIN = "/usr/local/bin/gitleaks";

let base = "";
let target = "";
let tmpDir = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-glreal-"));
	target = join(base, "work");
	tmpDir = join(base, "tmp");
	await mkdir(target, { recursive: true });
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** A synthetic GitHub token built by pieces: it never appears literally in the repo. */
function token(n: number): string {
	const head = ["gh", "p_"].join("");
	// Generated, never a literal: alternating case letters plus digits, 32 chars.
	const body = Array.from({ length: 32 }, (_, i) =>
		i % 3 === 2
			? String((i * 7) % 10)
			: String.fromCharCode((i % 2 === 0 ? 97 : 65) + ((i * 11) % 26)),
	).join("");
	return `${head}${body}${String(n).padStart(4, "0")}`;
}

const OWN_CONFIG = 'title = "mct"\n\n[extend]\nuseDefault = true\n';

describe("gitleaks 8.30.1 real", () => {
	it("SCAN-013 the pinned version is the one the real binary reports", async () => {
		expect(await checkGitleaksVersion(BIN, { run: dockerGitleaksRunner })).toBe(
			GITLEAKS_VERSION,
		);
	});

	it("SCAN-004 a hostile .gitleaks.toml and gitleaks:allow inside work/ do not hide the secret", async () => {
		await writeFile(
			join(target, ".gitleaks.toml"),
			"title = 'x'\n[allowlist]\npaths = ['''.*''']\nregexes = ['''.*''']\n",
		);
		await writeFile(
			join(target, "a.txt"),
			`k = "${token(1)}" # gitleaks:allow\n`,
		);
		const result = await runGitleaks({
			binary: BIN,
			target,
			tmpDir,
			run: dockerGitleaksRunner,
		});
		expect(result.version).toBe(GITLEAKS_VERSION);
		expect(
			result.findings.filter((f) => f.file === "a.txt" && f.line === 1),
		).toHaveLength(1);
	});

	it("SCAN-004 useDefault brings the default rules, with their global allowlist for lockfiles", async () => {
		await writeFile(join(target, "a.txt"), `k = "${token(2)}"\n`);
		await writeFile(join(target, "pnpm-lock.yaml"), `k: "${token(3)}"\n`);
		const result = await runGitleaks({
			binary: BIN,
			target,
			tmpDir,
			run: dockerGitleaksRunner,
		});
		expect(result.findings.map((f) => `${f.rule}:${f.file}`)).toEqual([
			"github-pat:a.txt",
		]);
	});

	it("SCAN-004 a .gitleaksignore in the target really hides findings, so runGitleaks refuses it", async () => {
		await writeFile(join(target, "a.txt"), `k = "${token(4)}"\n`);
		const scratch = join(base, "cfg");
		await mkdir(scratch, { recursive: true });
		await writeFile(join(scratch, "gitleaks.toml"), OWN_CONFIG);
		const rawArgs = (report: string): string[] => [
			"dir",
			target,
			"--config",
			join(scratch, "gitleaks.toml"),
			"--gitleaks-ignore-path",
			scratch,
			"--ignore-gitleaks-allow",
			"--redact",
			"--report-format",
			"json",
			"--report-path",
			report,
			"--exit-code",
			"2",
			"--no-banner",
			"--no-color",
			"--log-level",
			"error",
		];
		const opts = { cwd: scratch, env: {}, timeoutMs: 120_000 };

		const first = join(base, "r1.json");
		const r1 = await dockerGitleaksRunner(BIN, rawArgs(first), opts);
		expect(r1.code).toBe(2);
		const report = JSON.parse(await readFile(first, "utf8")) as {
			Fingerprint: string;
		}[];
		expect(report).toHaveLength(1);

		await writeFile(
			join(target, ".gitleaksignore"),
			`${report[0]?.Fingerprint}\n`,
		);
		const second = join(base, "r2.json");
		const r2 = await dockerGitleaksRunner(BIN, rawArgs(second), opts);
		expect(r2.code).toBe(0);

		const refused = await runGitleaks({
			binary: BIN,
			target,
			tmpDir,
			run: dockerGitleaksRunner,
		}).catch((e: unknown) => e);
		expect(refused).toBeInstanceOf(MctError);
		expect((refused as MctError).codigo).toBe("MOTOR_NO_DISPONIBLE");
	});

	it("SCAN-004 positions in a file over 100 KB: the first line of every chunk keeps the same corrected column", async () => {
		// ~420 KB of filler lines; tokens in windows of 41 lines around each
		// 100 KB boundary (gitleaks reads in chunks of 100 KB), so the first line
		// of every chunk after the first one carries a finding.
		const lines: string[] = [];
		const expected: number[] = [];
		let bytes = 0;
		const windows = [100_000, 200_000, 300_000, 400_000];
		for (let i = 0; i < 7000; i++) {
			const nearBoundary = windows.some((w) => Math.abs(bytes - w) < 20 * 70);
			if (nearBoundary || i === 0) {
				lines.push(`  token = "${token(i)}"`);
				expected.push(i + 1);
			} else {
				lines.push(
					`filler line number ${String(i).padStart(5, "0")} with some padding xxxxxxxxxxxxxxxx`,
				);
			}
			bytes += (lines[i] as string).length + 1;
		}
		const text = lines.join("\n");
		expect(Buffer.byteLength(text)).toBeGreaterThan(400_000);
		expect(expected.length).toBeGreaterThan(100);
		await writeFile(join(target, "big.txt"), text);

		const result = await runGitleaks({
			binary: BIN,
			target,
			tmpDir,
			run: dockerGitleaksRunner,
		});
		expect(result.findings.map((f) => f.line)).toEqual(expected);
		const wrong = result.findings.filter(
			(f) => f.endLine !== f.line || f.column !== 12 || f.endColumn !== 51,
		);
		expect(wrong).toEqual([]);
	});

	it("SCAN-004 scan() recovers every real match, with bytes turned into UTF-16 columns", async () => {
		const lines: string[] = [];
		for (let i = 0; i < 6000; i++) {
			lines.push(
				i % 50 === 0
					? `  token = "${token(i)}"`
					: `filler line ${i} xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
			);
		}
		await writeFile(join(target, "big.txt"), lines.join("\n"));
		await writeFile(join(target, "u.txt"), `ñ=ñ ${token(9)}\nx\n`);
		const result = await scan({
			work: target,
			quarantine: join(base, "quarantine"),
			clave: CLAVE_PRUEBA,
			gitleaks: {
				binary: BIN,
				installDir: base,
				tmpDir,
				run: dockerGitleaksRunner,
			},
		});
		expect(result.gitleaksVersion).toBe(GITLEAKS_VERSION);
		const big = result.hallazgos.filter(
			(f) => f.archivo === "big.txt" && f.regla === "github-pat",
		);
		expect(big.length).toBeGreaterThanOrEqual(1);
		const u = result.hallazgos.filter((f) => f.archivo === "u.txt");
		expect(u.some((f) => f.linea === 1 && f.columna === 5)).toBe(true);
	});
});
