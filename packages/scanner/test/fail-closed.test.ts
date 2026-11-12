import { createHash } from "node:crypto";
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type FetchLike,
	installGitleaks,
	type Runner,
	type RunOptions,
	runGitleaks,
	tarCommand,
} from "../src/gitleaks.js";

// Fixture values are assembled from fragments so no literal secret lives here.
const MARKER = ["MCT", "FAKE", "_", "ABCDEF", "123456"].join("");
/** Any absolute path: the fake runners never execute it. */
const ABS_BIN = resolve("gitleaks-fake-bin");
const MARKER_RE = "MCTFAKE_[A-Z0-9]{12}";

interface Spec {
	version?: string;
	exit?: number;
	report?: string;
	modeOut?: string;
}

/** Fake gitleaks: node script that mimics the flags/exit codes of 8.30.1. */
function fakeScript(spec: Spec): string {
	return `
const fs = require("fs");
const path = require("path");
const spec = ${JSON.stringify(spec)};
const a = process.argv.slice(2);
const get = (n) => { const i = a.indexOf(n); return i < 0 ? undefined : a[i + 1]; };
if (a[0] === "version") { console.log(spec.version || "8.30.1"); process.exit(0); }
const target = a[1];
const rp = get("--report-path");
if (spec.modeOut && process.platform !== "win32") {
  fs.writeFileSync(spec.modeOut, (fs.statSync(rp).mode & 0o777).toString(8));
}
if (spec.exit !== undefined) {
  if (spec.report !== undefined) fs.writeFileSync(rp, spec.report);
  process.exit(spec.exit);
}
// Config precedence of the real tool: --config first, else (target)/.gitleaks.toml.
const cfgPath = get("--config") || path.join(target, ".gitleaks.toml");
let active = true;
try { if (fs.readFileSync(cfgPath, "utf8").includes("disable-all")) active = false; } catch {}
const found = [];
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) { walk(f); continue; }
    if (!active) continue;
    fs.readFileSync(f, "utf8").split("\\n").forEach((text, i) => {
      const m = new RegExp(${JSON.stringify(MARKER_RE)}).exec(text);
      // gitleaks 8.30.1 (detect/location.go): byte columns, base 1, +1 off the first line.
      const shift = i > 0 ? 1 : 0;
      if (m) found.push({
        RuleID: "fake-rule", File: f, StartLine: i + 1, EndLine: i + 1,
        StartColumn: m.index + 1 + shift, EndColumn: m.index + m[0].length + shift,
        Match: m[0], Secret: a.includes("--redact") ? "REDACTED" : m[0],
      });
    });
  }
};
walk(target);
fs.writeFileSync(rp, JSON.stringify(found));
process.exit(found.length ? Number(get("--exit-code")) : 0);
`;
}

let root: string;
let target: string;
let tmpDir: string;

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "mct-gl-"));
	target = join(root, "work");
	tmpDir = join(root, "tmp");
	await mkdir(target, { recursive: true });
});

afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});

async function fake(
	spec: Spec,
): Promise<{ binary: string; binaryArgs: string[] }> {
	const file = join(root, `fake-${Math.random().toString(16).slice(2)}.cjs`);
	await writeFile(file, fakeScript(spec));
	return { binary: process.execPath, binaryArgs: [file] };
}

async function expectUnavailable(p: Promise<unknown>): Promise<MctError> {
	const error = await p.then(
		() => null,
		(e: unknown) => e,
	);
	expect(error).toBeInstanceOf(MctError);
	expect((error as MctError).codigo).toBe("MOTOR_NO_DISPONIBLE");
	expect((error as MctError).exit).toBe(12);
	return error as MctError;
}

async function leftovers(): Promise<string[]> {
	return readdir(tmpDir).catch(() => []);
}

describe("gitleaks fail closed", () => {
	it("SCAN-004 con gitleaks ausente sale con MOTOR_NO_DISPONIBLE", async () => {
		await expectUnavailable(
			runGitleaks({ binary: join(root, "no-existe"), target, tmpDir }),
		);
	});

	it("SCAN-004 un exit 1 (error de gitleaks) no es cero hallazgos", async () => {
		const f = await fake({ exit: 1, report: "[]" });
		await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
	});

	it("SCAN-004 un exit inesperado (126) falla cerrado", async () => {
		const f = await fake({ exit: 126 });
		await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
	});

	it("SCAN-004 exit 0 con el reporte vacío o inválido falla cerrado", async () => {
		for (const report of ["", "no es json", "{}", '[{"RuleID":"x"}]']) {
			const f = await fake({ exit: 0, report });
			await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
		}
	});

	it("SCAN-004 exit de hallazgos con reporte vacío falla cerrado", async () => {
		const f = await fake({ exit: 2, report: "[]" });
		await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
	});

	it("SCAN-004 un hallazgo fuera del objetivo falla cerrado", async () => {
		const outside = JSON.stringify([
			{
				RuleID: "r",
				File: join(root, "otro.txt"),
				StartLine: 1,
				EndLine: 1,
				StartColumn: 1,
				EndColumn: 3,
			},
		]);
		const f = await fake({ exit: 2, report: outside });
		await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
	});

	it("SCAN-004 un directorio objetivo inexistente es WORKSPACE_INVALIDO", async () => {
		const f = await fake({});
		const error = await runGitleaks({
			...f,
			target: join(root, "nada"),
			tmpDir,
		}).then(
			() => null,
			(e: unknown) => e,
		);
		expect((error as MctError).codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("SCAN-004 sin secretos devuelve la versión y una lista vacía real", async () => {
		await writeFile(join(target, "a.txt"), "nada que ver\n");
		const f = await fake({});
		const result = await runGitleaks({ ...f, target, tmpDir });
		expect(result).toEqual({ version: "8.30.1", findings: [] });
	});

	it("SCAN-004 el hallazgo no guarda el valor del secreto", async () => {
		await writeFile(join(target, "a.txt"), `x\nkey = ${MARKER}\n`);
		const f = await fake({});
		const result = await runGitleaks({ ...f, target, tmpDir });
		expect(result.findings).toEqual([
			{
				rule: "fake-rule",
				file: "a.txt",
				line: 2,
				column: 7,
				endLine: 2,
				endColumn: 26,
				fragment: "****",
			},
		]);
		expect(JSON.stringify(result)).not.toContain(MARKER);
	});

	it("SCAN-001 gitleaks 8.30.1 suma 1 a las columnas fuera de la primera línea y se corrige", async () => {
		const report = JSON.stringify([
			{
				RuleID: "r",
				File: "a.txt",
				StartLine: 1,
				EndLine: 1,
				StartColumn: 5,
				EndColumn: 9,
			},
			{
				RuleID: "r",
				File: "a.txt",
				StartLine: 3,
				EndLine: 4,
				StartColumn: 6,
				EndColumn: 3,
			},
		]);
		await writeFile(join(target, "a.txt"), "x\n");
		const f = await fake({ exit: 2, report });
		const result = await runGitleaks({ ...f, target, tmpDir });
		expect(result.findings).toMatchObject([
			{ line: 1, column: 5, endLine: 1, endColumn: 9 },
			{ line: 3, column: 5, endLine: 4, endColumn: 2 },
		]);
	});

	it("SCAN-001 una regla de solo ruta (línea y columna 0) es un hallazgo de archivo", async () => {
		const report = JSON.stringify([
			{
				RuleID: "pkcs12-file",
				File: "k.p12",
				StartLine: 0,
				EndLine: 0,
				StartColumn: 0,
				EndColumn: 0,
			},
		]);
		await writeFile(join(target, "k.p12"), "x");
		const f = await fake({ exit: 2, report });
		const result = await runGitleaks({ ...f, target, tmpDir });
		expect(result.findings).toEqual([
			{
				rule: "pkcs12-file",
				file: "k.p12",
				line: 0,
				column: 0,
				endLine: 0,
				endColumn: 0,
				fragment: "****",
			},
		]);
	});

	it("SCAN-004 posiciones incoherentes del reporte fallan cerrado", async () => {
		const bad = [
			{ StartLine: 0, StartColumn: 3, EndLine: 0, EndColumn: 4 },
			{ StartLine: 2, StartColumn: 0, EndLine: 2, EndColumn: 4 },
			{ StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 4 },
			{ StartLine: 2, StartColumn: 3 },
			{ StartLine: 3, StartColumn: 3, EndLine: 2, EndColumn: 4 },
			{ StartLine: 1, StartColumn: 5, EndLine: 1, EndColumn: 4 },
		];
		for (const pos of bad) {
			const report = JSON.stringify([{ RuleID: "r", File: "a.txt", ...pos }]);
			const f = await fake({ exit: 2, report });
			await expectUnavailable(runGitleaks({ ...f, target, tmpDir }));
		}
	});

	it("SCAN-004 borra el reporte temporal con éxito y con fallo", async () => {
		await writeFile(join(target, "a.txt"), `k=${MARKER}\n`);
		await runGitleaks({ ...(await fake({})), target, tmpDir });
		expect(await leftovers()).toEqual([]);
		await expectUnavailable(
			runGitleaks({ ...(await fake({ exit: 1 })), target, tmpDir }),
		);
		expect(await leftovers()).toEqual([]);
	});

	it.skipIf(process.platform === "win32")(
		"SCAN-004 el reporte temporal se crea con permisos 0600",
		async () => {
			const modeOut = join(root, "mode.txt");
			await runGitleaks({ ...(await fake({ modeOut })), target, tmpDir });
			expect(await readFile(modeOut, "utf8")).toBe("600");
		},
	);

	it("SCAN-004 el reporte temporal queda en tmpDir con nombre gitleaks-<ts>.json", async () => {
		const seen: string[] = [];
		const run: Runner = async (_c, args) => {
			const i = args.indexOf("--report-path");
			if (i >= 0) {
				seen.push(String(args[i + 1]));
				await writeFile(String(args[i + 1]), "[]");
				return { code: 0, signal: null, stdout: "", timedOut: false };
			}
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		};
		await runGitleaks({ binary: ABS_BIN, target, tmpDir, run });
		expect(seen[0]?.startsWith(tmpDir)).toBe(true);
		expect(seen[0]).toMatch(/gitleaks-\d+-[0-9a-f]+\.json$/);
	});
});

describe("gitleaks config propia (backlog MAJOR)", () => {
	const hostile = "[allowlist]\n# disable-all\npaths = ['''.*''']\n";

	it("SCAN-004 pasa siempre --config con un archivo propio fuera del objetivo", async () => {
		process.env.GITLEAKS_CONFIG = join(target, "otra.toml");
		process.env.GITLEAKS_CONFIG_TOML = hostile;
		const calls: { args: readonly string[]; options: RunOptions }[] = [];
		const run: Runner = async (_c, args, options) => {
			calls.push({ args, options });
			const i = args.indexOf("--report-path");
			if (i >= 0) await writeFile(String(args[i + 1]), "[]");
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		};
		try {
			await runGitleaks({ binary: ABS_BIN, target, tmpDir, run });
		} finally {
			delete process.env.GITLEAKS_CONFIG;
			delete process.env.GITLEAKS_CONFIG_TOML;
		}
		const scan = calls.find((c) => c.args.includes("dir"));
		const args = scan?.args ?? [];
		const cfg = String(args[args.indexOf("--config") + 1]);
		expect(args).toContain("--config");
		expect(cfg.startsWith(target)).toBe(false);
		expect(cfg.startsWith(tmpDir)).toBe(true);
		expect(args).toContain("--redact");
		expect(args).toContain("--ignore-gitleaks-allow");
		expect(args[args.indexOf("--gitleaks-ignore-path") + 1]).not.toBe(target);
		expect(
			Object.keys(scan?.options.env ?? {}).some((k) =>
				k.startsWith("GITLEAKS_"),
			),
		).toBe(false);
		expect(scan?.options.cwd.startsWith(target)).toBe(false);
	});

	it("SCAN-004 una .gitleaks.toml hostil dentro del objetivo no desactiva reglas", async () => {
		await writeFile(join(target, ".gitleaks.toml"), hostile);
		await writeFile(join(target, "a.txt"), `k=${MARKER}\n`);
		// Control: the fake does obey the target's file when no --config is given.
		const control = await fake({});
		const { execFileSync } = await import("node:child_process");
		const reportPath = join(root, "control.json");
		const code = (() => {
			try {
				execFileSync(
					control.binary,
					[
						...control.binaryArgs,
						"dir",
						target,
						"--report-path",
						reportPath,
						"--exit-code",
						"2",
					],
					{ stdio: "ignore" },
				);
				return 0;
			} catch (e) {
				return (e as { status: number }).status;
			}
		})();
		expect(code).toBe(0);
		expect(await readFile(reportPath, "utf8")).toBe("[]");
		// With the wrapper the rule stays on.
		const result = await runGitleaks({ ...control, target, tmpDir });
		expect(result.findings.map((x) => x.file)).toEqual(["a.txt"]);
	});
});

describe("gitleaks revisión T12", () => {
	function spyRunner(scans: string[]): Runner {
		return async (_c, args) => {
			const i = args.indexOf("--report-path");
			if (i >= 0) {
				scans.push("dir");
				await writeFile(String(args[i + 1]), "[]");
				return { code: 0, signal: null, stdout: "", timedOut: false };
			}
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		};
	}

	it("SCAN-004 un .gitleaksignore en el objetivo falla cerrado sin escanear", async () => {
		await writeFile(join(target, ".gitleaksignore"), "*:*:*\n");
		await writeFile(join(target, "a.txt"), `k=${MARKER}\n`);
		const scans: string[] = [];
		const error = await expectUnavailable(
			runGitleaks({
				binary: ABS_BIN,
				target,
				tmpDir,
				run: spyRunner(scans),
			}),
		);
		expect(error.detalle?.motivo).toBe("gitleaksignore-en-objetivo");
		expect(scans).toEqual([]);
		expect(await leftovers()).toEqual([]);
	});

	it("SCAN-004 sin .gitleaksignore en el objetivo escanea con normalidad", async () => {
		const scans: string[] = [];
		await runGitleaks({
			binary: ABS_BIN,
			target,
			tmpDir,
			run: spyRunner(scans),
		});
		expect(scans).toEqual(["dir"]);
	});

	it("SEG-106 un binario de gitleaks relativo se rechaza con MctError", async () => {
		const scans: string[] = [];
		for (const binary of ["gitleaks", "./gitleaks", "bin/gitleaks"]) {
			const error = await expectUnavailable(
				runGitleaks({ binary, target, tmpDir, run: spyRunner(scans) }),
			);
			expect(error.detalle?.motivo).toBe("binario-relativo");
		}
		expect(scans).toEqual([]);
	});

	it("SEG-106 en Windows tar se resuelve a System32 por ruta absoluta", () => {
		const bs = String.fromCharCode(92);
		const w = (...parts: string[]): string => parts.join(bs);
		expect(tarCommand("win32", { SystemRoot: w("C:", "Windows") })).toBe(
			w("C:", "Windows", "System32", "tar.exe"),
		);
		expect(tarCommand("win32", { windir: w("D:", "WIN") })).toBe(
			w("D:", "WIN", "System32", "tar.exe"),
		);
		expect(tarCommand("win32", {})).toBe(
			w("C:", "Windows", "System32", "tar.exe"),
		);
		expect(tarCommand("linux", { SystemRoot: w("C:", "Windows") })).toBe("tar");
	});
});

describe("gitleaks descarga", () => {
	const NAME_RE =
		/gitleaks_8\.30\.1_(linux|darwin|windows)_(x64|arm64)\.(tar\.gz|zip)$/;
	const archive = Buffer.from("contenido-del-release");
	const sha = (b: Buffer): string =>
		createHash("sha256").update(b).digest("hex");

	function fetcher(checksumHex: string): FetchLike {
		return async (url) => {
			const body = url.endsWith("checksums.txt")
				? Buffer.from(
						`${checksumHex}  gitleaks_8.30.1_linux_x64.tar.gz
`,
					)
				: archive;
			return {
				ok: true,
				status: 200,
				arrayBuffer: async () =>
					body.buffer.slice(
						body.byteOffset,
						body.byteOffset + body.byteLength,
					) as ArrayBuffer,
			};
		};
	}

	it("SCAN-004 con el checksum distinto borra la descarga y falla", async () => {
		const dest = join(root, "bin");
		let extracted = false;
		const seen: string[] = [];
		const wrong: FetchLike = async (url) => {
			seen.push(url);
			const inner = await fetcher(sha(Buffer.from("otra cosa")))(url, {
				signal: new AbortController().signal,
			});
			return inner;
		};
		await expectUnavailable(
			installGitleaks({
				destDir: dest,
				platform: "linux",
				arch: "x64",
				fetch: wrong,
				extract: async () => {
					extracted = true;
				},
			}),
		);
		expect(extracted).toBe(false);
		expect(seen.some((u) => u.includes("/v8.30.1/"))).toBe(true);
		expect(
			seen.every((u) => NAME_RE.test(u) || u.endsWith("checksums.txt")),
		).toBe(true);
		expect(await readdir(dest)).toEqual([]);
	});

	it("SCAN-004 sin la línea del archivo en checksums.txt falla y borra", async () => {
		const dest = join(root, "bin");
		const noLine: FetchLike = async (url) => {
			const body = url.endsWith("checksums.txt") ? Buffer.from("") : archive;
			return {
				ok: true,
				status: 200,
				arrayBuffer: async () =>
					body.buffer.slice(
						body.byteOffset,
						body.byteOffset + body.byteLength,
					) as ArrayBuffer,
			};
		};
		await expectUnavailable(
			installGitleaks({
				destDir: dest,
				platform: "linux",
				arch: "x64",
				fetch: noLine,
			}),
		);
		expect(await readdir(dest)).toEqual([]);
	});

	it("SCAN-004 con el checksum correcto extrae el binario y no deja la descarga", async () => {
		const dest = join(root, "bin");
		const binary = await installGitleaks({
			destDir: dest,
			platform: "linux",
			arch: "x64",
			fetch: fetcher(sha(archive)),
			extract: async (_a, member, d) => {
				await writeFile(join(d, member), "bin");
			},
		});
		expect(binary).toBe(join(dest, "gitleaks"));
		expect((await stat(binary)).isFile()).toBe(true);
		expect(await readdir(dest)).toEqual(["gitleaks"]);
	});

	it("SCAN-004 una respuesta HTTP de error o una plataforma sin binario falla cerrado", async () => {
		const bad: FetchLike = async () => ({
			ok: false,
			status: 404,
			arrayBuffer: async () => new ArrayBuffer(0),
		});
		await expectUnavailable(
			installGitleaks({
				destDir: join(root, "b1"),
				platform: "linux",
				arch: "x64",
				fetch: bad,
			}),
		);
		await expectUnavailable(
			installGitleaks({
				destDir: join(root, "b2"),
				platform: "freebsd",
				arch: "x64",
				fetch: bad,
			}),
		);
	});
});
