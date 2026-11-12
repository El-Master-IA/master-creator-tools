import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
	chmod,
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { MctError } from "@mct/contract/errors";
import { GITLEAKS_MAJOR, GITLEAKS_VERSION } from "@mct/contract/pins";

/** Execution limit (TMO-002, api.md). */
export const GITLEAKS_RUN_TIMEOUT_MS = 300_000;
/** Download limit (TMO-002, api.md). */
export const GITLEAKS_DOWNLOAD_TIMEOUT_MS = 60_000;
const VERSION_TIMEOUT_MS = 15_000;
const MAX_OUTPUT_BYTES = 1_000_000;
const MAX_REPORT_BYTES = 200 * 1024 * 1024;
const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024;

/**
 * gitleaks 8.30.1: exit 0 = no leaks; with `--exit-code N`, N = leaks found;
 * every error (config, scan, report) is exit 1. We pick 2 for leaks so that
 * 1 can never be confused with a clean run (README says "leaks or error").
 */
const EXIT_LEAKS = 2;

/**
 * Own config: the default ruleset, no allowlist of ours. Never the target's file.
 * Note (SEG-109, checked in gitleaks v8.30.1 config/config.go `extend`):
 * `useDefault` also inherits the default config's global `[allowlist]`, so
 * gitleaks itself skips by path `gitleaks.toml`, images/fonts/office docs/exe,
 * `go.sum`/`go.mod`, `node_modules/`, `vendor/`, lockfiles (package-lock.json,
 * pnpm-lock.yaml, yarn.lock, Pipfile.lock, ...), `.git`, and by value a few
 * placeholders (`true`/`false`/`null`, `$VAR`, `{{ x }}`, `${{ secrets.X }}`).
 * That is upstream's default behaviour, not a switch the target controls; do
 * not read "0 findings" as "those paths were scanned".
 */
const OWN_CONFIG = 'title = "mct"\n\n[extend]\nuseDefault = true\n';

export const MASKED_FRAGMENT = "****";

export interface RunResult {
	readonly code: number | null;
	readonly signal: NodeJS.Signals | null;
	readonly stdout: string;
	readonly timedOut: boolean;
	readonly error?: NodeJS.ErrnoException;
}

export interface RunOptions {
	readonly cwd: string;
	readonly env: NodeJS.ProcessEnv;
	readonly timeoutMs: number;
}

export type Runner = (
	command: string,
	args: readonly string[],
	options: RunOptions,
) => Promise<RunResult>;

export interface GitleaksFinding {
	readonly rule: string;
	/** Relative to the scanned target, with `/`. */
	readonly file: string;
	/** Base 1. 0 for a path-only rule (the finding is the file itself). */
	readonly line: number;
	/** Base 1, bytes, start of the MATCH (not of the secret group). 0 for path-only. */
	readonly column: number;
	/** Base 1; last line of the match. 0 for path-only. */
	readonly endLine: number;
	/** Base 1, bytes, INCLUSIVE last byte of the match on `endLine`. 0 for path-only. */
	readonly endColumn: number;
	/** Never the secret: the fixed mask. */
	readonly fragment: string;
}

export interface GitleaksResult {
	readonly version: string;
	readonly findings: readonly GitleaksFinding[];
}

export interface GitleaksOptions {
	/** Path to the gitleaks binary. */
	readonly binary: string;
	/** Arguments placed before the gitleaks ones (tests use a fake binary). */
	readonly binaryArgs?: readonly string[];
	/** Directory to scan. */
	readonly target: string;
	/** `.mct/tmp`: the temporary report goes here (0600) and is always removed. */
	readonly tmpDir: string;
	readonly timeoutMs?: number;
	readonly run?: Runner;
}

function unavailable(
	motivo: string,
	mensaje: string,
	extra: Record<string, unknown> = {},
	cause?: unknown,
): MctError {
	return new MctError("MOTOR_NO_DISPONIBLE", mensaje, {
		accion: "Ejecuta `mct doctor --install-gitleaks` y vuelve a intentarlo",
		etapa: "gitleaks",
		detalle: { motivo, ...extra },
		...(cause === undefined ? {} : { cause }),
	});
}

/** Environment without any GITLEAKS_* variable (they can swap the config). */
function cleanEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(base)) {
		if (!key.toUpperCase().startsWith("GITLEAKS_")) env[key] = value;
	}
	return env;
}

export const defaultRunner: Runner = (command, args, options) =>
	new Promise<RunResult>((resolvePromise) => {
		let stdout = "";
		let timedOut = false;
		let settled = false;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const finish = (r: RunResult): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolvePromise(r);
		};
		let child: ReturnType<typeof spawn>;
		try {
			child = spawn(command, [...args], {
				cwd: options.cwd,
				env: options.env,
				stdio: ["ignore", "pipe", "ignore"],
				windowsHide: true,
				shell: false,
			});
		} catch (error) {
			resolvePromise({
				code: null,
				signal: null,
				stdout: "",
				timedOut: false,
				error: error as NodeJS.ErrnoException,
			});
			return;
		}
		timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
			// If the kill signal is lost, still return.
			setTimeout(
				() => finish({ code: null, signal: "SIGKILL", stdout, timedOut }),
				2000,
			).unref();
		}, options.timeoutMs);
		child.stdout?.on("data", (chunk: Buffer) => {
			if (stdout.length < MAX_OUTPUT_BYTES) stdout += chunk.toString("utf8");
		});
		child.on("error", (error) =>
			finish({
				code: null,
				signal: null,
				stdout,
				timedOut,
				error: error as NodeJS.ErrnoException,
			}),
		);
		child.on("close", (code, signal) =>
			finish({ code, signal, stdout, timedOut }),
		);
	});

function parseMajor(version: string): number {
	const m = /^(\d+)\.\d+\.\d+$/.exec(version);
	return m ? Number(m[1]) : -1;
}

/** Runs `gitleaks version` and checks the pinned major (SCAN-013). */
export async function checkGitleaksVersion(
	binary: string,
	options: {
		readonly binaryArgs?: readonly string[];
		readonly run?: Runner;
		readonly cwd?: string;
	} = {},
): Promise<string> {
	const run = options.run ?? defaultRunner;
	const result = await run(binary, [...(options.binaryArgs ?? []), "version"], {
		cwd: options.cwd ?? process.cwd(),
		env: cleanEnv(process.env),
		timeoutMs: VERSION_TIMEOUT_MS,
	});
	if (result.timedOut) {
		throw unavailable("timeout", "gitleaks no respondió al pedir su versión");
	}
	if (result.error) {
		throw unavailable(
			result.error.code === "ENOENT" ? "ausente" : "no-ejecutable",
			"gitleaks no está disponible",
			{},
			result.error,
		);
	}
	if (result.code !== 0) {
		throw unavailable("version-fallo", "gitleaks falló al pedir su versión", {
			exit: result.code,
		});
	}
	const version = result.stdout.trim().replace(/^v/, "");
	const major = parseMajor(version);
	if (major < 0) {
		throw unavailable(
			"version-invalida",
			"gitleaks devolvió una versión que no se reconoce",
		);
	}
	if (major !== GITLEAKS_MAJOR) {
		throw unavailable(
			"version-mayor",
			`La versión mayor de gitleaks (${major}) difiere de la fijada (${GITLEAKS_MAJOR})`,
			{ encontrada: version, fijada: GITLEAKS_VERSION },
		);
	}
	return version;
}

function positiveInt(value: unknown): number | null {
	return typeof value === "number" && Number.isInteger(value) && value >= 1
		? value
		: null;
}

function zeroOrMissing(value: unknown): boolean {
	return value === undefined || value === 0;
}

/**
 * Real positions of a gitleaks 8.30.1 finding (detect/detect.go + location.go,
 * checked at the v8.30.1 tag). `StartLine` is 1-based, but the columns are
 * computed against `prevNewLine`, which is the index of the previous newline and
 * not of the first byte of the line: outside the first line both columns come
 * out +1. They are bytes, and refer to the whole regex MATCH, not to the secret
 * group. Rules with only a path have no positions at all (all four are 0).
 * Returns null when the positions are incoherent.
 */
function realPositions(rec: Record<string, unknown>): {
	line: number;
	column: number;
	endLine: number;
	endColumn: number;
} | null {
	const startLine = rec.StartLine;
	const startColumn = rec.StartColumn;
	if (
		startLine === 0 &&
		startColumn === 0 &&
		zeroOrMissing(rec.EndLine) &&
		zeroOrMissing(rec.EndColumn)
	) {
		return { line: 0, column: 0, endLine: 0, endColumn: 0 };
	}
	const line = positiveInt(startLine);
	const column = positiveInt(startColumn);
	const endLine = positiveInt(rec.EndLine);
	const endColumn = positiveInt(rec.EndColumn);
	if (
		line === null ||
		column === null ||
		endLine === null ||
		endColumn === null
	) {
		return null;
	}
	const start = column - (line > 1 ? 1 : 0);
	const end = endColumn - (endLine > 1 ? 1 : 0);
	if (start < 1 || end < 1 || endLine < line) return null;
	if (endLine === line && end < start) return null;
	return { line, column: start, endLine, endColumn: end };
}

function parseReport(text: string, target: string): readonly GitleaksFinding[] {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch (error) {
		throw unavailable(
			"reporte-invalido",
			"El reporte de gitleaks no es JSON válido",
			{},
			error,
		);
	}
	if (!Array.isArray(raw)) {
		throw unavailable(
			"reporte-invalido",
			"El reporte de gitleaks no es una lista",
		);
	}
	const root = resolve(target);
	const findings: GitleaksFinding[] = [];
	for (const item of raw as unknown[]) {
		const rec =
			item !== null && typeof item === "object"
				? (item as Record<string, unknown>)
				: null;
		const rule = rec?.RuleID;
		const file = rec?.File;
		const position = rec === null ? null : realPositions(rec);
		if (
			typeof rule !== "string" ||
			rule === "" ||
			typeof file !== "string" ||
			file === "" ||
			position === null
		) {
			throw unavailable(
				"reporte-invalido",
				"Un hallazgo del reporte de gitleaks no tiene el formato esperado",
			);
		}
		const rel = relative(root, isAbsolute(file) ? file : resolve(root, file));
		if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
			throw unavailable(
				"reporte-invalido",
				"Un hallazgo de gitleaks apunta fuera del objetivo",
			);
		}
		findings.push({
			rule,
			file: rel.split(sep).join("/"),
			...position,
			fragment: MASKED_FRAGMENT,
		});
	}
	return findings;
}

/**
 * Runs gitleaks over `target`, fail closed (SCAN-004, SCAN-013, TMO-002).
 * Always passes `--config` with its own file, so a `.gitleaks.toml` or
 * `gitleaks:allow` comments (`--ignore-gitleaks-allow`) inside the target never
 * switch rules off. `--gitleaks-ignore-path` is NOT enough for
 * `.gitleaksignore`: gitleaks 8.30.1 (cmd/root.go) also loads
 * `<source>/.gitleaksignore`. We do not scan a copy (cost on big trees, extra
 * code); a target that carries that file is refused with MOTOR_NO_DISPONIBLE.
 */
export async function runGitleaks(
	options: GitleaksOptions,
): Promise<GitleaksResult> {
	const run = options.run ?? defaultRunner;
	const timeoutMs = options.timeoutMs ?? GITLEAKS_RUN_TIMEOUT_MS;
	if (!isAbsolute(options.binary)) {
		throw unavailable(
			"binario-relativo",
			"La ruta del binario de gitleaks debe ser absoluta",
		);
	}
	const target = resolve(options.target);
	const tmpDir = resolve(options.tmpDir);

	try {
		const info = await stat(target);
		if (!info.isDirectory()) throw new Error("not a directory");
	} catch (error) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"El objetivo del escaneo no existe",
			{
				etapa: "gitleaks",
				cause: error,
			},
		);
	}

	const ignoreFile = join(target, ".gitleaksignore");
	const hasIgnoreFile = await lstat(ignoreFile).then(
		() => true,
		(error: NodeJS.ErrnoException) => error.code !== "ENOENT",
	);
	if (hasIgnoreFile) {
		throw unavailable(
			"gitleaksignore-en-objetivo",
			"El objetivo contiene un .gitleaksignore que gitleaks cargaría y ocultaría hallazgos",
		);
	}

	const version = await checkGitleaksVersion(options.binary, {
		...(options.binaryArgs === undefined
			? {}
			: { binaryArgs: options.binaryArgs }),
		run,
	});

	const stamp = `${Date.now()}-${randomBytes(4).toString("hex")}`;
	const reportPath = join(tmpDir, `gitleaks-${stamp}.json`);
	let scratch: string | undefined;
	try {
		await mkdir(tmpDir, { recursive: true, mode: 0o700 });
		scratch = await mkdtemp(join(tmpDir, "gitleaks-cfg-"));
		const configPath = join(scratch, "gitleaks.toml");
		await writeFile(configPath, OWN_CONFIG, { mode: 0o600 });
		await writeFile(reportPath, "", { mode: 0o600 });
		await chmod(reportPath, 0o600).catch(() => undefined);

		const args = [
			...(options.binaryArgs ?? []),
			"dir",
			target,
			"--config",
			configPath,
			"--gitleaks-ignore-path",
			scratch,
			"--ignore-gitleaks-allow",
			"--redact",
			"--report-format",
			"json",
			"--report-path",
			reportPath,
			"--exit-code",
			String(EXIT_LEAKS),
			"--no-banner",
			"--no-color",
			"--log-level",
			"error",
		];
		const result = await run(options.binary, args, {
			cwd: scratch,
			env: cleanEnv(process.env),
			timeoutMs,
		});
		if (result.timedOut) {
			throw unavailable("timeout", "gitleaks superó el tiempo máximo", {
				segundos: Math.round(timeoutMs / 1000),
			});
		}
		if (result.error) {
			throw unavailable(
				"no-ejecutable",
				"gitleaks no se pudo ejecutar",
				{},
				result.error,
			);
		}
		if (result.code !== 0 && result.code !== EXIT_LEAKS) {
			throw unavailable("exit-inesperado", "gitleaks terminó con error", {
				exit: result.code,
				senal: result.signal,
			});
		}
		const size = (await stat(reportPath)).size;
		if (size === 0 || size > MAX_REPORT_BYTES) {
			throw unavailable(
				"reporte-invalido",
				"gitleaks no dejó un reporte utilizable",
			);
		}
		const findings = parseReport(await readFile(reportPath, "utf8"), target);
		if (result.code === EXIT_LEAKS && findings.length === 0) {
			throw unavailable(
				"reporte-incoherente",
				"gitleaks indicó hallazgos pero el reporte viene vacío",
			);
		}
		return { version, findings };
	} catch (error) {
		if (error instanceof MctError) throw error;
		throw unavailable(
			"fallo-interno",
			"No se pudo ejecutar gitleaks",
			{},
			error,
		);
	} finally {
		await rm(reportPath, { force: true }).catch(() => undefined);
		if (scratch !== undefined) {
			await rm(scratch, { recursive: true, force: true }).catch(
				() => undefined,
			);
		}
	}
}

// ---------------------------------------------------------------- download

export type FetchLike = (
	url: string,
	init: { signal: AbortSignal },
) => Promise<{
	ok: boolean;
	status: number;
	arrayBuffer(): Promise<ArrayBuffer>;
}>;

export interface InstallOptions {
	/** Directory where the binary is left (created if missing). */
	readonly destDir: string;
	readonly platform?: NodeJS.Platform;
	readonly arch?: string;
	readonly fetch?: FetchLike;
	readonly timeoutMs?: number;
	/** Extracts `member` from `archive` into `destDir`. */
	readonly extract?: (
		archive: string,
		member: string,
		destDir: string,
	) => Promise<void>;
}

const RELEASE_BASE = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}`;

export function assetName(platform: string, arch: string): string {
	const os =
		platform === "linux"
			? "linux"
			: platform === "darwin"
				? "darwin"
				: platform === "win32"
					? "windows"
					: null;
	const cpu = arch === "x64" ? "x64" : arch === "arm64" ? "arm64" : null;
	if (os === null || cpu === null) {
		throw unavailable(
			"plataforma",
			"No hay binario oficial de gitleaks para esta plataforma",
			{ plataforma: platform, arquitectura: arch },
		);
	}
	const ext = os === "windows" ? "zip" : "tar.gz";
	return `gitleaks_${GITLEAKS_VERSION}_${os}_${cpu}.${ext}`;
}

/** Finds the SHA-256 of `name` in a `checksums.txt` body. */
export function checksumFor(checksums: string, name: string): string | null {
	for (const line of checksums.split(/\r?\n/)) {
		const m = /^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$/.exec(line);
		if (m && m[2] === name) return (m[1] ?? "").toLowerCase();
	}
	return null;
}

/**
 * `tar` command. On Windows an absolute `System32/tar.exe`: a bare `tar` is
 * resolved through cwd/PATH and could run a planted binary (SEG-106).
 */
export function tarCommand(
	platform: NodeJS.Platform,
	env: NodeJS.ProcessEnv,
): string {
	if (platform !== "win32") return "tar";
	const root = env.SystemRoot ?? env.windir ?? "C:\\Windows";
	return win32.join(root, "System32", "tar.exe");
}

const defaultExtract: NonNullable<InstallOptions["extract"]> = (
	archive,
	member,
	destDir,
) =>
	new Promise<void>((resolvePromise, reject) => {
		// bsdtar (Windows 10+, macOS) and GNU tar both read the formats we need.
		const child = spawn(
			tarCommand(process.platform, process.env),
			["-xf", archive, "-C", destDir, member],
			{
				stdio: "ignore",
				windowsHide: true,
				shell: false,
			},
		);
		child.on("error", reject);
		child.on("close", (code) =>
			code === 0 ? resolvePromise() : reject(new Error(`tar exit ${code}`)),
		);
	});

async function download(
	fetchFn: FetchLike,
	url: string,
	signal: AbortSignal,
): Promise<Buffer> {
	// The deadline covers headers and body, even if `fetchFn` ignores the signal.
	const aborted = new Promise<never>((_, reject) => {
		if (signal.aborted) reject(new Error("aborted"));
		signal.addEventListener("abort", () => reject(new Error("aborted")), {
			once: true,
		});
	});
	const work = (async (): Promise<Buffer> => {
		const response = await fetchFn(url, { signal });
		if (!response.ok) {
			throw unavailable("descarga-http", "La descarga de gitleaks falló", {
				estado: response.status,
			});
		}
		return Buffer.from(await response.arrayBuffer());
	})();
	work.catch(() => undefined);
	const buffer = await Promise.race([work, aborted]);
	if (buffer.length > MAX_DOWNLOAD_BYTES) {
		throw unavailable(
			"descarga-grande",
			"La descarga de gitleaks es demasiado grande",
		);
	}
	return buffer;
}

/**
 * Downloads the official pinned release, verifies its SHA-256 against the
 * release `checksums.txt` and extracts the binary. On any failure the
 * download is deleted. Returns the binary path.
 */
export async function installGitleaks(
	options: InstallOptions,
): Promise<string> {
	const platform = options.platform ?? process.platform;
	const name = assetName(platform, options.arch ?? process.arch);
	const fetchFn: FetchLike =
		options.fetch ?? ((url, init) => fetch(url, { signal: init.signal }));
	const extract = options.extract ?? defaultExtract;
	const timeoutMs = options.timeoutMs ?? GITLEAKS_DOWNLOAD_TIMEOUT_MS;
	const destDir = resolve(options.destDir);
	const member = platform === "win32" ? "gitleaks.exe" : "gitleaks";
	await mkdir(destDir, { recursive: true, mode: 0o700 });
	const archivePath = join(
		destDir,
		`${name}.${randomBytes(4).toString("hex")}.download`,
	);

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		let archive: Buffer;
		let checksums: Buffer;
		try {
			checksums = await download(
				fetchFn,
				`${RELEASE_BASE}/gitleaks_${GITLEAKS_VERSION}_checksums.txt`,
				controller.signal,
			);
			archive = await download(
				fetchFn,
				`${RELEASE_BASE}/${name}`,
				controller.signal,
			);
		} catch (error) {
			if (error instanceof MctError) throw error;
			throw unavailable(
				controller.signal.aborted ? "timeout" : "descarga",
				controller.signal.aborted
					? "La descarga de gitleaks superó el tiempo máximo"
					: "La descarga de gitleaks falló",
				controller.signal.aborted
					? { segundos: Math.round(timeoutMs / 1000) }
					: {},
				error,
			);
		}
		const expected = checksumFor(checksums.toString("utf8"), name);
		const actual = createHash("sha256").update(archive).digest("hex");
		if (expected === null || expected !== actual) {
			throw unavailable(
				"checksum",
				"El SHA-256 de la descarga no coincide con checksums.txt",
				{ archivo: name },
			);
		}
		await writeFile(archivePath, archive, { mode: 0o600 });
		try {
			await extract(archivePath, member, destDir);
		} catch (error) {
			throw unavailable("extraccion", "No se pudo extraer gitleaks", {}, error);
		}
		const binary = join(destDir, member);
		await chmod(binary, 0o755).catch(() => undefined);
		return binary;
	} finally {
		clearTimeout(timer);
		await rm(archivePath, { force: true }).catch(() => undefined);
	}
}
