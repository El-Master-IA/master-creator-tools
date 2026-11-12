import { spawn } from "node:child_process";
import { lstat, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, win32 } from "node:path";
import { MctError, redactTokens } from "@mct/contract/errors";

/** TMO-001: a GitHub clone is cut at 120 s. */
export const CLONE_TIMEOUT_MS = 120_000;

const MAX_OUTPUT = 64 * 1024;
const MAX_DETAIL = 500;
const TOKEN_ENV = "MCT_GIT_TOKEN";
/** Characters a GitHub token can have; anything else is refused before it reaches a script or env. */
const TOKEN_SHAPE = /^[A-Za-z0-9_.-]{8,512}$/;
const GITHUB_URL =
	/^https:\/\/github\.com\/([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100})\/?$/;
/** Env that git and gh need to work; nothing else from the parent leaks into the child. */
const ENV_ALLOW = [
	"PATH",
	"Path",
	"SystemRoot",
	"HOME",
	"USERPROFILE",
	"APPDATA",
	"LOCALAPPDATA",
	"XDG_CONFIG_HOME",
	"GH_CONFIG_DIR",
	"TEMP",
	"TMP",
	"TMPDIR",
	"LANG",
] as const;

export type CloneLang = "es" | "en";

export interface RunResult {
	code: number | null;
	stdout: string;
	stderr: string;
}

export interface RunOptions {
	env: Record<string, string>;
	cwd: string;
	signal: AbortSignal;
}

/** Runs an executable by absolute path with an argv array (never a shell). */
export type Runner = (
	file: string,
	args: readonly string[],
	options: RunOptions,
) => Promise<RunResult>;

export interface CloneHooks {
	run?: Runner;
	/** Test hook: can only shorten the 120 s limit. */
	timeoutMs?: number;
	/** Max wait for the child to die after a timeout, before deleting the copy. */
	graceMs?: number;
	gitPath?: string;
	ghPath?: string;
}

export interface CloneOptions extends CloneHooks {
	url: string;
	/** Folder to create; it must not exist. */
	dir: string;
	env?: Record<string, string | undefined>;
	lang?: CloneLang;
	/** Ctrl+C: kills the running git/gh process tree. */
	signal?: AbortSignal;
}

export interface GithubRef {
	owner: string;
	repo: string;
	/** Canonical URL: no credentials, query or trailing slash. */
	url: string;
}

const MSG = {
	es: {
		url: "El origen debe ser https://github.com/<owner>/<repo>.",
		accionUrl: "Usa una URL https de GitHub sin credenciales ni parámetros.",
		token: "La credencial de GitHub tiene un formato no válido.",
		accionToken: "Revisa GITHUB_TOKEN o GH_TOKEN.",
		timeout:
			"El clon superó los 120 s y se canceló; la copia parcial se borró.",
		timeoutResiduo:
			"El clon superó los 120 s y se canceló, pero la copia parcial no se pudo borrar por completo; bórrala a mano.",
		accionTimeout:
			"Reintenta con mejor conexión o clona a mano y usa la carpeta.",
		fallo:
			"No se pudo clonar el repo (no existe, es privado sin credencial o no hay red).",
		accionFallo:
			"Revisa la URL y, si es privado, define GITHUB_TOKEN o inicia sesión con gh.",
		sinGit: "No se encontró git en el PATH.",
		accionGit: "Instala git y vuelve a correr init.",
	},
	en: {
		url: "The source must be https://github.com/<owner>/<repo>.",
		accionUrl: "Use an https GitHub URL without credentials or parameters.",
		token: "The GitHub credential has an invalid format.",
		accionToken: "Check GITHUB_TOKEN or GH_TOKEN.",
		timeout:
			"The clone exceeded 120 s and was cancelled; the partial copy was deleted.",
		timeoutResiduo:
			"The clone exceeded 120 s and was cancelled, but the partial copy could not be fully deleted; delete it by hand.",
		accionTimeout:
			"Retry with a better connection or clone by hand and use the folder.",
		fallo:
			"The repo could not be cloned (missing, private without credential, or no network).",
		accionFallo:
			"Check the URL and, if it is private, set GITHUB_TOKEN or sign in with gh.",
		sinGit: "git was not found on PATH.",
		accionGit: "Install git and run init again.",
	},
} as const;

/** True when the text looks like a URL (has a scheme) or an scp-style git address. */
export function looksLikeUrl(origen: string): boolean {
	return /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(origen) || /^git@/i.test(origen);
}

function bad(mensaje: string, accion: string): MctError {
	return new MctError("VALIDACION", mensaje, { etapa: "init", accion });
}

/** CLI-002: only https://github.com/<owner>/<repo>. Anything else is VALIDACION. */
export function parseGithubUrl(url: string, lang: CloneLang = "es"): GithubRef {
	const m = MSG[lang];
	const hit = url.length > 300 ? null : GITHUB_URL.exec(url);
	if (hit === null) throw bad(m.url, m.accionUrl);
	const owner = hit[1] as string;
	const repo = (hit[2] as string).replace(/\.git$/, "");
	if (repo === "" || repo === "." || repo === "..") {
		throw bad(m.url, m.accionUrl);
	}
	return { owner, repo, url: `https://github.com/${owner}/${repo}` };
}

function envValue(
	env: Record<string, string | undefined>,
	key: string,
): string | undefined {
	const found = Object.keys(env).find(
		(k) => k.toLowerCase() === key.toLowerCase(),
	);
	return found === undefined ? undefined : env[found];
}

/** Absolute path of an executable on PATH (never a bare name, never a relative PATH entry). */
export async function resolveExecutable(
	name: string,
	env: Record<string, string | undefined>,
): Promise<string | null> {
	const path = envValue(env, "PATH");
	if (path === undefined) return null;
	const names =
		process.platform === "win32" ? [`${name}.exe`, `${name}.cmd`] : [name];
	for (const dir of path.split(delimiter)) {
		if (dir === "" || !isAbsolute(dir)) continue;
		for (const n of names) {
			const candidate = join(dir, n);
			try {
				if ((await stat(candidate)).isFile()) return candidate;
			} catch {
				// not here
			}
		}
	}
	return null;
}

function childEnv(
	env: Record<string, string | undefined>,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const key of ENV_ALLOW) {
		const v = env[key];
		if (v !== undefined) out[key] = v;
	}
	out.GIT_TERMINAL_PROMPT = "0";
	out.GCM_INTERACTIVE = "never";
	out.GIT_LFS_SKIP_SMUDGE = "1";
	out.GIT_CONFIG_NOSYSTEM = "1";
	return out;
}

const HARDENING = [
	"core.hooksPath=/dev/null",
	"credential.helper=",
	"protocol.file.allow=never",
	"filter.lfs.smudge=",
	"filter.lfs.process=",
	"filter.lfs.required=false",
] as const;

const CLONE_FLAGS = [
	"--depth",
	"1",
	"--no-tags",
	"--single-branch",
	"--no-recurse-submodules",
] as const;

function gitArgs(ref: GithubRef, dir: string): string[] {
	return [
		...HARDENING.flatMap((c) => ["-c", c]),
		"clone",
		...CLONE_FLAGS,
		"--",
		ref.url,
		dir,
	];
}

function ghArgs(ref: GithubRef, dir: string): string[] {
	return [
		"repo",
		"clone",
		`${ref.owner}/${ref.repo}`,
		dir,
		"--",
		...HARDENING.flatMap((c) => ["-c", c]),
		...CLONE_FLAGS,
	];
}

/** TMO-001: after the abort, wait this long for the child to close before deleting. */
const KILL_GRACE_MS = 10_000;

/** Removes `dir` with retries; never throws. Returns true when it is gone. */
async function removeTree(dir: string): Promise<boolean> {
	try {
		await rm(dir, {
			recursive: true,
			force: true,
			maxRetries: 20,
			retryDelay: 250,
		});
	} catch {
		// verified below
	}
	return lstat(dir).then(
		() => false,
		() => true,
	);
}

/** Default runner: spawn without shell, bounded output, whole process tree killed on abort. */
export const spawnRunner: Runner = (file, args, options) =>
	new Promise<RunResult>((resolveRun, rejectRun) => {
		const child = spawn(file, [...args], {
			env: options.env,
			cwd: options.cwd,
			shell: false,
			windowsHide: true,
			detached: process.platform !== "win32",
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d: Buffer) => {
			if (stdout.length < MAX_OUTPUT) stdout += d.toString("utf8");
		});
		child.stderr.on("data", (d: Buffer) => {
			if (stderr.length < MAX_OUTPUT) stderr += d.toString("utf8");
		});
		const kill = (): void => {
			const pid = child.pid;
			const root = options.env.SystemRoot;
			if (
				process.platform === "win32" &&
				pid !== undefined &&
				root !== undefined &&
				win32.isAbsolute(root)
			) {
				const k = spawn(
					win32.join(root, "System32", "taskkill.exe"),
					["/PID", String(pid), "/T", "/F"],
					{ stdio: "ignore", windowsHide: true },
				);
				k.on("error", () => child.kill("SIGKILL"));
			} else {
				try {
					// POSIX: the child leads its own group; kill the whole group.
					if (pid === undefined || process.platform === "win32") {
						throw new Error("no group");
					}
					process.kill(-pid, "SIGKILL");
				} catch {
					child.kill("SIGKILL");
				}
			}
			// Orphans may keep the pipes open; do not let them hold `close` or the event loop.
			const release = setTimeout(() => {
				child.stdout.destroy();
				child.stderr.destroy();
			}, 1_000);
			release.unref();
		};
		if (options.signal.aborted) kill();
		options.signal.addEventListener("abort", kill, { once: true });
		child.on("error", (e) => rejectRun(e));
		child.on("close", (code) => {
			options.signal.removeEventListener("abort", kill);
			resolveRun({ code, stdout, stderr });
		});
	});

function scrub(text: string, token: string | undefined): string {
	let out = text;
	if (token !== undefined && token !== "") {
		out = out.split(token).join("[REDACTADO]");
	}
	return redactTokens(out).replace(/\s+/g, " ").trim().slice(0, MAX_DETAIL);
}

const ASKPASS_SCRIPT = [
	"#!/bin/sh",
	'case "$1" in',
	`  *sername*) printf '%s\\n' "x-access-token" ;;`,
	`  *) printf '%s\\n' "$${TOKEN_ENV}" ;;`,
	"esac",
	"",
].join("\n");

/**
 * CLI-002, CLI-009, TMO-001. Clones a GitHub repo into `dir` (shallow, no hooks, submodules or LFS),
 * removes `.git`, and deletes `dir` on any failure or timeout.
 */
export async function cloneGithub(options: CloneOptions): Promise<GithubRef> {
	const lang = options.lang ?? "es";
	const m = MSG[lang];
	const ref = parseGithubUrl(options.url, lang);
	const env = options.env ?? process.env;
	const limit = Math.min(
		options.timeoutMs ?? CLONE_TIMEOUT_MS,
		CLONE_TIMEOUT_MS,
	);
	const run = options.run ?? spawnRunner;

	const rawToken = envValue(env, "GITHUB_TOKEN") ?? envValue(env, "GH_TOKEN");
	const token =
		rawToken === undefined || rawToken === "" ? undefined : rawToken;
	if (token !== undefined && !TOKEN_SHAPE.test(token)) {
		throw bad(m.token, m.accionToken);
	}

	const git = options.gitPath ?? (await resolveExecutable("git", env));
	if (git === null) {
		throw new MctError("INTERNO", m.sinGit, {
			etapa: "init",
			accion: m.accionGit,
		});
	}

	let helperDir: string | undefined;
	const controller = new AbortController();
	if (options.signal?.aborted) controller.abort();
	options.signal?.addEventListener("abort", () => controller.abort(), {
		once: true,
	});
	let timer: NodeJS.Timeout | undefined;
	let timedOut = false;
	let pending: Promise<unknown> | undefined;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
			reject(new Error("timeout"));
		}, limit);
	});
	deadline.catch(() => undefined);

	const attempt = async (
		file: string,
		args: string[],
		extra: Record<string, string>,
	): Promise<RunResult> => {
		await rm(options.dir, { recursive: true, force: true });
		const running = run(file, args, {
			env: { ...childEnv(env), ...extra },
			cwd: tmpdir(),
			signal: controller.signal,
		});
		pending = running;
		running.catch(() => undefined);
		return Promise.race([running, deadline]);
	};

	try {
		let result: RunResult;
		if (token !== undefined) {
			// CLI-009: the helper only exists during the clone and never contains the token.
			helperDir = await mkdtemp(join(tmpdir(), "mct-askpass-"));
			const helper = join(helperDir, "askpass.sh");
			await writeFile(helper, ASKPASS_SCRIPT, { mode: 0o700 });
			result = await attempt(git, gitArgs(ref, options.dir), {
				GIT_ASKPASS: helper.replace(/\\/g, "/"),
				[TOKEN_ENV]: token,
			});
		} else {
			result = await attempt(git, gitArgs(ref, options.dir), {});
			if (result.code !== 0 && !controller.signal.aborted) {
				const gh = options.ghPath ?? (await resolveExecutable("gh", env));
				if (gh !== null) {
					result = await attempt(gh, ghArgs(ref, options.dir), {});
				}
			}
		}
		if (result.code !== 0) {
			throw new MctError("ORIGEN_NO_ENCONTRADO", m.fallo, {
				etapa: "init",
				accion: m.accionFallo,
				detalle: {
					motivo: "clon",
					salida: scrub(`${result.stderr} ${result.stdout}`, token),
				},
			});
		}
		await rm(join(options.dir, ".git"), { recursive: true, force: true });
		return ref;
	} catch (e) {
		if (timedOut && pending !== undefined) {
			// Let the killed tree release its files (bounded) before deleting.
			let graceTimer: NodeJS.Timeout | undefined;
			await Promise.race([
				pending.then(
					() => undefined,
					() => undefined,
				),
				new Promise<void>((r) => {
					graceTimer = setTimeout(r, options.graceMs ?? KILL_GRACE_MS);
				}),
			]);
			if (graceTimer !== undefined) clearTimeout(graceTimer);
		}
		const gone = await removeTree(options.dir);
		if (timedOut) {
			throw new MctError(
				"ORIGEN_NO_ENCONTRADO",
				gone ? m.timeout : m.timeoutResiduo,
				{
					etapa: "init",
					accion: m.accionTimeout,
					detalle: gone
						? { motivo: "timeout" }
						: { motivo: "timeout", residuo: "true" },
				},
			);
		}
		if (e instanceof MctError) throw e;
		throw new MctError("ORIGEN_NO_ENCONTRADO", m.fallo, {
			etapa: "init",
			accion: m.accionFallo,
			detalle: { motivo: "clon", salida: scrub(String(e), token) },
		});
	} finally {
		if (timer !== undefined) clearTimeout(timer);
		if (helperDir !== undefined) {
			await removeTree(helperDir);
		}
	}
}
