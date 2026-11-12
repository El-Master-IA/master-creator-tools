import { randomBytes } from "node:crypto";
import {
	chmod,
	copyFile,
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, sep } from "node:path";
import { MctError } from "@mct/contract/errors";
import {
	type Runner,
	type RunResult,
	resolveExecutable,
	spawnRunner,
} from "./clone.js";

/** TMO-003: the SSH connection to the remote Docker host is cut at 15 s. */
export const SSH_TIMEOUT_MS = 15_000;

/** Probe commands only print a version; keep them short. */
const PROBE_TIMEOUT_MS = 30_000;
/** Where `docker cp` lands dist (root-owned). The install copies it to APP_DIR as uid 1000. */
const DIST_DIR = "/tmp/dist";
const APP_DIR = "/tmp/app";
const WORKDIR = "/tmp";
const ALIAS_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const IMAGE_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$/;
/** Env the Docker and ssh clients need; the rest of the host env never reaches a child. */
const ENV_ALLOW = [
	"PATH",
	"Path",
	"SystemRoot",
	"HOME",
	"USERPROFILE",
	"APPDATA",
	"LOCALAPPDATA",
	"TEMP",
	"TMP",
	"TMPDIR",
	"LANG",
	"SSH_AUTH_SOCK",
	"DOCKER_CONFIG",
	"DOCKER_HOST",
	"DOCKER_CONTEXT",
	"DOCKER_TLS_VERIFY",
	"DOCKER_CERT_PATH",
	"XDG_RUNTIME_DIR",
] as const;

export type DockerLang = "es" | "en";

export interface SandboxLimits {
	memory: string;
	cpus: string;
	pids: number;
}

/** VER-001 / seguridad.md: CPU, memory and pids caps for every verify container. */
export const DEFAULT_LIMITS: SandboxLimits = {
	memory: "1g",
	cpus: "2",
	pids: 512,
};

export type DockerTarget =
	| { kind: "local"; dockerPath: string; env: Record<string, string> }
	| {
			kind: "remote";
			alias: string;
			dockerPath: string;
			/** The ssh the Docker client runs; the sandbox wraps it to force strict host keys. */
			sshPath: string;
			env: Record<string, string>;
	  };

export interface DockerHooks {
	run?: Runner;
	/** Test hook: can only shorten the 15 s SSH limit. */
	sshTimeoutMs?: number;
	dockerPath?: string;
	sshPath?: string;
}

export interface ResolveOptions extends DockerHooks {
	/** `--remote <alias>`: explicit, never falls back to local Docker. */
	remote?: string;
	/** `--local`: local Docker only. */
	local?: boolean;
	/** `verify.remoto` from mct.config.json: falls back to local Docker on no answer. */
	configRemote?: string;
	env?: Record<string, string | undefined>;
	lang?: DockerLang;
}

const MSG = {
	es: {
		sinDocker: "No hay Docker local ni remoto disponible.",
		accionSinDocker:
			"Instala Docker, o configura verify.remoto con un alias de ~/.ssh/config.",
		alias: "El alias SSH no es válido.",
		accionAlias: "Usa un alias de ~/.ssh/config (letras, números, . _ -).",
		flags: "--remote y --local no se pueden combinar.",
		accionFlags: "Elige uno solo.",
		timeout: "El host remoto no respondió en 15 s.",
		accionTimeout: "Revisa la red o el alias, o usa --local.",
		denegado: "El host remoto rechazó la conexión SSH (permiso denegado).",
		accionDenegado: "Revisa tu llave SSH y el usuario del alias.",
		desconocido: "El host SSH es desconocido; no se aceptó su clave.",
		accionDesconocido:
			"Verifica la huella del host y añádelo a known_hosts a mano.",
		cambiada: "La clave del host SSH cambió; no se aceptó.",
		accionCambiada:
			"Si el cambio es legítimo, actualiza known_hosts a mano; si no, no conectes.",
		sshError: "No se pudo conectar por SSH al host remoto.",
		accionSshError: "Revisa el alias en ~/.ssh/config y la conexión.",
		sinSsh: "No se encontró ssh en el PATH.",
		accionSsh: "Instala un cliente OpenSSH.",
		imagen: "El nombre de la imagen no es válido.",
		accionImagen: "Revisa la imagen del adaptador.",
		dist: "dist/ debe ser una carpeta real, sin enlaces.",
		accionDist: "Corre package de nuevo.",
		interrumpido: "La operación de Docker se canceló.",
		puerto: "El puerto del healthcheck no es válido.",
	},
	en: {
		sinDocker: "No local or remote Docker is available.",
		accionSinDocker:
			"Install Docker, or set verify.remoto to an alias from ~/.ssh/config.",
		alias: "The SSH alias is not valid.",
		accionAlias: "Use an alias from ~/.ssh/config (letters, digits, . _ -).",
		flags: "--remote and --local cannot be combined.",
		accionFlags: "Pick one.",
		timeout: "The remote host did not answer in 15 s.",
		accionTimeout: "Check the network or the alias, or use --local.",
		denegado:
			"The remote host rejected the SSH connection (permission denied).",
		accionDenegado: "Check your SSH key and the alias user.",
		desconocido: "The SSH host is unknown; its key was not accepted.",
		accionDesconocido:
			"Verify the host fingerprint and add it to known_hosts by hand.",
		cambiada: "The SSH host key changed; it was not accepted.",
		accionCambiada:
			"If the change is legitimate, update known_hosts by hand; if not, do not connect.",
		sshError: "Could not connect to the remote host over SSH.",
		accionSshError: "Check the alias in ~/.ssh/config and the connection.",
		sinSsh: "ssh was not found on PATH.",
		accionSsh: "Install an OpenSSH client.",
		imagen: "The image name is not valid.",
		accionImagen: "Check the adapter image.",
		dist: "dist/ must be a real folder, without links.",
		accionDist: "Run package again.",
		interrumpido: "The Docker operation was cancelled.",
		puerto: "The healthcheck port is not valid.",
	},
} as const;

function childEnv(
	env: Record<string, string | undefined>,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const key of ENV_ALLOW) {
		const v = env[key];
		if (v !== undefined) out[key] = v;
	}
	return out;
}

function noDocker(
	lang: DockerLang,
	motivo: string,
	extra?: { mensaje: string; accion: string },
): MctError {
	const m = MSG[lang];
	return new MctError("DOCKER_NO_DISPONIBLE", extra?.mensaje ?? m.sinDocker, {
		etapa: "verify",
		accion: extra?.accion ?? m.accionSinDocker,
		detalle: { motivo },
	});
}

/** Runs one command with a deadline; resolves `"timeout"` when it did not finish in time. */
async function runBounded(
	run: Runner,
	file: string,
	args: readonly string[],
	env: Record<string, string>,
	limitMs: number,
): Promise<RunResult | "timeout" | "error"> {
	const controller = new AbortController();
	let timer: NodeJS.Timeout | undefined;
	let timedOut = false;
	const deadline = new Promise<"timeout">((resolve) => {
		timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
			resolve("timeout");
		}, limitMs);
	});
	const running = run(file, args, {
		env,
		cwd: process.cwd(),
		signal: controller.signal,
	});
	running.catch(() => undefined);
	try {
		return await Promise.race([running, deadline]);
	} catch {
		return timedOut ? "timeout" : "error";
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

type SshVerdict =
	| { ok: true }
	| { ok: false; motivo: "ssh-timeout" | "ssh-denegado" | "ssh-error" }
	| { ok: false; hostkey: "host-desconocido" | "clave-cambiada" };

function classifySsh(result: RunResult): SshVerdict {
	if (result.code === 0) return { ok: true };
	const text = `${result.stderr}\n${result.stdout}`;
	if (/REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(text)) {
		return { ok: false, hostkey: "clave-cambiada" };
	}
	if (
		/Host key verification failed/i.test(text) ||
		/host key is known/i.test(text)
	) {
		return { ok: false, hostkey: "host-desconocido" };
	}
	if (/Permission denied/i.test(text)) {
		return { ok: false, motivo: "ssh-denegado" };
	}
	if (/timed out/i.test(text)) return { ok: false, motivo: "ssh-timeout" };
	return { ok: false, motivo: "ssh-error" };
}

/** VER-006: ssh argv for the remote probe. Never accepts a new or changed key. */
export function sshProbeArgs(alias: string): string[] {
	return [
		"-o",
		"StrictHostKeyChecking=yes",
		"-o",
		"BatchMode=yes",
		"-o",
		`ConnectTimeout=${SSH_TIMEOUT_MS / 1000}`,
		"--",
		alias,
		"docker",
		"version",
		"--format",
		"{{.Server.Version}}",
	];
}

async function probeLocal(
	run: Runner,
	dockerPath: string,
	env: Record<string, string>,
): Promise<boolean> {
	const out = await runBounded(
		run,
		dockerPath,
		["version", "--format", "{{.Server.Version}}"],
		env,
		PROBE_TIMEOUT_MS,
	);
	return typeof out === "object" && out.code === 0;
}

/**
 * VER-003, VER-006, TMO-003. Picks the Docker the sandbox will use.
 * Remote: ssh with StrictHostKeyChecking=yes; an explicit `--remote` never falls back to local.
 */
export async function resolveDocker(
	options: ResolveOptions = {},
): Promise<DockerTarget> {
	const lang = options.lang ?? "es";
	const m = MSG[lang];
	const run = options.run ?? spawnRunner;
	const hostEnv = options.env ?? process.env;
	const env = childEnv(hostEnv);
	if (options.remote !== undefined && options.local === true) {
		throw new MctError("VALIDACION", m.flags, {
			etapa: "verify",
			accion: m.accionFlags,
		});
	}
	const explicit = options.remote;
	const alias =
		options.local === true ? undefined : (explicit ?? options.configRemote);
	if (alias !== undefined && !ALIAS_SHAPE.test(alias)) {
		throw new MctError("VALIDACION", m.alias, {
			etapa: "verify",
			accion: m.accionAlias,
		});
	}
	const limit = Math.min(
		options.sshTimeoutMs ?? SSH_TIMEOUT_MS,
		SSH_TIMEOUT_MS,
	);
	const dockerPath =
		options.dockerPath ?? (await resolveExecutable("docker", hostEnv));

	const local = async (): Promise<DockerTarget> => {
		if (dockerPath !== null && (await probeLocal(run, dockerPath, env))) {
			return { kind: "local", dockerPath, env };
		}
		throw noDocker(lang, "sin-docker");
	};

	if (alias === undefined) return local();

	const ssh = options.sshPath ?? (await resolveExecutable("ssh", hostEnv));
	if (ssh === null) {
		// TMO-003: a missing ssh is an SSH failure; only a configured alias falls back to local.
		if (explicit === undefined) return local();
		throw noDocker(lang, "sin-ssh", {
			mensaje: m.sinSsh,
			accion: m.accionSsh,
		});
	}
	if (dockerPath === null) throw noDocker(lang, "sin-docker");
	const out = await runBounded(run, ssh, sshProbeArgs(alias), env, limit);
	let verdict: SshVerdict;
	if (out === "timeout") verdict = { ok: false, motivo: "ssh-timeout" };
	else if (out === "error") verdict = { ok: false, motivo: "ssh-error" };
	else verdict = classifySsh(out);

	if (verdict.ok) {
		return {
			kind: "remote",
			alias,
			dockerPath,
			sshPath: ssh,
			env: { ...env, DOCKER_HOST: `ssh://${alias}` },
		};
	}
	if ("hostkey" in verdict) {
		const changed = verdict.hostkey === "clave-cambiada";
		throw new MctError("VALIDACION", changed ? m.cambiada : m.desconocido, {
			etapa: "verify",
			accion: changed ? m.accionCambiada : m.accionDesconocido,
			detalle: { motivo: verdict.hostkey },
		});
	}
	if (verdict.motivo === "ssh-denegado") {
		throw noDocker(lang, "ssh-denegado", {
			mensaje: m.denegado,
			accion: m.accionDenegado,
		});
	}
	// TMO-003: only a configured alias falls back to local Docker; `--remote` never does.
	if (explicit === undefined) return local();
	const timeout = verdict.motivo === "ssh-timeout";
	throw noDocker(lang, verdict.motivo, {
		mensaje: timeout ? m.timeout : m.sshError,
		accion: timeout ? m.accionTimeout : m.accionSshError,
	});
}

/** VER-006: options the Docker client's own ssh must carry (it does not use the probe argv). */
export const STRICT_SSH_OPTIONS = [
	"-o",
	"StrictHostKeyChecking=yes",
	"-o",
	"BatchMode=yes",
	"-o",
	`ConnectTimeout=${SSH_TIMEOUT_MS / 1000}`,
] as const;

/** Content of the ephemeral `ssh` wrapper that injects STRICT_SSH_OPTIONS before Docker's argv. */
export function sshWrapperScript(sshPath: string, windows: boolean): string {
	const opts = STRICT_SSH_OPTIONS.join(" ");
	if (windows) {
		if (/["%\r\n]/.test(sshPath)) {
			throw new MctError("INTERNO", MSG.en.sinSsh, { etapa: "verify" });
		}
		return `@"${sshPath}" ${opts} %*\r\n`;
	}
	const quoted = `'${sshPath.replaceAll("'", String.raw`'\''`)}'`;
	return `#!/bin/sh\nexec ${quoted} ${opts} "$@"\n`;
}

/**
 * For a remote target, builds an env whose PATH starts with a private dir holding an `ssh` wrapper,
 * so every ssh the Docker client spawns checks host keys strictly. Local targets pass through.
 */
async function strictSshEnv(
	target: DockerTarget,
): Promise<{ env: Record<string, string>; dispose: () => Promise<void> }> {
	if (target.kind !== "remote") {
		return { env: target.env, dispose: async () => undefined };
	}
	const windows = process.platform === "win32";
	const dir = await mkdtemp(join(tmpdir(), "mct-ssh-"));
	const dispose = (): Promise<void> =>
		rm(dir, { recursive: true, force: true }).catch(() => undefined);
	try {
		const file = join(dir, windows ? "ssh.cmd" : "ssh");
		await writeFile(file, sshWrapperScript(target.sshPath, windows), {
			mode: 0o700,
		});
		const key =
			"Path" in target.env && !("PATH" in target.env) ? "Path" : "PATH";
		const current = target.env[key];
		const env = {
			...target.env,
			[key]: current ? `${dir}${delimiter}${current}` : dir,
		};
		return { env, dispose };
	} catch (e) {
		await dispose();
		throw e;
	}
}

/** The flags shared by every sandbox container: non root, no caps, no privilege gain, capped. */
export function sandboxFlags(limits: SandboxLimits = DEFAULT_LIMITS): string[] {
	return [
		"--user",
		"1000:1000",
		"--cap-drop=ALL",
		"--security-opt",
		"no-new-privileges",
		"--memory",
		limits.memory,
		"--cpus",
		limits.cpus,
		"--pids-limit",
		String(limits.pids),
		"--workdir",
		WORKDIR,
		"--env",
		"HOME=/tmp",
	];
}

/** VER-001: install phase. Has network (to fetch dependencies); dist arrives later by `docker cp`. */
export function installCreateArgs(
	name: string,
	image: string,
	command: string,
	limits: SandboxLimits = DEFAULT_LIMITS,
): string[] {
	return [
		"create",
		"--name",
		name,
		...sandboxFlags(limits),
		"--entrypoint",
		"sh",
		image,
		"-c",
		`mkdir -p ${APP_DIR} && cp -R ${DIST_DIR}/. ${APP_DIR} && cd ${APP_DIR} && ${command}`,
	];
}

/**
 * VER-001: start and healthcheck phase. Always `--network none`.
 * `detach` (VER-005 http healthcheck) starts it in the background and keeps it after it exits, so
 * its exit code can be read with `docker inspect`; the caller removes it.
 */
export function startRunArgs(
	name: string,
	image: string,
	command: string,
	limits: SandboxLimits = DEFAULT_LIMITS,
	detach = false,
): string[] {
	return [
		"run",
		...(detach ? ["--detach"] : ["--rm"]),
		"--name",
		name,
		"--network",
		"none",
		...sandboxFlags(limits),
		"--entrypoint",
		"sh",
		image,
		"-c",
		`cd ${APP_DIR} && ${command}`,
	];
}

export interface SandboxOptions {
	target: DockerTarget;
	image: string;
	/** Absolute path of `dist/`. */
	distDir: string;
	installCommand: string;
	startCommand: string;
	limits?: SandboxLimits;
	run?: Runner;
	signal?: AbortSignal;
	lang?: DockerLang;
	/**
	 * VER-005: the start command is a server. Instead of waiting for it to exit, the container runs
	 * in the background (still `--network none`) and `GET http://127.0.0.1:<port>/` is tried from
	 * inside it with `docker exec` until it answers 2xx or the container exits.
	 */
	http?: { port: number; intervalMs?: number };
}

/** Request made inside the container; exit 0 only for a 2xx (redirects are not followed). */
export function httpProbeScript(port: number): string {
	return `fetch("http://127.0.0.1:${port}/",{redirect:"manual",signal:AbortSignal.timeout(2000)}).then(r=>process.exit(r.status>=200&&r.status<300?0:1),()=>process.exit(1))`;
}

/**
 * VER-001: copies `src` to `dest` with daemon-independent modes (dirs 0755, files 0644, keeping the
 * exec bit as 0755). Ownership is not carried, so no `docker cp --archive` (which breaks on daemons
 * that read `--user uid:gid` as a user name) is needed and uid 1000 can read everything. Fail closed:
 * links and special files are refused.
 */
export async function normalizeDistCopy(
	src: string,
	dest: string,
	onBad: () => MctError,
): Promise<void> {
	await mkdir(dest, { recursive: true });
	await chmod(dest, 0o755);
	for (const entry of await readdir(src, { withFileTypes: true })) {
		const from = join(src, entry.name);
		const to = join(dest, entry.name);
		const st = await lstat(from);
		if (st.isSymbolicLink()) throw onBad();
		if (st.isDirectory()) {
			await normalizeDistCopy(from, to, onBad);
		} else if (st.isFile()) {
			await copyFile(from, to);
			await chmod(to, (st.mode & 0o111) !== 0 ? 0o755 : 0o644);
		} else {
			throw onBad();
		}
	}
}

export interface SandboxResult {
	install: RunResult;
	start: RunResult | null;
	/** How the start phase ended: the command exited, or the http probe got a 2xx. */
	via?: "salida" | "http";
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		if (signal.aborted) {
			resolve();
			return;
		}
		const done = (): void => {
			clearTimeout(timer);
			signal.removeEventListener("abort", done);
			resolve();
		};
		const timer = setTimeout(done, ms);
		signal.addEventListener("abort", done, { once: true });
	});
}

/**
 * VER-001. Installs `dist/` in a clean container (with network), commits that state and runs the
 * start command from it with `--network none`. `dist/` enters with `docker cp`, never a bind mount,
 * so it also works with a remote Docker. Containers and the image are removed at the end.
 */
export async function runSandbox(
	options: SandboxOptions,
): Promise<SandboxResult> {
	const lang = options.lang ?? "es";
	const m = MSG[lang];
	if (!IMAGE_SHAPE.test(options.image)) {
		throw new MctError("VALIDACION", m.imagen, {
			etapa: "verify",
			accion: m.accionImagen,
		});
	}
	const hp = options.http?.port;
	if (hp !== undefined && (!Number.isInteger(hp) || hp < 1 || hp > 65_535)) {
		throw new MctError("VALIDACION", m.puerto, {
			etapa: "verify",
			accion: m.accionImagen,
		});
	}
	const st = isAbsolute(options.distDir)
		? await lstat(options.distDir).catch(() => null)
		: null;
	if (st === null || st.isSymbolicLink() || !st.isDirectory()) {
		throw new MctError("VALIDACION", m.dist, {
			etapa: "verify",
			accion: m.accionDist,
		});
	}
	const run = options.run ?? spawnRunner;
	const { target } = options;
	const limits = options.limits ?? DEFAULT_LIMITS;
	const id = randomBytes(6).toString("hex");
	const installName = `mct-install-${id}`;
	const startName = `mct-start-${id}`;
	const stateImage = `mct-verify-state:${id}`;
	const signal = options.signal ?? new AbortController().signal;
	const strict = await strictSshEnv(target);
	const dockerEnv = strict.env;
	const docker = (args: string[]): Promise<RunResult> =>
		run(target.dockerPath, args, {
			env: dockerEnv,
			cwd: process.cwd(),
			signal,
		});
	const must = async (args: string[]): Promise<void> => {
		const r = await docker(args);
		if (r.code !== 0) {
			throw new MctError("DOCKER_NO_DISPONIBLE", m.sinDocker, {
				etapa: "verify",
				accion: m.accionSinDocker,
				detalle: { motivo: "docker-fallo", paso: args[0] ?? "" },
			});
		}
	};

	let stageParent: string | null = null;
	try {
		// The copy is 0755 so uid 1000 can read it in the container; its private parent (mkdtemp, 0700)
		// keeps other local users out of a dist that may still be under review.
		stageParent = await mkdtemp(join(tmpdir(), "mct-dist-"));
		await chmod(stageParent, 0o700);
		const stage = join(stageParent, "dist");
		await normalizeDistCopy(
			options.distDir,
			stage,
			() =>
				new MctError("VALIDACION", m.dist, {
					etapa: "verify",
					accion: m.accionDist,
				}),
		);
		await must(
			installCreateArgs(
				installName,
				options.image,
				options.installCommand,
				limits,
			),
		);
		await must(["cp", `${stage}${sep}.`, `${installName}:${DIST_DIR}`]);
		const install = await docker(["start", "--attach", installName]);
		if (install.code !== 0) return { install, start: null };
		await must(["commit", installName, stateImage]);
		if (options.http === undefined) {
			const start = await docker(
				startRunArgs(startName, stateImage, options.startCommand, limits),
			);
			return { install, start, via: "salida" };
		}
		const { port, intervalMs = 1_500 } = options.http;
		await must(
			startRunArgs(startName, stateImage, options.startCommand, limits, true),
		);
		const probe = ["exec", startName, "node", "-e", httpProbeScript(port)];
		const state = [
			"inspect",
			"--format",
			"{{.State.Status}} {{.State.ExitCode}}",
		];
		while (!signal.aborted) {
			const seen = await docker([...state, startName]);
			const [status, exit] = seen.stdout.trim().split(" ");
			if (seen.code === 0 && (status === "exited" || status === "dead")) {
				const code = Number.parseInt(exit ?? "", 10);
				return {
					install,
					start: {
						code: Number.isNaN(code) ? 1 : code,
						stdout: "",
						stderr: "",
					},
					via: "salida",
				};
			}
			const answer = await docker(probe);
			if (answer.code === 0 && !signal.aborted) {
				return {
					install,
					start: { code: 0, stdout: "", stderr: "" },
					via: "http",
				};
			}
			await sleep(intervalMs, signal);
		}
		// Aborted: the catch below turns it into INTERRUMPIDO.
		throw new MctError("INTERRUMPIDO", m.interrumpido, { etapa: "verify" });
	} catch (e) {
		if (signal.aborted) {
			throw new MctError("INTERRUMPIDO", m.interrumpido, { etapa: "verify" });
		}
		throw e;
	} finally {
		const quiet = new AbortController().signal;
		const clean = (args: string[]): Promise<unknown> =>
			run(target.dockerPath, args, {
				env: dockerEnv,
				cwd: process.cwd(),
				signal: quiet,
			}).catch(() => undefined);
		await clean(["rm", "--force", installName]);
		await clean(["rm", "--force", startName]);
		// Always: a commit cut short by Ctrl+C may still finish on the daemon.
		await clean(["rmi", "--force", stateImage]);
		await strict.dispose();
		if (stageParent !== null) {
			await rm(stageParent, { recursive: true, force: true }).catch(
				() => undefined,
			);
		}
	}
}
