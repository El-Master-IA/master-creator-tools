import { homedir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { GITLEAKS_MAJOR, GITLEAKS_VERSION } from "@mct/contract/pins";
import {
	checkGitleaksVersion,
	defaultRunner,
	type InstallOptions,
	installGitleaks,
	type Runner,
} from "@mct/scanner/gitleaks";
import { resolveExecutable } from "./clone.js";
import {
	checkDictionaryPerms,
	defaultDictionaryPath,
	type Lang,
	type PermOptions,
} from "./init-guards.js";

/** TMO-003 (api.md): SSH to verify.remoto gets 15 s. */
export const SSH_TIMEOUT_MS = 15_000;
const DOCKER_TIMEOUT_MS = 15_000;

export type DoctorId = "gitleaks" | "docker" | "ssh" | "github" | "permisos";
export type DoctorState = "ok" | "aviso" | "falla";

export interface DoctorCheck {
	id: DoctorId;
	estado: DoctorState;
	mensaje: string;
	accion?: string;
}

export interface DoctorReport {
	checks: DoctorCheck[];
	siguiente: string;
}

type Env = Readonly<Record<string, string | undefined>>;

export interface DoctorOptions {
	home?: string;
	env?: Env;
	lang?: Lang;
	/** `verify.remoto` of mct.config.json: an SSH alias. */
	remoto?: string | undefined;
	/** mct.config.json could not be read: report it instead of running ssh. */
	configInvalid?: boolean;
	/** `--install-gitleaks`: the only thing doctor may change. */
	installGitleaks?: boolean;
	/** Test hooks. */
	run?: Runner;
	resolveExe?: (name: string, env: Env) => Promise<string | null>;
	install?: (options: InstallOptions) => Promise<string>;
	perms?: Partial<PermOptions>;
}

type ResolveExe = NonNullable<DoctorOptions["resolveExe"]>;

const ALIAS_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TOKEN_SHAPE = /^[A-Za-z0-9_.-]{8,512}$/;

/** Variables a child process (docker, ssh) may see. Never a credential of ours. */
const CHILD_ENV = [
	"PATH",
	"HOME",
	"USERPROFILE",
	"SystemRoot",
	"windir",
	"TEMP",
	"TMP",
	"APPDATA",
	"LOCALAPPDATA",
	"ProgramData",
	"SSH_AUTH_SOCK",
	"DOCKER_HOST",
	"DOCKER_CONFIG",
	"XDG_RUNTIME_DIR",
];

function lookup(env: Env, key: string): string | undefined {
	const found = Object.keys(env).find(
		(k) => k.toLowerCase() === key.toLowerCase(),
	);
	return found === undefined ? undefined : env[found];
}

function childEnv(env: Env): NodeJS.ProcessEnv {
	const out: NodeJS.ProcessEnv = {};
	for (const key of CHILD_ENV) {
		const value = lookup(env, key);
		if (value !== undefined) out[key] = value;
	}
	return out;
}

function nonEmpty(env: Env, key: string): string | undefined {
	const value = lookup(env, key);
	return value === undefined || value === "" ? undefined : value;
}

const T = {
	es: {
		glOk: (v: string) => `gitleaks ${v} instalado`,
		glFalla: "gitleaks no está instalado o no responde con la versión fijada",
		glInstall: "mct doctor --install-gitleaks",
		dockerOk: "Docker local responde",
		dockerNo: "No encuentro Docker en el PATH",
		dockerDown: "Docker está instalado pero el servicio no responde",
		dockerAccion: "Inicia Docker o instálalo; verify puede usar verify.remoto",
		sshNo: "sin remoto: verify.remoto no está configurado",
		sshOk: (a: string) => `SSH a ${a} responde`,
		dockerRemoto: (a: string) => ` (no hace falta: verify usará ${a})`,
		sshBad: (a: string) => `verify.remoto «${a}» no es un alias SSH válido`,
		sshFail: (a: string) => `SSH a ${a} no responde`,
		sshNoBin: "No encuentro ssh en el PATH",
		sshAccion: "Revisa tu clave y el alias en ~/.ssh/config",
		cfgBad: "mct.config.json no es válido; no se probó el remoto",
		cfgAccion: "revisa mct.config.json",
		ghOk: "credencial de GitHub presente",
		ghNo: "credencial de GitHub ausente",
		ghAccion:
			"Define GITHUB_TOKEN o ejecuta gh auth login (solo hace falta para publicar o clonar)",
		ghBad: "credencial de GitHub presente pero con formato no válido",
		ghBadAccion: "Revisa GITHUB_TOKEN o GH_TOKEN",
		permOk: "permisos de ~/.mct/sensible.txt correctos",
		permNo: "~/.mct/sensible.txt no existe (es opcional)",
		unknown: (id: string) => `No se pudo completar el chequeo ${id}`,
		init: "mct init <origen>",
		y: " y ",
		installFail: "No se pudo instalar gitleaks",
	},
	en: {
		glOk: (v: string) => `gitleaks ${v} installed`,
		glFalla:
			"gitleaks is not installed or does not answer with the pinned version",
		glInstall: "mct doctor --install-gitleaks",
		dockerOk: "Local Docker responds",
		dockerNo: "Docker not found on PATH",
		dockerDown: "Docker is installed but the service does not respond",
		dockerAccion: "Start or install Docker; verify can use verify.remoto",
		sshNo: "no remote: verify.remoto is not configured",
		sshOk: (a: string) => `SSH to ${a} responds`,
		dockerRemoto: (a: string) => ` (not needed: verify will use ${a})`,
		sshBad: (a: string) => `verify.remoto «${a}» is not a valid SSH alias`,
		sshFail: (a: string) => `SSH to ${a} does not respond`,
		sshNoBin: "ssh not found on PATH",
		sshAccion: "Check your key and the alias in ~/.ssh/config",
		cfgBad: "mct.config.json is not valid; the remote was not tested",
		cfgAccion: "check mct.config.json",
		ghOk: "GitHub credentials present",
		ghNo: "GitHub credentials absent",
		ghAccion:
			"Set GITHUB_TOKEN or run gh auth login (only needed to publish or clone)",
		ghBad: "GitHub credentials present but with an invalid format",
		ghBadAccion: "Check GITHUB_TOKEN or GH_TOKEN",
		permOk: "~/.mct/sensible.txt permissions are correct",
		permNo: "~/.mct/sensible.txt does not exist (it is optional)",
		unknown: (id: string) => `The ${id} check could not be completed`,
		init: "mct init <source>",
		y: " and ",
		installFail: "Could not install gitleaks",
	},
} as const;

function gitleaksPaths(home: string): { dir: string; binary: string } {
	const dir = join(home, ".mct", "bin");
	const name = process.platform === "win32" ? "gitleaks.exe" : "gitleaks";
	return { dir, binary: join(dir, name) };
}

async function checkGitleaks(
	home: string,
	lang: Lang,
	run: Runner,
): Promise<DoctorCheck> {
	const t = T[lang];
	try {
		const version = await checkGitleaksVersion(gitleaksPaths(home).binary, {
			run,
		});
		return { id: "gitleaks", estado: "ok", mensaje: t.glOk(version) };
	} catch (error) {
		if (error instanceof MctError) {
			return {
				id: "gitleaks",
				estado: "falla",
				mensaje: t.glFalla,
				accion: t.glInstall,
			};
		}
		throw error;
	}
}

async function checkDocker(
	lang: Lang,
	env: Env,
	run: Runner,
	resolveExe: ResolveExe,
): Promise<DoctorCheck> {
	const t = T[lang];
	const docker = await resolveExe("docker", env);
	if (docker === null) {
		return {
			id: "docker",
			estado: "falla",
			mensaje: t.dockerNo,
			accion: t.dockerAccion,
		};
	}
	const r = await run(docker, ["version", "--format", "{{.Server.Version}}"], {
		cwd: process.cwd(),
		env: childEnv(env),
		timeoutMs: DOCKER_TIMEOUT_MS,
	});
	if (r.code === 0 && !r.timedOut && r.error === undefined) {
		return { id: "docker", estado: "ok", mensaje: t.dockerOk };
	}
	return {
		id: "docker",
		estado: "falla",
		mensaje: t.dockerDown,
		accion: t.dockerAccion,
	};
}

async function checkSsh(
	lang: Lang,
	remoto: string | undefined,
	env: Env,
	run: Runner,
	resolveExe: ResolveExe,
	configInvalid = false,
): Promise<DoctorCheck> {
	const t = T[lang];
	if (configInvalid) {
		return {
			id: "ssh",
			estado: "falla",
			mensaje: t.cfgBad,
			accion: t.cfgAccion,
		};
	}
	if (remoto === undefined || remoto === "") {
		return { id: "ssh", estado: "aviso", mensaje: t.sshNo };
	}
	// A leading dash would be read by ssh as an option.
	if (!ALIAS_SHAPE.test(remoto)) {
		return {
			id: "ssh",
			estado: "falla",
			mensaje: t.sshBad(remoto.slice(0, 64)),
			accion: t.sshAccion,
		};
	}
	const ssh = await resolveExe("ssh", env);
	if (ssh === null) {
		return {
			id: "ssh",
			estado: "falla",
			mensaje: t.sshNoBin,
			accion: t.sshAccion,
		};
	}
	const r = await run(
		ssh,
		[
			"-o",
			"BatchMode=yes",
			"-o",
			"StrictHostKeyChecking=yes",
			"-o",
			`ConnectTimeout=${SSH_TIMEOUT_MS / 1000}`,
			remoto,
			"true",
		],
		{ cwd: process.cwd(), env: childEnv(env), timeoutMs: SSH_TIMEOUT_MS },
	);
	if (r.code === 0 && !r.timedOut && r.error === undefined) {
		return { id: "ssh", estado: "ok", mensaje: t.sshOk(remoto) };
	}
	return {
		id: "ssh",
		estado: "falla",
		mensaje: t.sshFail(remoto),
		accion: t.sshAccion,
	};
}

/** Presence only: the value is never copied into the report. */
async function checkGithub(
	lang: Lang,
	env: Env,
	run: Runner,
	resolveExe: ResolveExe,
): Promise<DoctorCheck> {
	const t = T[lang];
	const token = nonEmpty(env, "GITHUB_TOKEN") ?? nonEmpty(env, "GH_TOKEN");
	if (token === undefined) {
		// A `gh auth login` session is a valid credential. Output is discarded.
		const gh = await resolveExe("gh", env);
		if (gh !== null) {
			const r = await run(gh, ["auth", "status"], {
				cwd: process.cwd(),
				env: childEnv(env),
				timeoutMs: DOCKER_TIMEOUT_MS,
			});
			if (r.code === 0 && !r.timedOut && r.error === undefined) {
				return { id: "github", estado: "ok", mensaje: t.ghOk };
			}
		}
		return {
			id: "github",
			estado: "aviso",
			mensaje: t.ghNo,
			accion: t.ghAccion,
		};
	}
	if (!TOKEN_SHAPE.test(token)) {
		return {
			id: "github",
			estado: "aviso",
			mensaje: t.ghBad,
			accion: t.ghBadAccion,
		};
	}
	return { id: "github", estado: "ok", mensaje: t.ghOk };
}

async function checkPerms(
	home: string,
	lang: Lang,
	env: Env,
	extra: Partial<PermOptions>,
): Promise<DoctorCheck> {
	const t = T[lang];
	const r = await checkDictionaryPerms({
		path: defaultDictionaryPath(home),
		lang,
		env: { ...env },
		...extra,
	});
	if (r.estado === "ok") {
		return { id: "permisos", estado: "ok", mensaje: t.permOk };
	}
	if (r.estado === "ausente") {
		return { id: "permisos", estado: "ok", mensaje: t.permNo };
	}
	return {
		id: "permisos",
		estado: "aviso",
		mensaje: r.mensaje,
		...(r.accion === undefined ? {} : { accion: r.accion }),
	};
}

/** A check that throws something unexpected is reported as a failure, never as "ok". */
async function guarded(
	id: DoctorId,
	lang: Lang,
	fn: () => Promise<DoctorCheck> | DoctorCheck,
): Promise<DoctorCheck> {
	try {
		return await fn();
	} catch {
		return { id, estado: "falla", mensaje: T[lang].unknown(id) };
	}
}

/** CLI-007: the actions that fix what failed, or the first `init`. */
function nextCommand(lang: Lang, checks: readonly DoctorCheck[]): string {
	const t = T[lang];
	const actions: string[] = [];
	for (const c of checks) {
		const needs =
			c.estado === "falla" || (c.id === "permisos" && c.estado === "aviso");
		if (needs && c.accion !== undefined && !actions.includes(c.accion)) {
			actions.push(c.accion);
		}
	}
	return actions.length === 0 ? t.init : actions.join(t.y);
}

async function installPinned(
	home: string,
	lang: Lang,
	run: Runner,
	install: NonNullable<DoctorOptions["install"]>,
): Promise<void> {
	const { dir, binary } = gitleaksPaths(home);
	try {
		const present = await checkGitleaksVersion(binary, { run });
		if (present === GITLEAKS_VERSION) return;
	} catch {
		// absent or another major: install below
	}
	try {
		const installed = await install({ destDir: dir });
		const version = await checkGitleaksVersion(installed, { run });
		if (Number.parseInt(version, 10) !== GITLEAKS_MAJOR) {
			throw new Error("major");
		}
	} catch (error) {
		if (error instanceof MctError && error.codigo === "MOTOR_NO_DISPONIBLE") {
			throw error;
		}
		throw new MctError("MOTOR_NO_DISPONIBLE", T[lang].installFail, {
			accion: T[lang].glInstall,
			etapa: "doctor",
			cause: error,
		});
	}
}

/** CLI-007, SEC-001. Five read-only checks (the only write is `--install-gitleaks`). */
export async function runDoctor(
	options: DoctorOptions = {},
): Promise<DoctorReport> {
	const lang = options.lang ?? "es";
	const home = options.home ?? homedir();
	const env: Env = options.env ?? process.env;
	const run = options.run ?? defaultRunner;
	const resolveExe: ResolveExe = options.resolveExe ?? resolveExecutable;

	if (options.installGitleaks === true) {
		await installPinned(home, lang, run, options.install ?? installGitleaks);
	}

	const checks: DoctorCheck[] = [
		await guarded("gitleaks", lang, () => checkGitleaks(home, lang, run)),
		await guarded("docker", lang, () =>
			checkDocker(lang, env, run, resolveExe),
		),
		await guarded("ssh", lang, () =>
			checkSsh(
				lang,
				options.remoto,
				env,
				run,
				resolveExe,
				options.configInvalid === true,
			),
		),
		await guarded("github", lang, () =>
			checkGithub(lang, env, run, resolveExe),
		),
		await guarded("permisos", lang, () =>
			checkPerms(home, lang, env, options.perms ?? {}),
		),
	];
	// CLI-007: with a reachable verify.remoto, a missing or stopped local Docker does
	// not block verify, so it is a warning and not a next step.
	const ssh = checks.find((c) => c.id === "ssh");
	const docker = checks.findIndex((c) => c.id === "docker");
	const dockerCheck = checks[docker];
	if (
		ssh?.estado === "ok" &&
		options.remoto !== undefined &&
		dockerCheck !== undefined &&
		dockerCheck.estado === "falla"
	) {
		checks[docker] = {
			id: "docker",
			estado: "aviso",
			mensaje: dockerCheck.mensaje + T[lang].dockerRemoto(options.remoto),
		};
	}
	return { checks, siguiente: nextCommand(lang, checks) };
}
