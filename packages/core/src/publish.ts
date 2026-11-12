import { execFileSync } from "node:child_process";
import {
	chmod,
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { join, win32 } from "node:path";
import { n8nAdapter } from "@mct/adapter-n8n/index";
import { nodeAdapter } from "@mct/adapter-node/index";
import { MctError, redactTokens } from "@mct/contract/errors";
import type { Adapter, State } from "@mct/contract/types";
import { loadDictionary } from "@mct/scanner/dictionary";
import { type ScanGitleaksOptions, scan } from "@mct/scanner/scan";
import {
	CLONE_TIMEOUT_MS,
	cloneGithub,
	type Runner,
	resolveExecutable,
	spawnRunner,
} from "./clone.js";
import { type GithubClient, resolveGithubToken } from "./github.js";
import { hashTree } from "./hash.js";
import { defaultDictionaryPath } from "./init-guards.js";
import { createLogger } from "./logger.js";
import { runPublishChecks } from "./publish-gates.js";
import { readState, withLock, writeState } from "./workspace.js";

export const PUBLISH_STATE_SCHEMA_VERSION = 1;
export const RELEASE_TAG = "v0.1.0";
export const DEFAULT_TOPICS: readonly string[] = [
	"cli",
	"open-source",
	"sanitized",
];
const BRANCH = "main";
const MAX_OUTPUT_DETAIL = 500;
const TOKEN_ENV = "MCT_GIT_TOKEN";
const TOKEN_SHAPE = /^[A-Za-z0-9_.-]{8,512}$/;
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const TOPIC = /^[a-z0-9][a-z0-9-]{0,49}$/;
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
const ADAPTERS: readonly Adapter[] = [nodeAdapter, n8nAdapter];

export type PublishLang = "es" | "en";
export type Paso =
	| "crear"
	| "commit"
	| "escaneoRemoto"
	| "publico"
	| "tag"
	| "release"
	| "topics";
export type EstadoPaso = "pendiente" | "ok" | "fallo";

export const PASOS: readonly Paso[] = [
	"crear",
	"commit",
	"escaneoRemoto",
	"publico",
	"tag",
	"release",
	"topics",
];

export interface PublishStateFile {
	schemaVersion: number;
	repo: string;
	repoId: number;
	creadoPorWorkspace: true;
	/** Hash of the verified dist/ that was (or will be) pushed; --resume must still match it. */
	distSha256: string;
	pasos: Record<Paso, EstadoPaso>;
	ts: string;
}

/** Everything `publish` needs from git; the default talks to the real `git`. */
export interface PublishGit {
	/** One commit with the contents of `dist`, pushed to the empty repo. */
	pushInitial(args: {
		dist: string;
		repo: string;
		token: string;
		tmpDir: string;
		/** Verified hash of `dist`; a tree that differs is never pushed. */
		distSha256: string;
	}): Promise<void>;
	/** Shallow clone (without `.git`) of the repo into `dir`, which must not exist. */
	cloneRemote(args: {
		repo: string;
		token: string;
		dir: string;
	}): Promise<void>;
}

export interface GitPortOptions {
	run?: Runner;
	gitPath?: string;
	ghPath?: string;
	env?: Record<string, string | undefined>;
	timeoutMs?: number;
	lang?: PublishLang;
}

export interface PublishOptions {
	/** `.mct/` directory of the workspace. */
	raiz: string;
	/** `owner/name`. */
	repo: string;
	client: GithubClient;
	/** Second confirmation before making the repo public (PUB-003). */
	confirmarPublico: () => Promise<boolean>;
	git?: PublishGit;
	/** Token for git; by default resolved with the same rules as the client (PUB-005). */
	token?: string;
	dryRun?: boolean;
	resume?: boolean;
	/** `--private`: leave the repo private. */
	privado?: boolean;
	topics?: readonly string[];
	lang?: PublishLang;
	home?: string;
	gitleaks?: Partial<ScanGitleaksOptions>;
	env?: Record<string, string | undefined>;
	now?: () => string;
}

export interface PublishResult {
	url: string;
	visibilidad: "privado" | "publico";
	tag: string;
	dryRun?: true;
}

const MSG = {
	es: {
		sinEstado: "--resume necesita un publish-state.json de este workspace",
		accionResume: "Corre publish sin --resume o revisa el repo",
		estadoMal: "publish-state.json tiene una forma inválida",
		accionWs: "Revisa el workspace o recréalo con init --force",
		enlace: "publish-state.json es un enlace o no es un archivo",
		resumeRepo: "--resume no corresponde al repo guardado por este workspace",
		resumeEstado:
			"El estado del repo no permite reanudar (visibilidad y pasos no coinciden)",
		repoRespuesta: "GitHub devolvió una respuesta que no se entiende",
		accionGh: "Reintenta; si persiste, revisa el repo en GitHub",
		sinGit: "No se encontró git en el PATH.",
		accionGit: "Instala git y reintenta.",
		token: "La credencial de GitHub tiene un formato no válido.",
		accionToken: "Revisa GITHUB_TOKEN, GH_TOKEN o la sesión de gh.",
		gitFallo: "git no pudo completar la operación",
		accionFallo: "Revisa la red y los permisos y retoma con --resume",
		timeout: "git superó el tiempo máximo y se canceló",
		hallazgos: "El escaneo del repo remoto encontró hallazgos",
		cancelado: "No se confirmó hacer público el repo; sigue privado",
		accionCancel: "Retoma con --resume cuando quieras publicarlo",
		residuo: "No se pudo borrar remote-scan/",
		accionResiduo: "Borra .mct/remote-scan a mano",
		cuarentena: "No se pudo borrar quarantine/",
		accionCuarentena: "Corre: mct clean",
		topics: "Un topic no es válido",
		distCambio:
			"dist/ ya no es el que se aprobó y se empujó (o está por empujarse)",
		accionDist:
			"Borra el repo en GitHub (gh repo delete) y publica de nuevo con el dist aprobado",
		release: "Primera versión publicada con mct.",
	},
	en: {
		sinEstado: "--resume needs a publish-state.json from this workspace",
		accionResume: "Run publish without --resume or check the repo",
		estadoMal: "publish-state.json has an invalid shape",
		accionWs: "Check the workspace or recreate it with init --force",
		enlace: "publish-state.json is a link or not a file",
		resumeRepo: "--resume does not match the repo saved by this workspace",
		resumeEstado:
			"The repo state does not allow resuming (visibility and steps differ)",
		repoRespuesta: "GitHub returned a response that is not understood",
		accionGh: "Retry; if it persists, check the repo on GitHub",
		sinGit: "git was not found on PATH.",
		accionGit: "Install git and retry.",
		token: "The GitHub credential has an invalid format.",
		accionToken: "Check GITHUB_TOKEN, GH_TOKEN or the gh session.",
		gitFallo: "git could not complete the operation",
		accionFallo: "Check the network and permissions and continue with --resume",
		timeout: "git exceeded the time limit and was cancelled",
		hallazgos: "The remote repo scan found findings",
		cancelado: "Making the repo public was not confirmed; it stays private",
		accionCancel: "Continue with --resume when you want to publish it",
		residuo: "remote-scan/ could not be deleted",
		accionResiduo: "Delete .mct/remote-scan by hand",
		cuarentena: "quarantine/ could not be deleted",
		accionCuarentena: "Run: mct clean",
		topics: "A topic is not valid",
		distCambio:
			"dist/ is no longer the one that was approved and pushed (or about to be)",
		accionDist:
			"Delete the repo on GitHub (gh repo delete) and publish again with the approved dist",
		release: "First release published with mct.",
	},
} as const;

function fail(
	codigo: string,
	mensaje: string,
	accion: string,
	detalle?: Record<string, unknown>,
	cause?: unknown,
): MctError {
	return new MctError(codigo, mensaje, {
		etapa: "publish",
		accion,
		...(detalle !== undefined && { detalle }),
		...(cause !== undefined && { cause }),
	});
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

function scrub(text: string, token: string | undefined): string {
	let out = text;
	if (token !== undefined && token !== "") {
		out = out.split(token).join("[REDACTADO]");
	}
	return redactTokens(out)
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, MAX_OUTPUT_DETAIL);
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

const ASKPASS_SCRIPT = [
	"#!/bin/sh",
	'case "$1" in',
	`  *sername*) printf '%s\\n' "x-access-token" ;;`,
	`  *) printf '%s\\n' "$${TOKEN_ENV}" ;;`,
	"esac",
	"",
].join("\n");

const PUSH_HARDENING = [
	"core.hooksPath=/dev/null",
	"credential.helper=",
	"core.excludesFile=",
	"core.autocrlf=false",
	"commit.gpgsign=false",
	"user.name=mct",
	"user.email=mct@users.noreply.github.com",
] as const;

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

/**
 * CLI-009: git port with the real `git`. The token reaches git only through an
 * ephemeral `GIT_ASKPASS` helper that lives during the call; never argv, URL or logs.
 */
export function createGitPort(options: GitPortOptions = {}): PublishGit {
	const lang = options.lang ?? "es";
	const m = MSG[lang];
	const env = options.env ?? process.env;
	const run = options.run ?? spawnRunner;
	const limit = Math.min(
		options.timeoutMs ?? CLONE_TIMEOUT_MS,
		CLONE_TIMEOUT_MS,
	);

	const checkToken = (token: string): void => {
		if (!TOKEN_SHAPE.test(token)) {
			throw fail("VALIDACION", m.token, m.accionToken);
		}
	};

	const pushInitial: PublishGit["pushInitial"] = async ({
		dist,
		repo,
		token,
		tmpDir,
		distSha256,
	}) => {
		checkToken(token);
		const git = options.gitPath ?? (await resolveExecutable("git", env));
		if (git === null) throw fail("INTERNO", m.sinGit, m.accionGit);
		await mkdir(tmpDir, { recursive: true, mode: 0o700 });
		const helperDir = await mkdtemp(join(tmpDir, "askpass-"));
		const gitDir = await mkdtemp(join(tmpDir, "push-"));
		const controller = new AbortController();
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
		}, limit);
		try {
			const helper = join(helperDir, "askpass.sh");
			await writeFile(helper, ASKPASS_SCRIPT, { mode: 0o700 });
			const base = childEnv(env);
			const base2 = [
				...PUSH_HARDENING.flatMap((c) => ["-c", c]),
				`--git-dir=${gitDir}`,
				`--work-tree=${dist}`,
			];
			const exec = async (
				args: string[],
				extra: Record<string, string>,
			): Promise<void> => {
				const res = await run(git, [...base2, ...args], {
					env: { ...base, ...extra },
					cwd: tmpdir(),
					signal: controller.signal,
				});
				if (timedOut) throw fail("INTERNO", m.timeout, m.accionFallo);
				if (res.code !== 0) {
					throw fail("INTERNO", m.gitFallo, m.accionFallo, {
						operacion: args[0],
						salida: scrub(`${res.stderr} ${res.stdout}`, token),
					});
				}
			};
			const sameTree = async (): Promise<void> => {
				if ((await hashTree(dist)) !== distSha256) {
					throw fail("APROBACION_DESACTUALIZADA", m.distCambio, m.accionDist);
				}
			};
			await sameTree();
			await exec(["init", "--quiet", `--initial-branch=${BRANCH}`], {});
			await exec(["add", "--all"], {});
			await exec(
				["commit", "--quiet", "--no-verify", "-m", "Initial commit"],
				{},
			);
			// dist/ must not have changed between the gates and the committed tree.
			await sameTree();
			await exec(
				[
					"push",
					"--quiet",
					`https://github.com/${repo}.git`,
					`HEAD:refs/heads/${BRANCH}`,
				],
				{
					GIT_ASKPASS: helper.replace(/\\/g, "/"),
					[TOKEN_ENV]: token,
				},
			);
		} catch (e) {
			if (e instanceof MctError) throw e;
			throw fail("INTERNO", timedOut ? m.timeout : m.gitFallo, m.accionFallo, {
				salida: scrub(String(e), token),
			});
		} finally {
			clearTimeout(timer);
			await removeTree(helperDir);
			await removeTree(gitDir);
		}
	};

	const cloneRemote: PublishGit["cloneRemote"] = async ({
		repo,
		token,
		dir,
	}) => {
		checkToken(token);
		const cloneEnv: Record<string, string | undefined> = {};
		for (const [k, v] of Object.entries(env)) {
			if (!/^(github_token|gh_token)$/i.test(k)) cloneEnv[k] = v;
		}
		cloneEnv.GITHUB_TOKEN = token;
		try {
			await cloneGithub({
				url: `https://github.com/${repo}`,
				dir,
				env: cloneEnv,
				lang,
				...(options.run !== undefined && { run: options.run }),
				...(options.gitPath !== undefined && { gitPath: options.gitPath }),
				...(options.ghPath !== undefined && { ghPath: options.ghPath }),
				...(options.timeoutMs !== undefined && {
					timeoutMs: options.timeoutMs,
				}),
			});
		} catch (e) {
			if (e instanceof MctError) {
				throw new MctError(e.codigo, e.message, {
					etapa: "publish",
					...(e.accion !== undefined && { accion: e.accion }),
					...(e.detalle !== undefined && { detalle: e.detalle }),
				});
			}
			throw e;
		}
	};

	return { pushInitial, cloneRemote };
}

// ---- publish-state.json ----

async function restrictFile(path: string): Promise<void> {
	if (process.platform !== "win32") {
		await chmod(path, 0o600);
		return;
	}
	const { SystemRoot: root } = process.env;
	if (root === undefined || !win32.isAbsolute(root)) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"No se pudieron aplicar los permisos",
		);
	}
	try {
		execFileSync(
			win32.join(root, "System32", "icacls.exe"),
			[path, "/inheritance:r", "/grant:r", `${userInfo().username}:F`],
			{ stdio: "ignore", windowsHide: true },
		);
	} catch (cause) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"No se pudieron aplicar los permisos",
			{ cause },
		);
	}
}

async function writePublishState(
	raiz: string,
	state: PublishStateFile,
	m: (typeof MSG)[PublishLang],
): Promise<void> {
	const destino = join(raiz, "publish-state.json");
	try {
		if ((await lstat(destino)).isSymbolicLink()) {
			throw fail("WORKSPACE_INVALIDO", m.enlace, m.accionWs);
		}
	} catch (cause) {
		if (cause instanceof MctError) throw cause;
		if ((cause as NodeJS.ErrnoException).code !== "ENOENT") {
			throw fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs);
		}
	}
	const tmp = `${destino}.${process.pid}.tmp`;
	await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
	try {
		await restrictFile(tmp);
		await rename(tmp, destino);
	} catch (e) {
		await rm(tmp, { force: true });
		throw e;
	}
}

/** `undefined` only when the file does not exist; anything else odd is an error. */
async function readPublishState(
	raiz: string,
	m: (typeof MSG)[PublishLang],
): Promise<PublishStateFile | undefined> {
	const path = join(raiz, "publish-state.json");
	let info: Awaited<ReturnType<typeof lstat>>;
	try {
		info = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs);
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		throw fail("WORKSPACE_INVALIDO", m.enlace, m.accionWs);
	}
	if (info.size > 64 * 1024) {
		throw fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(await readFile(path, "utf8"));
	} catch {
		throw fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs);
	}
	const bad = (): MctError =>
		fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs);
	if (!isObj(parsed) || parsed.schemaVersion !== PUBLISH_STATE_SCHEMA_VERSION) {
		throw bad();
	}
	const { repo, repoId, creadoPorWorkspace, pasos, ts, distSha256 } = parsed;
	if (
		typeof repo !== "string" ||
		typeof repoId !== "number" ||
		!Number.isSafeInteger(repoId) ||
		repoId <= 0 ||
		creadoPorWorkspace !== true ||
		typeof ts !== "string" ||
		typeof distSha256 !== "string" ||
		!SHA256.test(distSha256) ||
		!isObj(pasos)
	) {
		throw bad();
	}
	const out = {} as Record<Paso, EstadoPaso>;
	for (const p of PASOS) {
		const v = pasos[p];
		if (v !== "pendiente" && v !== "ok" && v !== "fallo") throw bad();
		out[p] = v;
	}
	return {
		schemaVersion: PUBLISH_STATE_SCHEMA_VERSION,
		repo,
		repoId,
		creadoPorWorkspace: true,
		distSha256,
		pasos: out,
		ts,
	};
}

// ---- GitHub helpers ----

interface RepoInfo {
	id: number;
	private: boolean;
}

function repoInfo(data: unknown, m: (typeof MSG)[PublishLang]): RepoInfo {
	if (
		!isObj(data) ||
		typeof data.id !== "number" ||
		!Number.isSafeInteger(data.id) ||
		typeof data.private !== "boolean"
	) {
		throw fail("INTERNO", m.repoRespuesta, m.accionGh);
	}
	return { id: data.id, private: data.private };
}

function estadoDe(e: unknown): number | undefined {
	if (e instanceof MctError && e.codigo === "INTERNO") {
		const s = e.detalle?.estado;
		return typeof s === "number" ? s : undefined;
	}
	return undefined;
}

// ---- remote scan ----

/** Ids of findings decided in sanitize as accepted or false positive (fail closed on bad shape). */
async function decidedIds(
	raiz: string,
	m: (typeof MSG)[PublishLang],
): Promise<Set<string>> {
	const bad = (): MctError =>
		fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs, {
			archivo: "findings.json",
		});
	let parsed: unknown;
	try {
		parsed = JSON.parse(await readFile(join(raiz, "findings.json"), "utf8"));
	} catch {
		throw bad();
	}
	if (!isObj(parsed) || !Array.isArray(parsed.hallazgos)) throw bad();
	const ids = new Set<string>();
	for (const h of parsed.hallazgos as unknown[]) {
		if (!isObj(h) || typeof h.id !== "string" || typeof h.estado !== "string") {
			throw bad();
		}
		if (h.estado === "aceptado" || h.estado === "falso-positivo") ids.add(h.id);
	}
	return ids;
}

async function scanRemote(
	opts: PublishOptions,
	git: PublishGit,
	token: string,
	m: (typeof MSG)[PublishLang],
): Promise<{ total: number; porMotor: Record<string, number> }> {
	const dir = join(opts.raiz, "remote-scan");
	const decididos = await decidedIds(opts.raiz, m);
	const home = opts.home ?? homedir();
	let failure: unknown;
	let result: { total: number; porMotor: Record<string, number> } | undefined;
	try {
		await removeTree(dir);
		await git.cloneRemote({ repo: opts.repo, token, dir });
		if (process.platform !== "win32") await chmod(dir, 0o700);
		const state = await readState(opts.raiz);
		const adapter = ADAPTERS.find((a) => a.id === state.adapter);
		if (adapter === undefined) {
			throw fail("WORKSPACE_INVALIDO", m.estadoMal, m.accionWs, {
				archivo: "state.json",
			});
		}
		const terms = await loadDictionary(defaultDictionaryPath(home));
		const tmpDir = join(opts.raiz, "tmp");
		await mkdir(tmpDir, { recursive: true, mode: 0o700 });
		const g = opts.gitleaks ?? {};
		const res = await scan({
			work: dir,
			// Not the local quarantine: it never reaches the remote repo.
			quarantine: join(tmpDir, "sin-cuarentena"),
			rules: adapter.rules(),
			dictionary: terms,
			gitleaks: { installDir: join(home, ".mct", "bin"), tmpDir, ...g },
		});
		const porMotor: Record<string, number> = {};
		let total = 0;
		for (const h of res.hallazgos) {
			// Same id = same engine, rule, path, line and value as one the person decided.
			if (decididos.has(h.id)) continue;
			total++;
			porMotor[h.motor] = (porMotor[h.motor] ?? 0) + 1;
		}
		result = { total, porMotor };
	} catch (e) {
		failure = e;
	}
	const gone = await removeTree(dir);
	if (failure !== undefined) throw failure;
	if (!gone) throw fail("INTERNO", m.residuo, m.accionResiduo);
	return result as { total: number; porMotor: Record<string, number> };
}

/**
 * PUB-003, PUB-008, PUB-010, SAN-005. Private repo with one commit, remote scan with both
 * engines, second confirmation, tag, release, topics. Every step is saved in
 * `publish-state.json`; `--resume` continues from there. Ends by deleting `quarantine/`.
 */
export async function publish(opts: PublishOptions): Promise<PublishResult> {
	const lang = opts.lang ?? "es";
	const m = MSG[lang];
	const now = opts.now ?? (() => new Date().toISOString());
	const topics = [...(opts.topics ?? DEFAULT_TOPICS)];
	if (
		topics.length === 0 ||
		topics.length > 20 ||
		!topics.every((t) => TOPIC.test(t))
	) {
		throw fail("VALIDACION", m.topics, m.accionResume);
	}
	const [owner, name] = opts.repo.split("/") as [string, string];
	const url = `https://github.com/${opts.repo}`;
	const t0 = Date.now();

	return withLock(opts.raiz, async () => {
		const logger = createLogger(opts.raiz, "publish", { now });
		try {
			const prev = opts.resume
				? await readPublishState(opts.raiz, m)
				: undefined;
			if (opts.resume && prev === undefined) {
				throw fail("VALIDACION", m.sinEstado, m.accionResume);
			}
			if (prev !== undefined && prev.repo !== opts.repo) {
				throw fail("VALIDACION", m.resumeRepo, m.accionResume);
			}
			const checks = await runPublishChecks(opts.client, {
				raiz: opts.raiz,
				repo: opts.repo,
				lang,
				...(opts.dryRun === true && { dryRun: true }),
				...(prev !== undefined && { resumeRepoId: prev.repoId }),
			});
			if (opts.resume && checks.modo !== "reanudar") {
				throw fail("VALIDACION", m.resumeRepo, m.accionResume);
			}
			if (opts.dryRun === true) {
				return { url, visibilidad: "privado", tag: RELEASE_TAG, dryRun: true };
			}
			const verified = (await readState(opts.raiz)).verificado;
			if (verified === null) {
				throw fail("PUERTA_BLOQUEADA", m.distCambio, m.accionDist);
			}
			const distSha256 = verified.distSha256;
			if (prev !== undefined && prev.distSha256 !== distSha256) {
				throw new MctError("APROBACION_DESACTUALIZADA", m.distCambio, {
					etapa: "publish",
					accion: m.accionDist,
				});
			}

			const token =
				opts.token ??
				(
					await resolveGithubToken({
						lang,
						...(opts.env !== undefined && { env: opts.env }),
					})
				).token;
			const git =
				opts.git ?? createGitPort({ lang, env: opts.env ?? process.env });
			const client = opts.client;
			const raiz = opts.raiz;
			let visibilidad: "privado" | "publico" = "privado";
			let st: PublishStateFile;

			const save = async (): Promise<void> => {
				st = { ...st, ts: now() };
				await writePublishState(raiz, st, m);
			};
			const mark = (paso: Paso, estado: EstadoPaso): void => {
				st = { ...st, pasos: { ...st.pasos, [paso]: estado } };
			};
			const step = async (
				paso: Paso,
				fn: () => Promise<void>,
			): Promise<void> => {
				if (st.pasos[paso] === "ok") return;
				try {
					await fn();
				} catch (e) {
					mark(paso, "fallo");
					await save().catch(() => undefined);
					throw e;
				}
				mark(paso, "ok");
				await save();
			};

			if (prev !== undefined) {
				const info = repoInfo(
					(
						await client.request("GET /repos/{owner}/{repo}", {
							owner,
							repo: name,
						})
					).data,
					m,
				);
				if (info.id !== prev.repoId) {
					throw fail("VALIDACION", m.resumeRepo, m.accionResume);
				}
				st = prev;
				if (info.private) {
					if (prev.pasos.publico === "ok") {
						throw fail("VALIDACION", m.resumeEstado, m.accionResume);
					}
				} else {
					const previos: Paso[] = [
						"crear",
						"commit",
						"escaneoRemoto",
						"publico",
					];
					if (!previos.every((p) => prev.pasos[p] === "ok")) {
						throw fail("VALIDACION", m.resumeEstado, m.accionResume);
					}
					visibilidad = "publico";
				}
			} else {
				const me = await client.request("GET /user");
				const login = isObj(me.data) ? me.data.login : undefined;
				if (typeof login !== "string" || login === "") {
					throw fail("INTERNO", m.repoRespuesta, m.accionGh);
				}
				const own = login.toLowerCase() === owner.toLowerCase();
				const created = await (own
					? client.request("POST /user/repos", {
							name,
							private: true,
							auto_init: false,
						})
					: client.request("POST /orgs/{org}/repos", {
							org: owner,
							name,
							private: true,
							auto_init: false,
						}));
				const info = repoInfo(created.data, m);
				if (!info.private) {
					throw fail("INTERNO", m.repoRespuesta, m.accionGh);
				}
				st = {
					schemaVersion: PUBLISH_STATE_SCHEMA_VERSION,
					repo: opts.repo,
					repoId: info.id,
					creadoPorWorkspace: true,
					distSha256,
					pasos: {
						crear: "ok",
						commit: "pendiente",
						escaneoRemoto: "pendiente",
						publico: "pendiente",
						tag: "pendiente",
						release: "pendiente",
						topics: "pendiente",
					},
					ts: now(),
				};
				await writePublishState(raiz, st, m);
			}

			await step("commit", async () => {
				// The repo was created after the gates: dist/ must still be the verified one.
				if ((await hashTree(join(raiz, "dist"))) !== distSha256) {
					throw new MctError("APROBACION_DESACTUALIZADA", m.distCambio, {
						etapa: "publish",
						accion: m.accionDist,
					});
				}
				await git.pushInitial({
					dist: join(raiz, "dist"),
					repo: opts.repo,
					token,
					tmpDir: join(raiz, "tmp"),
					distSha256,
				});
			});

			await step("escaneoRemoto", async () => {
				const res = await scanRemote(opts, git, token, m);
				if (res.total > 0) {
					throw fail(
						"PUERTA_BLOQUEADA",
						m.hallazgos,
						lang === "es"
							? `El repo sigue privado. Bórralo (Settings › Danger zone, o: gh repo delete ${opts.repo}), corrige el origen y publica de nuevo`
							: `The repo stays private. Delete it (Settings › Danger zone, or: gh repo delete ${opts.repo}), fix the source and publish again`,
						{ hallazgos: res.total, porMotor: res.porMotor, repo: opts.repo },
					);
				}
			});

			if (opts.privado !== true) {
				await step("publico", async () => {
					if (!(await opts.confirmarPublico())) {
						throw fail("CANCELADO", m.cancelado, m.accionCancel);
					}
					await client.request("PATCH /repos/{owner}/{repo}", {
						owner,
						repo: name,
						private: false,
					});
				});
				visibilidad = "publico";
			}

			await step("tag", async () => {
				const head = await client.request(
					"GET /repos/{owner}/{repo}/commits/{ref}",
					{ owner, repo: name, ref: BRANCH },
				);
				const sha = isObj(head.data) ? head.data.sha : undefined;
				if (typeof sha !== "string" || !COMMIT_SHA.test(sha)) {
					throw fail("INTERNO", m.repoRespuesta, m.accionGh);
				}
				try {
					await client.request("POST /repos/{owner}/{repo}/git/refs", {
						owner,
						repo: name,
						ref: `refs/tags/${RELEASE_TAG}`,
						sha,
					});
				} catch (e) {
					if (estadoDe(e) !== 422) throw e;
					// Already there from a run that died before saving: it must exist.
					await client.request("GET /repos/{owner}/{repo}/git/ref/{ref}", {
						owner,
						repo: name,
						ref: `tags/${RELEASE_TAG}`,
					});
				}
			});

			await step("release", async () => {
				try {
					await client.request("POST /repos/{owner}/{repo}/releases", {
						owner,
						repo: name,
						tag_name: RELEASE_TAG,
						name: RELEASE_TAG,
						body: m.release,
						draft: false,
						prerelease: false,
					});
				} catch (e) {
					if (estadoDe(e) !== 422) throw e;
					await client.request(
						"GET /repos/{owner}/{repo}/releases/tags/{tag}",
						{
							owner,
							repo: name,
							tag: RELEASE_TAG,
						},
					);
				}
			});

			await step("topics", async () => {
				await client.request("PUT /repos/{owner}/{repo}/topics", {
					owner,
					repo: name,
					names: topics,
				});
			});

			// SAN-005: the quarantine goes away when publish ends.
			const quarantine = join(raiz, "quarantine");
			await rm(quarantine, { recursive: true, force: true });
			const queda = await lstat(quarantine).then(
				() => true,
				() => false,
			);
			if (queda) {
				throw fail("INTERNO", m.cuarentena, m.accionCuarentena);
			}
			const actual: State = await readState(raiz);
			await writeState(raiz, {
				...actual,
				etapas: { ...actual.etapas, publish: { estado: "ok", ts: now() } },
			});
			await logger.log({
				evento: "publish.ok",
				duracionMs: Date.now() - t0,
			});
			return { url, visibilidad, tag: RELEASE_TAG };
		} catch (error) {
			await logger.error(error).catch(() => undefined);
			throw error;
		}
	});
}
