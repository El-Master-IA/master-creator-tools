import { MctError, redactTokens } from "@mct/contract/errors";
import { Octokit } from "@octokit/rest";
import { type Runner, resolveExecutable, spawnRunner } from "./clone.js";

/** TMO-001: each Octokit call is cut at 30 s. */
export const GITHUB_CALL_TIMEOUT_MS = 30_000;
/** TMO-001, PUB-007: retries after the first attempt. */
export const GITHUB_MAX_RETRIES = 3;
/** A server-requested wait longer than this is not honoured: fail closed with LIMITE_GITHUB. */
export const GITHUB_MAX_WAIT_MS = 60_000;
const BACKOFF_BASE_MS = 1_000;
const MAX_DETAIL = 300;
const REDACTED = "[REDACTADO]";
/** Characters a GitHub token can have; anything else is refused. */
const TOKEN_SHAPE = /^[A-Za-z0-9_.-]{8,512}$/;
/** Variables `gh` needs to find its own config; no token variables. */
const GH_ENV_ALLOW = [
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
] as const;
export const REQUIRED_PERMISSIONS = [
	"Administration: write",
	"Contents: write",
	"Metadata: read",
] as const;

export type GithubLang = "es" | "en";
export type TokenSource = "GITHUB_TOKEN" | "GH_TOKEN" | "gh";
export type Sleep = (ms: number) => Promise<void>;

export interface GithubClientOptions {
	env?: Record<string, string | undefined>;
	lang?: GithubLang;
	/** Test hook: fetch used by Octokit. */
	fetch?: typeof fetch;
	/** Test hook: wait between retries. */
	sleep?: Sleep;
	/** Test hook: can only shorten the 30 s limit. */
	timeoutMs?: number;
	/** Test hook: clock for `x-ratelimit-reset`. */
	now?: () => number;
	/** Runner for `gh auth token`. */
	run?: Runner;
	ghPath?: string;
}

export interface GithubResponse {
	status: number;
	headers: Record<string, string | undefined>;
	data: unknown;
}

export interface GithubClient {
	readonly tokenSource: TokenSource;
	/** Last `x-ratelimit-remaining` seen, or undefined before any response. */
	readonly rateRemaining: number | undefined;
	request(
		route: string,
		params?: Record<string, unknown>,
	): Promise<GithubResponse>;
	/** PUB-009: read-only check; throws PERMISO_INSUFICIENTE before any write call. */
	checkPermissions(): Promise<void>;
}

const MSG = {
	es: {
		sinCred: "No hay credencial de GitHub (GITHUB_TOKEN, GH_TOKEN o gh auth).",
		accionCred: "Define GITHUB_TOKEN o inicia sesión con gh auth login.",
		formato: "La credencial de GitHub tiene un formato no válido.",
		accionFormato: "Revisa GITHUB_TOKEN, GH_TOKEN o la sesión de gh.",
		limite: "GitHub limitó las llamadas y se agotaron los 3 reintentos.",
		accionLimite: "Espera unos minutos y retoma con --resume.",
		permiso: "Al token le faltan permisos para publicar.",
		accionPermiso:
			"Usa un token clásico con el permiso repo o inicia sesión con gh auth login (los tokens fine-grained no se pueden verificar).",
		noVerificable:
			"No se pudo comprobar los permisos del token; se trata como insuficiente.",
		fallo: "La llamada a GitHub falló.",
		accionFallo: "Revisa la red y la credencial y reintenta.",
		auth: "GitHub rechazó la credencial.",
	},
	en: {
		sinCred: "No GitHub credential (GITHUB_TOKEN, GH_TOKEN or gh auth).",
		accionCred: "Set GITHUB_TOKEN or sign in with gh auth login.",
		formato: "The GitHub credential has an invalid format.",
		accionFormato: "Check GITHUB_TOKEN, GH_TOKEN or the gh session.",
		limite: "GitHub rate-limited the calls and the 3 retries ran out.",
		accionLimite: "Wait a few minutes and continue with --resume.",
		permiso: "The token lacks permissions to publish.",
		accionPermiso:
			"Use a classic token with the repo scope or sign in with gh auth login (fine-grained tokens cannot be verified).",
		noVerificable:
			"The token permissions could not be checked; treated as insufficient.",
		fallo: "The GitHub call failed.",
		accionFallo: "Check the network and the credential, then retry.",
		auth: "GitHub rejected the credential.",
	},
} as const;

function scrub(text: string, token: string): string {
	let out = text;
	if (token !== "") out = out.split(token).join(REDACTED);
	return redactTokens(out).replace(/\s+/g, " ").trim().slice(0, MAX_DETAIL);
}

function envValue(
	env: Record<string, string | undefined>,
	key: string,
): string | undefined {
	const found = Object.keys(env).find(
		(k) => k.toLowerCase() === key.toLowerCase(),
	);
	const v = found === undefined ? undefined : env[found];
	return v === undefined || v.trim() === "" ? undefined : v.trim();
}

/** PUB-005: GITHUB_TOKEN, then GH_TOKEN, then `gh auth token`. The value is never stored or printed. */
export async function resolveGithubToken(
	options: GithubClientOptions = {},
): Promise<{ token: string; source: TokenSource }> {
	const m = MSG[options.lang ?? "es"];
	const env = options.env ?? process.env;
	let token = envValue(env, "GITHUB_TOKEN");
	let source: TokenSource = "GITHUB_TOKEN";
	if (token === undefined) {
		token = envValue(env, "GH_TOKEN");
		source = "GH_TOKEN";
	}
	if (token === undefined) {
		source = "gh";
		const gh = options.ghPath ?? (await resolveExecutable("gh", env));
		if (gh !== null) {
			const controller = new AbortController();
			const timer = setTimeout(
				() => controller.abort(),
				Math.min(
					options.timeoutMs ?? GITHUB_CALL_TIMEOUT_MS,
					GITHUB_CALL_TIMEOUT_MS,
				),
			);
			try {
				const ghEnv: Record<string, string> = {};
				for (const key of GH_ENV_ALLOW) {
					const v = env[key];
					if (v !== undefined && v !== "") ghEnv[key] = v;
				}
				const res = await (options.run ?? spawnRunner)(gh, ["auth", "token"], {
					env: ghEnv,
					cwd: process.cwd(),
					signal: controller.signal,
				});
				if (res.code === 0) token = res.stdout.trim() || undefined;
			} catch {
				// no usable gh session: reported below as SIN_CREDENCIAL
				token = undefined;
			} finally {
				clearTimeout(timer);
			}
		}
	}
	if (token === undefined) {
		throw new MctError("SIN_CREDENCIAL", m.sinCred, {
			etapa: "publish",
			accion: m.accionCred,
		});
	}
	if (!TOKEN_SHAPE.test(token)) {
		throw new MctError("SIN_CREDENCIAL", m.formato, {
			etapa: "publish",
			accion: m.accionFormato,
			detalle: { fuente: source },
		});
	}
	return { token, source };
}

function normalize(
	headers: Record<string, unknown> | undefined,
): Record<string, string | undefined> {
	const out: Record<string, string | undefined> = {};
	if (headers === undefined || headers === null) return out;
	for (const k of Object.keys(headers)) {
		const v = headers[k];
		if (typeof v === "string" || typeof v === "number") {
			out[k.toLowerCase()] = String(v);
		}
	}
	return out;
}

interface Failure {
	status: number;
	headers: Record<string, string | undefined>;
	message: string;
}

function isLimit(f: Failure): boolean {
	if (f.status === 429) return true;
	if (f.status !== 403) return false;
	return (
		f.headers["retry-after"] !== undefined ||
		f.headers["x-ratelimit-remaining"] === "0" ||
		/rate limit|abuse|secondary/i.test(f.message)
	);
}

/** Wait before the next attempt: retry-after, then reset time, then exponential backoff. */
function waitFor(f: Failure, attempt: number, nowMs: number): number {
	const ra = f.headers["retry-after"];
	if (ra !== undefined) {
		if (/^\d{1,9}$/.test(ra)) return Number(ra) * 1000;
		const at = Date.parse(ra);
		if (!Number.isNaN(at)) return Math.max(0, at - nowMs);
	}
	const reset = f.headers["x-ratelimit-reset"];
	if (
		f.headers["x-ratelimit-remaining"] === "0" &&
		reset !== undefined &&
		/^\d{1,12}$/.test(reset)
	) {
		return Math.max(0, Number(reset) * 1000 - nowMs);
	}
	return BACKOFF_BASE_MS * 2 ** attempt;
}

const defaultSleep: Sleep = (ms) =>
	new Promise((r) => {
		setTimeout(r, ms);
	});

/**
 * PUB-005, PUB-007, PUB-009, TMO-001. Octokit client: 30 s per call, 3 retries with backoff,
 * `retry-after` honoured, errors redacted, token read only from the environment or `gh auth`.
 */
export async function createGithubClient(
	options: GithubClientOptions = {},
): Promise<GithubClient> {
	const m = MSG[options.lang ?? "es"];
	const { token, source } = await resolveGithubToken(options);
	const limit = Math.min(
		options.timeoutMs ?? GITHUB_CALL_TIMEOUT_MS,
		GITHUB_CALL_TIMEOUT_MS,
	);
	const sleep = options.sleep ?? defaultSleep;
	const now = options.now ?? Date.now;
	const octokit = new Octokit({
		auth: token,
		userAgent: "mct",
		...(options.fetch !== undefined && { request: { fetch: options.fetch } }),
	});
	let remaining: number | undefined;

	const track = (headers: Record<string, string | undefined>): void => {
		const rem = headers["x-ratelimit-remaining"];
		if (rem !== undefined && /^\d{1,9}$/.test(rem)) remaining = Number(rem);
	};

	const attemptOnce = async (
		route: string,
		params: Record<string, unknown>,
	): Promise<GithubResponse> => {
		const controller = new AbortController();
		let timer: NodeJS.Timeout | undefined;
		const deadline = new Promise<never>((_, reject) => {
			timer = setTimeout(() => {
				controller.abort();
				reject(Object.assign(new Error("timeout"), { status: 408 }));
			}, limit);
		});
		deadline.catch(() => undefined);
		const call = octokit.request(route, {
			...params,
			request: { signal: controller.signal },
		});
		call.catch(() => undefined);
		try {
			const res = await Promise.race([call, deadline]);
			const headers = normalize(res.headers as Record<string, unknown>);
			track(headers);
			return { status: res.status, headers, data: res.data };
		} finally {
			if (timer !== undefined) clearTimeout(timer);
		}
	};

	const toFailure = (e: unknown): Failure => {
		const err = e as {
			status?: unknown;
			message?: unknown;
			response?: { headers?: Record<string, unknown> };
		};
		return {
			status: typeof err?.status === "number" ? err.status : 0,
			headers: normalize(err?.response?.headers),
			message: scrub(String(err?.message ?? e), token),
		};
	};

	const request: GithubClient["request"] = async (route, params = {}) => {
		let last: Failure | undefined;
		for (let attempt = 0; attempt <= GITHUB_MAX_RETRIES; attempt++) {
			try {
				return await attemptOnce(route, params);
			} catch (e) {
				const f = toFailure(e);
				track(f.headers);
				last = f;
				const limited = isLimit(f);
				const transient =
					limited || f.status === 0 || f.status === 408 || f.status >= 500;
				if (!transient || attempt === GITHUB_MAX_RETRIES) break;
				const wait = waitFor(f, attempt, now());
				if (limited && wait > GITHUB_MAX_WAIT_MS) break;
				await sleep(wait);
			}
		}
		const f = last as Failure;
		const detalle = { estado: f.status, intentos: GITHUB_MAX_RETRIES + 1 };
		if (isLimit(f)) {
			throw new MctError("LIMITE_GITHUB", m.limite, {
				etapa: "publish",
				accion: m.accionLimite,
				detalle,
			});
		}
		if (f.status === 401) {
			throw new MctError("SIN_CREDENCIAL", m.auth, {
				etapa: "publish",
				accion: m.accionCred,
				detalle,
			});
		}
		if (f.status === 403) {
			throw new MctError("PERMISO_INSUFICIENTE", m.permiso, {
				etapa: "publish",
				accion: m.accionPermiso,
				detalle,
			});
		}
		throw new MctError("INTERNO", m.fallo, {
			etapa: "publish",
			accion: m.accionFallo,
			detalle: { ...detalle, salida: f.message },
		});
	};

	const checkPermissions = async (): Promise<void> => {
		// Read-only probe.
		const res = await request("GET /user");
		const raw = res.headers["x-oauth-scopes"];
		if (raw === undefined) {
			// No scopes header. Fine-grained tokens expose none and GitHub has no read-only
			// introspection of their permissions (Administration, Contents), so they cannot be
			// proven before the first write. Fail closed (PUB-009): require a classic token or gh auth.
			throw new MctError("PERMISO_INSUFICIENTE", m.noVerificable, {
				etapa: "publish",
				accion: m.accionPermiso,
				detalle: {
					faltan: [...REQUIRED_PERMISSIONS],
					motivo: "no-verificable",
				},
			});
		}
		const scopes = raw
			.split(",")
			.map((s) => s.trim())
			.filter((s) => s !== "");
		if (!scopes.includes("repo")) {
			throw new MctError("PERMISO_INSUFICIENTE", m.permiso, {
				etapa: "publish",
				accion: m.accionPermiso,
				detalle: { faltan: ["Administration: write", "Contents: write"] },
			});
		}
	};

	return {
		tokenSource: source,
		get rateRemaining() {
			return remaining;
		},
		request,
		checkPermissions,
	};
}
