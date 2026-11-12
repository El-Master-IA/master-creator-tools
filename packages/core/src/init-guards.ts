import { execFileSync } from "node:child_process";
import { stat as fsStat, realpath } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { dirname, resolve as hostResolve, join, posix, win32 } from "node:path";
import { MctError } from "@mct/contract/errors";

export type Lang = "es" | "en";

export type SyncProvider = "onedrive" | "dropbox" | "icloud" | "google-drive";

export interface SyncedFolder {
	proveedor: SyncProvider;
	/** Human readable provider name. */
	nombre: string;
}

const NOMBRES: Record<SyncProvider, string> = {
	onedrive: "OneDrive",
	dropbox: "Dropbox",
	icloud: "iCloud Drive",
	"google-drive": "Google Drive",
};

// Env variables that OneDrive sets to its (possibly relocated) root.
const ONEDRIVE_ENV = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"];

function looksWindows(p: string): boolean {
	return /^[A-Za-z]:[\\/]/.test(p) || p.startsWith("\\\\") || p.includes("\\");
}

/** Absolute, forward-slash, lower-case form. Style follows the path, not the host OS. */
function normalize(p: string): string {
	const abs = looksWindows(p)
		? win32.resolve(p)
		: posix.isAbsolute(p)
			? posix.resolve(p)
			: hostResolve(p);
	return abs.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

function providerOf(segment: string, parent: string): SyncProvider | null {
	const cloudStorage = parent === "cloudstorage";
	if (
		segment === "onedrive" ||
		segment.startsWith("onedrive -") ||
		(cloudStorage && segment.startsWith("onedrive-"))
	)
		return "onedrive";
	if (segment === "dropbox" || segment.startsWith("dropbox ("))
		return "dropbox";
	if (
		segment.startsWith("icloud drive") ||
		segment === "iclouddrive" ||
		segment === "com~apple~clouddocs"
	)
		return "icloud";
	if (
		segment === "google drive" ||
		segment === "googledrive" ||
		(cloudStorage && segment.startsWith("googledrive-")) ||
		segment === "my drive" ||
		segment === "mi unidad" ||
		segment === "meu drive" ||
		segment === "shared drives" ||
		segment === "unidades compartidas"
	)
		return "google-drive";
	return null;
}

export interface DetectOptions {
	env?: Record<string, string | undefined>;
}

/** Pure, path-based check. Works the same for Windows and POSIX shaped paths. */
export function detectSyncedFolder(
	path: string,
	opts: DetectOptions = {},
): SyncedFolder | null {
	const norm = normalize(path);
	const env = opts.env ?? process.env;
	for (const key of ONEDRIVE_ENV) {
		const raw = env[key];
		if (raw === undefined || raw === "") continue;
		const root = normalize(raw);
		if (norm === root || norm.startsWith(`${root}/`)) {
			return { proveedor: "onedrive", nombre: NOMBRES.onedrive };
		}
	}
	const parts = norm.split("/");
	for (const [i, segment] of parts.entries()) {
		const proveedor = providerOf(segment, parts[i - 1] ?? "");
		if (proveedor !== null) return { proveedor, nombre: NOMBRES[proveedor] };
	}
	return null;
}

async function realOfExistingAncestor(path: string): Promise<string | null> {
	let current = resolveAbs(path);
	for (;;) {
		try {
			return await realpath(current);
		} catch {
			const parent = dirname(current);
			if (parent === current) return null;
			current = parent;
		}
	}
}

function resolveAbs(p: string): string {
	return looksWindows(p) ? win32.resolve(p) : hostResolve(p);
}

export interface GuardOptions {
	dest: string;
	isTTY: boolean;
	lang?: Lang;
	env?: Record<string, string | undefined>;
	/** Asks the human; only used with a TTY. Missing means "no". */
	confirmar?: (info: {
		proveedor: SyncProvider;
		nombre: string;
		ruta: string;
	}) => Promise<boolean>;
}

export interface GuardResult {
	sincronizado: boolean;
	proveedor?: SyncProvider;
}

const MSG = {
	es: {
		sinTty:
			"El destino está en una carpeta sincronizada y no hay terminal para confirmar. No se copió nada. Usa --dest con una carpeta local.",
		rechazado:
			"Cancelado: el workspace habría quedado en una carpeta sincronizada. No se copió nada.",
		accion: "Usa: mct init <origen> --dest <carpeta local>",
	},
	en: {
		sinTty:
			"The destination is in a synced folder and there is no terminal to confirm. Nothing was copied. Use --dest with a local folder.",
		rechazado:
			"Cancelled: the workspace would have been inside a synced folder. Nothing was copied.",
		accion: "Use: mct init <source> --dest <local folder>",
	},
} as const;

/**
 * CLI-006. Runs before any copy. Synced destination: without TTY or without a
 * positive confirmation the result is CANCELADO. Never asks when not synced.
 */
export async function guardSyncedDestination(
	opts: GuardOptions,
): Promise<GuardResult> {
	const lang = opts.lang ?? "es";
	const detectOpts: DetectOptions = opts.env ? { env: opts.env } : {};
	let found = detectSyncedFolder(opts.dest, detectOpts);
	if (found === null) {
		const real = await realOfExistingAncestor(opts.dest);
		if (real !== null) found = detectSyncedFolder(real, detectOpts);
	}
	if (found === null) return { sincronizado: false };

	const m = MSG[lang];
	if (!opts.isTTY) {
		throw new MctError("CANCELADO", m.sinTty, {
			etapa: "init",
			accion: m.accion,
			detalle: { proveedor: found.proveedor },
		});
	}
	const answer: unknown =
		opts.confirmar === undefined
			? false
			: await opts.confirmar({
					proveedor: found.proveedor,
					nombre: found.nombre,
					ruta: opts.dest,
				});
	// Only a literal `true` confirms: a clack cancel Symbol or anything else cancels.
	if (answer !== true) {
		throw new MctError("CANCELADO", m.rechazado, {
			etapa: "init",
			accion: m.accion,
			detalle: { proveedor: found.proveedor },
		});
	}
	return { sincronizado: true, proveedor: found.proveedor };
}

// ---------------------------------------------------------------- SEC-001

export type PermState = "ok" | "aviso" | "ausente" | "indeterminado";

export interface PermResult {
	estado: PermState;
	mensaje: string;
	accion?: string;
}

export interface PermOptions {
	path: string;
	lang?: Lang;
	platform?: NodeJS.Platform;
	user?: string;
	stat?: (path: string) => Promise<{ mode: number }>;
	/** Test hook: existence check for the Windows branch. */
	exists?: (path: string) => Promise<boolean>;
	/** Returns icacls output for `path`. Throws if it cannot run. */
	runIcacls?: (path: string) => string;
	env?: Record<string, string | undefined>;
}

export function defaultDictionaryPath(home: string = homedir()): string {
	return join(home, ".mct", "sensible.txt");
}

function isErrno(e: unknown, code: string): boolean {
	return (
		typeof e === "object" &&
		e !== null &&
		(e as { code?: unknown }).code === code
	);
}

function runIcaclsAbsolute(
	path: string,
	env: Record<string, string | undefined>,
): string {
	// Absolute path to the system binary: never resolved through PATH or cwd.
	const root = env.SystemRoot ?? env.windir;
	if (root === undefined || !win32.isAbsolute(root)) {
		throw new Error("SystemRoot not available");
	}
	return execFileSync(win32.join(root, "System32", "icacls.exe"), [path], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
		windowsHide: true,
	});
}

/** Principals of every ACE in icacls output. Independent of the OS language. */
function aclPrincipals(output: string, path: string): string[] {
	const text = output.split(path).join("");
	const out: string[] = [];
	for (const line of text.split(/\r?\n/)) {
		const m = /^\s*(.+?):\(/.exec(line);
		if (m?.[1] !== undefined) out.push(m[1].trim());
	}
	return out;
}

const PERM_MSG = {
	es: {
		aviso: (p: string) =>
			`El diccionario ${p} tiene permisos abiertos: otros usuarios del equipo podrían leerlo.`,
		indet: (p: string) =>
			`No se pudieron comprobar los permisos de ${p}; revisa que solo tu usuario pueda leerlo.`,
		accionIndet: (a: string) => `Revisa a mano y, si hace falta, ejecuta: ${a}`,
	},
	en: {
		aviso: (p: string) =>
			`The dictionary ${p} has open permissions: other users on this machine could read it.`,
		indet: (p: string) =>
			`Could not check the permissions of ${p}; make sure only your user can read it.`,
		accionIndet: (a: string) => `Check manually and, if needed, run: ${a}`,
	},
} as const;

/** SEC-001. Missing file is "ausente"; a check that cannot decide is "indeterminado" (a warning). */
export async function checkDictionaryPerms(
	opts: PermOptions,
): Promise<PermResult> {
	const lang = opts.lang ?? "es";
	const platform = opts.platform ?? process.platform;
	const env = opts.env ?? process.env;
	const m = PERM_MSG[lang];
	const path = opts.path;
	const statFn = opts.stat ?? fsStat;
	const win = platform === "win32";

	let user = opts.user;
	if (win && user === undefined) {
		try {
			user = userInfo().username;
		} catch {
			user = undefined;
		}
	}
	const fixPosix = `chmod 600 "${path}"`;
	const fixWin = `icacls "${path}" /inheritance:r /grant:r "${user ?? "%USERNAME%"}:F"`;
	const fix = win ? fixWin : fixPosix;
	const indeterminado = (): PermResult => ({
		estado: "indeterminado",
		mensaje: m.indet(path),
		accion: m.accionIndet(fix),
	});

	let mode = 0;
	if (win && opts.exists !== undefined) {
		if (!(await opts.exists(path))) {
			return { estado: "ausente", mensaje: "" };
		}
	} else {
		try {
			mode = (await statFn(path)).mode;
		} catch (e) {
			if (isErrno(e, "ENOENT")) return { estado: "ausente", mensaje: "" };
			return indeterminado();
		}
	}

	if (!win) {
		if ((mode & 0o077) === 0) return { estado: "ok", mensaje: "" };
		return { estado: "aviso", mensaje: m.aviso(path), accion: fixPosix };
	}

	if (user === undefined) return indeterminado();
	let output: string;
	try {
		output = (opts.runIcacls ?? ((p) => runIcaclsAbsolute(p, env)))(path);
	} catch {
		return indeterminado();
	}
	const principals = aclPrincipals(output, path);
	if (principals.length === 0) return indeterminado();
	const me = user.toLowerCase();
	const onlyMe = principals.every(
		(p) => (p.split("\\").pop() ?? "").toLowerCase() === me,
	);
	if (onlyMe) return { estado: "ok", mensaje: "" };
	return { estado: "aviso", mensaje: m.aviso(path), accion: fixWin };
}
