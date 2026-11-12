import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
	chmod,
	lstat,
	mkdir,
	readFile,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type {
	EstadoEtapa,
	Etapa,
	Finding,
	State,
	Workspace,
} from "@mct/contract/types";
import { CLAVE_BYTES } from "@mct/scanner/finding-id";

export const STATE_SCHEMA_VERSION = 1;

export const ETAPAS: readonly Etapa[] = [
	"init",
	"scan",
	"sanitize",
	"licenses",
	"package",
	"verify",
	"publish",
];

const WORK_CASCADE: readonly Etapa[] = [
	"sanitize",
	"licenses",
	"package",
	"verify",
];

const DECIDIDOS = new Set(["resuelto", "falso-positivo", "aceptado"]);

export interface InitOptions {
	mctVersion: string;
	origen: State["origen"];
	adapter: string;
	now?: () => string;
}

function invalido(
	mensaje: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		accion: "Revisa el workspace o recréalo con init --force",
		...(detalle !== undefined && { detalle }),
	});
}

/** Restrict a path to the current user: chmod on POSIX, icacls on Windows. */
async function restrict(path: string, dir: boolean): Promise<void> {
	if (process.platform === "win32") {
		const user = userInfo().username;
		const grant = dir ? `${user}:(OI)(CI)F` : `${user}:F`;
		try {
			execFileSync("icacls", [path, "/inheritance:r", "/grant:r", grant], {
				stdio: "ignore",
			});
		} catch (cause) {
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"No se pudieron aplicar los permisos",
				{ cause, detalle: { ruta: path } },
			);
		}
		return;
	}
	await chmod(path, dir ? 0o700 : 0o600);
}

/** `raiz` is the `.mct/` directory (holds state.json, lock, work/, dist/...). */
export function workspacePaths(raiz: string): Workspace {
	return {
		raiz,
		work: join(raiz, "work"),
		quarantine: join(raiz, "quarantine"),
		dist: join(raiz, "dist"),
		estado: () => readState(raiz),
	};
}

/** Writes the 32-byte HMAC key of Finding.id (SCAN-015): 0600 / user-only ACL, never logged. */
async function writeClave(raiz: string): Promise<void> {
	const destino = join(raiz, "clave");
	await writeFile(destino, randomBytes(CLAVE_BYTES), { mode: 0o600 });
	await restrict(destino, false);
}

/** Creates `.mct/` with 0700 dirs, a 0600 state.json and the 0600 `clave` (SCAN-015). */
export async function createWorkspace(
	raiz: string,
	init: InitOptions,
): Promise<Workspace> {
	const ws = workspacePaths(raiz);
	await assertNoLinks(raiz);
	const ts = (init.now ?? (() => new Date().toISOString()))();
	await mkdir(raiz, { recursive: true });
	await restrict(raiz, true);
	for (const dir of [ws.work, ws.quarantine, ws.dist]) {
		await mkdir(dir, { recursive: true });
		await restrict(dir, true);
	}
	await assertNoLinks(raiz);
	await writeClave(raiz);
	const etapas = {} as State["etapas"];
	for (const e of ETAPAS) {
		etapas[e] = { estado: e === "init" ? "ok" : "pendiente", ts };
	}
	await writeState(raiz, {
		schemaVersion: STATE_SCHEMA_VERSION,
		mctVersion: init.mctVersion,
		origen: init.origen,
		adapter: init.adapter,
		workSha256: "",
		distSha256: "",
		verificado: null,
		etapas,
	});
	return ws;
}

/** SEG-010: `.mct` and its subdirectories must not be symlinks or junctions. */
async function assertNoLinks(raiz: string): Promise<void> {
	for (const dir of [
		raiz,
		join(raiz, "work"),
		join(raiz, "quarantine"),
		join(raiz, "dist"),
	]) {
		let st: Awaited<ReturnType<typeof lstat>>;
		try {
			st = await lstat(dir);
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code === "ENOENT") continue;
			throw invalido("No se pudo inspeccionar el workspace", { cause });
		}
		if (st.isSymbolicLink()) {
			throw invalido("El workspace no puede ser un enlace simbólico", {
				ruta: dir,
			});
		}
		if (!st.isDirectory()) {
			throw invalido("El workspace no es un directorio", { ruta: dir });
		}
	}
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);
const isHash = (v: unknown): boolean =>
	typeof v === "string" && (v === "" || /^[0-9a-f]{64}$/.test(v));
const ESTADOS_ETAPA = new Set(["pendiente", "ok", "bloqueada"]);
const TIPOS_ORIGEN = new Set(["carpeta", "github", "n8n-json"]);

function assertStateShape(v: unknown): asserts v is State {
	const mal = (campo: string): never => {
		throw invalido("state.json tiene una forma inválida", { campo });
	};
	if (!isObj(v)) return mal("raiz");
	if (typeof v.mctVersion !== "string") mal("mctVersion");
	if (typeof v.adapter !== "string") mal("adapter");
	const o = v.origen;
	if (
		!isObj(o) ||
		typeof o.tipo !== "string" ||
		!TIPOS_ORIGEN.has(o.tipo) ||
		typeof o.ref !== "string"
	) {
		mal("origen");
	}
	if (!isHash(v.workSha256)) mal("workSha256");
	if (!isHash(v.distSha256)) mal("distSha256");
	const ver = v.verificado;
	if (
		ver !== null &&
		(!isObj(ver) ||
			!isHash(ver.distSha256) ||
			typeof ver.destino !== "string" ||
			typeof ver.ts !== "string")
	) {
		mal("verificado");
	}
	const et = v.etapas;
	if (!isObj(et)) return mal("etapas");
	for (const e of ETAPAS) {
		const x = et[e];
		if (
			!isObj(x) ||
			typeof x.estado !== "string" ||
			!ESTADOS_ETAPA.has(x.estado) ||
			typeof x.ts !== "string"
		) {
			mal(`etapas.${e}`);
		}
	}
}

export async function readState(raiz: string): Promise<State> {
	await assertNoLinks(raiz);
	let raw: string;
	try {
		raw = await readFile(join(raiz, "state.json"), "utf8");
	} catch (cause) {
		throw new MctError("WORKSPACE_INVALIDO", "No hay un state.json legible", {
			cause,
			accion: "Corre init primero",
		});
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (cause) {
		throw new MctError("WORKSPACE_INVALIDO", "state.json no es JSON válido", {
			cause,
		});
	}
	const version =
		parsed !== null && typeof parsed === "object"
			? (parsed as { schemaVersion?: unknown }).schemaVersion
			: undefined;
	if (version !== STATE_SCHEMA_VERSION) {
		throw invalido("state.json trae un schemaVersion desconocido", {
			esperado: STATE_SCHEMA_VERSION,
			recibido: version ?? null,
		});
	}
	assertStateShape(parsed);
	return parsed;
}

/** Atomic write (temp file + rename), 0600. Caller should hold the lock. */
export async function writeState(raiz: string, state: State): Promise<void> {
	if (state.schemaVersion !== STATE_SCHEMA_VERSION) {
		throw invalido("schemaVersion desconocido al escribir state.json");
	}
	assertStateShape(state);
	await assertNoLinks(raiz);
	const destino = join(raiz, "state.json");
	const tmp = `${destino}.${process.pid}.tmp`;
	await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
	await restrict(tmp, false);
	await rename(tmp, destino);
}

function pidVivo(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (cause) {
		return (cause as NodeJS.ErrnoException).code === "EPERM";
	}
}

async function lockHuerfano(lock: string): Promise<boolean> {
	let txt: string;
	try {
		txt = await readFile(lock, "utf8");
	} catch {
		return false;
	}
	const pid = Number.parseInt(txt.trim(), 10);
	if (!Number.isInteger(pid) || pid <= 0) return false;
	return !pidVivo(pid);
}

/** Runs `fn` holding `.mct/lock`; rejects if a live command holds it. A lock left by a dead PID is recovered. */
export async function withLock<T>(
	raiz: string,
	fn: () => Promise<T>,
): Promise<T> {
	const lock = join(raiz, "lock");
	for (let intento = 0; ; intento++) {
		try {
			await writeFile(lock, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
			break;
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code === "EEXIST") {
				if (intento === 0 && (await lockHuerfano(lock))) {
					await rm(lock, { force: true });
					continue;
				}
				throw new MctError(
					"WORKSPACE_INVALIDO",
					"Otro comando tiene el lock del workspace",
					{
						accion:
							"Espera a que termine el otro comando; si no hay ninguno, borra .mct/lock",
						detalle: { lock: "lock" },
					},
				);
			}
			throw new MctError("WORKSPACE_INVALIDO", "No se pudo tomar el lock", {
				cause,
			});
		}
	}
	try {
		return await fn();
	} finally {
		await rm(lock, { force: true });
	}
}

/** Reads, mutates and atomically writes state under the lock. */
export function updateState(
	raiz: string,
	mutate: (s: State) => State,
): Promise<State> {
	return withLock(raiz, async () => {
		const next = mutate(await readState(raiz));
		await writeState(raiz, next);
		return next;
	});
}

function setPendiente(
	etapas: State["etapas"],
	lista: readonly Etapa[],
	ts: string,
): State["etapas"] {
	const out = { ...etapas };
	for (const e of lista) out[e] = { estado: "pendiente" as EstadoEtapa, ts };
	return out;
}

/** STATE-001 cascade rule. Pure: returns the new state. */
export function applyCascade(
	state: State,
	hashes: { workSha256?: string; distSha256?: string },
	ts: string = new Date().toISOString(),
): State {
	let next: State = { ...state };
	if (
		hashes.workSha256 !== undefined &&
		hashes.workSha256 !== state.workSha256
	) {
		next = {
			...next,
			workSha256: hashes.workSha256,
			etapas: setPendiente(next.etapas, WORK_CASCADE, ts),
		};
	}
	if (
		hashes.distSha256 !== undefined &&
		hashes.distSha256 !== state.distSha256
	) {
		next = {
			...next,
			distSha256: hashes.distSha256,
			etapas: setPendiente(next.etapas, ["verify"], ts),
		};
	}
	return next;
}

/**
 * Re-scan reconciliation: decided findings that do not reappear become obsoleto (never deleted).
 * resuelto/obsoleto that reappear reopen (D-045); falso-positivo/aceptado keep their decision.
 */
export function reconcileFindings(
	previos: readonly Finding[],
	rescan: readonly Finding[],
): Finding[] {
	const nuevos = new Map(rescan.map((f) => [f.id, f]));
	const vistos = new Set<string>();
	const out: Finding[] = [];
	for (const prev of previos) {
		vistos.add(prev.id);
		const actual = nuevos.get(prev.id);
		if (actual === undefined) {
			out.push(
				DECIDIDOS.has(prev.estado) ? { ...prev, estado: "obsoleto" } : prev,
			);
		} else if (prev.estado === "obsoleto" || prev.estado === "resuelto") {
			out.push({ ...actual, estado: "abierto" });
		} else {
			out.push(prev);
		}
	}
	for (const f of rescan) if (!vistos.has(f.id)) out.push(f);
	return out;
}
