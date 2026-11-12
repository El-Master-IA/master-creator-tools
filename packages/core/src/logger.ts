import { lstat, mkdir, open } from "node:fs/promises";
import { join } from "node:path";
import { MctError, redactTokens } from "@mct/contract/errors";
import type { Etapa } from "@mct/contract/types";
import { ETAPAS, readState } from "./workspace.js";

/** Only these fields can reach a log line (api.md › Observabilidad). Allow-list, not deny-list. */
export interface LogEvent {
	evento: string;
	duracionMs?: number;
	/** Relative path with `/`, never content. */
	archivo?: string;
	regla?: string;
	/** sha256 hex of the finding. */
	hallazgoId?: string;
}

export interface Logger {
	/** Appends one JSONL line to `.mct/logs/<etapa>.jsonl`. */
	log(event: LogEvent): Promise<void>;
	/** Logs only the error code, never its message, cause or detail. */
	error(err: unknown): Promise<void>;
}

export interface LoggerOptions {
	now?: () => string;
}

const ALLOWED = new Set([
	"evento",
	"duracionMs",
	"archivo",
	"regla",
	"hallazgoId",
]);
const MAX_TEXT = 512;
const SHA256 = /^[0-9a-f]{64}$/;

function rechazo(mensaje: string, detalle?: Record<string, unknown>): MctError {
	return new MctError("INTERNO", mensaje, {
		...(detalle !== undefined && { detalle }),
	});
}

function invalido(mensaje: string): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		accion: "Revisa el workspace o recréalo con init --force",
	});
}

function texto(campo: string, v: unknown): string {
	if (typeof v !== "string" || v === "" || v.length > MAX_TEXT) {
		throw rechazo("Campo de log inválido", { campo });
	}
	return redactTokens(v);
}

function ruta(v: unknown): string {
	const t = texto("archivo", v);
	if (
		t.includes("\0") ||
		t.startsWith("/") ||
		t.includes("\\") ||
		/^[A-Za-z]:/.test(t) ||
		t.split("/").includes("..")
	) {
		throw rechazo("Campo de log inválido", { campo: "archivo" });
	}
	return t;
}

function validar(event: unknown): Record<string, string | number> {
	if (event === null || typeof event !== "object" || Array.isArray(event)) {
		throw rechazo("El evento de log debe ser un objeto");
	}
	const raw = event as Record<string, unknown>;
	for (const key of Object.keys(raw)) {
		if (!ALLOWED.has(key)) {
			throw rechazo("Campo no permitido en el log", { campo: key });
		}
	}
	const out: Record<string, string | number> = {
		evento: texto("evento", raw.evento),
	};
	if (raw.duracionMs !== undefined) {
		const d = raw.duracionMs;
		if (typeof d !== "number" || !Number.isFinite(d) || d < 0) {
			throw rechazo("Campo de log inválido", { campo: "duracionMs" });
		}
		out.duracionMs = d;
	}
	if (raw.archivo !== undefined) out.archivo = ruta(raw.archivo);
	if (raw.regla !== undefined) out.regla = texto("regla", raw.regla);
	if (raw.hallazgoId !== undefined) {
		if (typeof raw.hallazgoId !== "string" || !SHA256.test(raw.hallazgoId)) {
			throw rechazo("Campo de log inválido", { campo: "hallazgoId" });
		}
		out.hallazgoId = raw.hallazgoId;
	}
	return out;
}

/** POSIX only: Windows relies on the inherited ACL set by `createWorkspace`. */
function assertClosed(mode: number, que: string): void {
	if (process.platform !== "win32" && (mode & 0o077) !== 0) {
		throw invalido(`${que} tiene permisos abiertos`);
	}
}

async function inspect(path: string, dir: boolean, que: string) {
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw new MctError("WORKSPACE_INVALIDO", `No se pudo inspeccionar ${que}`, {
			cause,
		});
	}
	if (st.isSymbolicLink()) throw invalido(`${que} no puede ser un enlace`);
	if (dir ? !st.isDirectory() : !st.isFile()) {
		throw invalido(`${que} no tiene el tipo esperado`);
	}
	assertClosed(st.mode, que);
	return st;
}

async function prepare(raiz: string, etapa: Etapa): Promise<string> {
	await readState(raiz); // links in .mct and valid workspace, fail closed
	await inspect(raiz, true, ".mct");
	const dir = join(raiz, "logs");
	if ((await inspect(dir, true, "logs")) === undefined) {
		try {
			await mkdir(dir, { mode: 0o700 });
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code !== "EEXIST") {
				throw new MctError("WORKSPACE_INVALIDO", "No se pudo crear logs/", {
					cause,
				});
			}
		}
		await inspect(dir, true, "logs");
	}
	const file = join(dir, `${etapa}.jsonl`);
	await inspect(file, false, `logs/${etapa}.jsonl`);
	return file;
}

export function createLogger(
	raiz: string,
	etapa: Etapa,
	options: LoggerOptions = {},
): Logger {
	if (!ETAPAS.includes(etapa)) {
		throw new MctError("VALIDACION", "Etapa de log desconocida");
	}
	const now = options.now ?? (() => new Date().toISOString());
	let cola: Promise<void> = Promise.resolve();

	async function escribe(line: string): Promise<void> {
		const file = await prepare(raiz, etapa);
		const fh = await open(file, "a", 0o600);
		try {
			await fh.appendFile(line, "utf8");
		} finally {
			await fh.close();
		}
	}

	function enqueue(fields: Record<string, string | number>): Promise<void> {
		const line = redactTokens(
			`${JSON.stringify({ ts: now(), etapa, ...fields })}\n`,
		);
		const next = cola.then(() => escribe(line));
		cola = next.catch(() => undefined);
		return next;
	}

	return {
		log: async (event) => enqueue(validar(event)),
		error: async (err) => {
			const codigo = err instanceof MctError ? err.codigo : "INTERNO";
			await enqueue({ evento: `error.${codigo}` });
		},
	};
}
