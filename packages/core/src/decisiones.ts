import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { type FileHandle, lstat, open, realpath } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { MctError, redactTokens } from "@mct/contract/errors";

export const MOTIVO_MIN = 10;
export const MOTIVO_MAX = 500;
/** SAN-012: "1 MB o más" is rejected (decimal megabyte: the stricter reading). */
export const DECISIONES_MAX_BYTES = 1_000_000;

const SHA256 = /^[0-9a-f]{64}$/;
export const PLACEHOLDER = /^[A-Z][A-Z0-9_]{0,63}$/;
const REF_MIN = 4;

export interface EntradaDecision {
	id: string;
	accion: "falso-positivo" | "reemplazar";
	motivo?: string;
	nombre?: string;
}

export interface ArchivoDecisiones {
	entradas: EntradaDecision[];
	/** SHA-256 of the file bytes. */
	sha256: string;
}

export interface OrigenInfo {
	tipo: string;
	ref: string;
}

function validacion(
	mensaje: string,
	detalle?: Record<string, unknown>,
	accion?: string,
): MctError {
	return new MctError("VALIDACION", mensaje, {
		etapa: "sanitize",
		...(accion !== undefined && { accion }),
		...(detalle !== undefined && { detalle }),
	});
}

const INVISIBLES = new RegExp(
	[
		"\\p{Cc}",
		"\\p{Cf}",
		"\\p{Cs}",
		"\\p{Co}",
		"\\p{Cn}",
		"\\p{Zl}",
		"\\p{Zp}",
		"\\u00A0\\u1680\\u2000-\\u200A\\u202F\\u205F\\u3000",
		"\\u2800\\u3164\\u115F\\u1160\\uFFA0\\u180E\\u034F",
		"\\uFE00-\\uFE0F",
	]
		.join("")
		.replace(/^/, "[")
		.concat("]"),
	"u",
);

const plegar = (t: string): string => t.normalize("NFKC").toLowerCase();

/**
 * SAN-002: 10 to 500 visible characters, one line, no invisible characters, no token and no
 * reference value (4+ characters, case-insensitive after NFKC) as a substring. The error never
 * repeats the offending value.
 */
export function validarMotivo(
	motivo: unknown,
	referencias: Iterable<string> = [],
): string {
	if (typeof motivo !== "string") {
		throw validacion(
			"El motivo es obligatorio",
			undefined,
			"Escribe un motivo de 10 a 500 caracteres",
		);
	}
	if (INVISIBLES.test(motivo)) {
		throw validacion("El motivo tiene caracteres invisibles o de control");
	}
	const limpio = motivo.trim();
	const largo = Array.from(limpio).length;
	if (largo < MOTIVO_MIN || largo > MOTIVO_MAX) {
		throw validacion(
			`El motivo debe tener entre ${MOTIVO_MIN} y ${MOTIVO_MAX} caracteres`,
		);
	}
	if (redactTokens(limpio) !== limpio) {
		throw validacion("El motivo parece contener un token");
	}
	const pajar = plegar(limpio);
	for (const ref of referencias) {
		const r = plegar(ref).trim();
		if (Array.from(r).length >= REF_MIN && pajar.includes(r)) {
			throw validacion(
				"El motivo no puede contener un valor de un hallazgo ni un término del diccionario",
			);
		}
	}
	return limpio;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

function dentro(padre: string, hijo: string): boolean {
	const r = relative(padre, hijo);
	return (
		r === "" ||
		(!r.startsWith("..") && !r.startsWith(sep) && !/^[A-Za-z]:/.test(r))
	);
}

async function realOpcional(p: string): Promise<string | null> {
	try {
		return await realpath(p);
	} catch {
		return null;
	}
}

/**
 * SAN-012 / SAN-015: reads and validates the whole decisions file (shape and location) before
 * anything is applied. Any defect is `VALIDACION`; messages never carry file content.
 */
export async function leerArchivoDecisiones(
	ruta: string,
	ctx: { raiz: string; origen: OrigenInfo },
): Promise<ArchivoDecisiones> {
	const abs = resolve(ruta);
	// TOCTOU: open once and decide on the descriptor. POSIX refuses a final link with
	// O_NOFOLLOW; Windows has no such flag, so a link is rejected with lstat beforehand.
	const posix = process.platform !== "win32";
	if (!posix) {
		let previo: Awaited<ReturnType<typeof lstat>> | undefined;
		try {
			previo = await lstat(abs);
		} catch {
			throw validacion(
				"El archivo de decisiones no existe o no se puede leer",
				{
					motivo: "ausente",
				},
			);
		}
		if (previo.isSymbolicLink()) {
			throw validacion("El archivo de decisiones no puede ser un enlace", {
				motivo: "enlace",
			});
		}
	}
	let fh: FileHandle;
	try {
		fh = await open(
			abs,
			posix
				? constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
				: constants.O_RDONLY,
		);
	} catch (e) {
		if (posix && (e as NodeJS.ErrnoException).code === "ELOOP") {
			throw validacion("El archivo de decisiones no puede ser un enlace", {
				motivo: "enlace",
			});
		}
		throw validacion("El archivo de decisiones no existe o no se puede leer", {
			motivo: "ausente",
		});
	}
	try {
		return await leerDesdeDescriptor(fh, abs, ctx);
	} finally {
		await fh.close().catch(() => undefined);
	}
}

async function leerDesdeDescriptor(
	fh: FileHandle,
	abs: string,
	ctx: { raiz: string; origen: OrigenInfo },
): Promise<ArchivoDecisiones> {
	const st = await fh.stat();
	if (!st.isFile()) {
		throw validacion("El archivo de decisiones no es un archivo regular", {
			motivo: "no-regular",
		});
	}
	if (st.size >= DECISIONES_MAX_BYTES) {
		throw validacion("El archivo de decisiones es demasiado grande", {
			motivo: "tamano",
		});
	}

	// SAN-015: location. Real paths, so a linked folder cannot smuggle it inside.
	const padreReal = await realOpcional(dirname(abs));
	if (padreReal === null) {
		throw validacion("El archivo de decisiones no se puede leer", {
			motivo: "ilegible",
		});
	}
	const real = join(padreReal, basename(abs));
	const raizReal = (await realOpcional(ctx.raiz)) ?? resolve(ctx.raiz);
	if (dentro(raizReal, real)) {
		throw validacion(
			"El archivo de decisiones no puede estar dentro de .mct (work, dist o quarantine)",
			{ motivo: "ubicacion" },
			"Muévelo a <dest>/decisiones.json con chmod 600 y repite",
		);
	}
	if (ctx.origen.tipo === "carpeta") {
		const origenReal = await realOpcional(ctx.origen.ref);
		if (origenReal !== null && dentro(origenReal, real)) {
			const destReal = dirname(raizReal);
			const permitido =
				real === join(origenReal, "decisiones.json") && destReal === origenReal;
			if (!permitido) {
				throw validacion(
					"El archivo de decisiones no puede estar dentro del origen",
					{ motivo: "ubicacion" },
					"Muévelo a <dest>/decisiones.json con chmod 600 y repite",
				);
			}
		}
	}
	if (process.platform !== "win32" && (st.mode & 0o077) !== 0) {
		throw validacion(
			"El archivo de decisiones tiene permisos demasiado abiertos",
			{ motivo: "permisos" },
			"Corre: chmod 600 decisiones.json",
		);
	}

	let raw: Buffer;
	try {
		raw = await fh.readFile();
	} catch {
		throw validacion("El archivo de decisiones no se puede leer", {
			motivo: "ilegible",
		});
	}
	if (raw.length >= DECISIONES_MAX_BYTES) {
		throw validacion("El archivo de decisiones es demasiado grande", {
			motivo: "tamano",
		});
	}
	let doc: unknown;
	try {
		doc = JSON.parse(raw.toString("utf8"));
	} catch {
		throw validacion("El archivo de decisiones no es JSON válido", {
			motivo: "json",
		});
	}
	if (!isObj(doc)) {
		throw validacion("El archivo de decisiones tiene una forma inválida", {
			motivo: "forma",
		});
	}
	for (const k of Object.keys(doc)) {
		if (k !== "schemaVersion" && k !== "decisiones") {
			throw validacion("El archivo de decisiones trae una clave desconocida", {
				motivo: "clave-desconocida",
			});
		}
	}
	if (doc.schemaVersion !== 1) {
		throw validacion(
			"El archivo de decisiones trae un schemaVersion no admitido",
			{ motivo: "schemaVersion" },
		);
	}
	if (!Array.isArray(doc.decisiones)) {
		throw validacion("El archivo de decisiones no trae la lista decisiones", {
			motivo: "forma",
		});
	}
	const entradas: EntradaDecision[] = [];
	for (const [n, e] of doc.decisiones.entries()) {
		const mal = (motivo: string): MctError =>
			validacion(`La entrada ${n + 1} del archivo de decisiones no es válida`, {
				motivo,
				entrada: n + 1,
			});
		if (!isObj(e)) throw mal("forma");
		for (const k of Object.keys(e)) {
			if (!["id", "accion", "motivo", "nombre"].includes(k)) {
				throw mal("clave-desconocida");
			}
		}
		if (typeof e.id !== "string" || !SHA256.test(e.id)) throw mal("id");
		if (e.accion !== "falso-positivo" && e.accion !== "reemplazar") {
			throw mal("accion");
		}
		if (e.accion === "falso-positivo") {
			if (e.nombre !== undefined) throw mal("nombre");
			if (typeof e.motivo !== "string") throw mal("motivo");
			entradas.push({ id: e.id, accion: e.accion, motivo: e.motivo });
		} else {
			if (e.motivo !== undefined) throw mal("motivo");
			if (e.nombre !== undefined) {
				if (typeof e.nombre !== "string" || !PLACEHOLDER.test(e.nombre)) {
					throw mal("nombre");
				}
				entradas.push({ id: e.id, accion: e.accion, nombre: e.nombre });
			} else {
				entradas.push({ id: e.id, accion: e.accion });
			}
		}
	}
	return {
		entradas,
		sha256: createHash("sha256").update(raw).digest("hex"),
	};
}
