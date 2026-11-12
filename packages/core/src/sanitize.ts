import { createHash, randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import { chmod, copyFile, lstat, mkdir, readFile, rm } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { MctError, redactTokens } from "@mct/contract/errors";
import type {
	Adapter,
	Change,
	Etapa,
	Finding,
	State,
} from "@mct/contract/types";
import { findingId, normalizeValue } from "@mct/scanner/finding-id";
import type { LicenseRow, ReportLang } from "@mct/templates/report";
import { isMaskedFragment, renderReport } from "@mct/templates/report";
import {
	APPROVAL_FILE,
	invalidateApproval,
	signApproval,
	writeFileAtomic,
} from "./approval.js";
import { hashTree } from "./hash.js";
import { createLogger } from "./logger.js";
import {
	applyCascade,
	ETAPAS,
	readState,
	reconcileFindings,
	withLock,
	workspacePaths,
	writeState,
} from "./workspace.js";

export const FINDINGS_SCHEMA_VERSION = 1;
export const FINDINGS_FILE = "findings.json";

/** Review rounds before the gate stays closed (new findings can appear after a re-scan). */
const MAX_RONDAS = 3;
/** Longest value searched when locating a finding in its file. */
const MAX_VALUE_CHARS = 8192;
const MOTIVO_MIN = 10;
const MOTIVO_MAX = 500;

const SHA256 = /^[0-9a-f]{64}$/;
const PLACEHOLDER = /^[A-Z][A-Z0-9_]{0,63}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const DIC_MASK = /\[dic:\d+\]/;
const DECIDIDOS = new Set(["resuelto", "falso-positivo", "aceptado"]);

export type Decision =
	| { accion: "reemplazar"; nombre?: string }
	| { accion: "falso-positivo"; motivo: string }
	| { accion: "aceptar"; motivo: string }
	| { accion: "abortar" };

export interface DecisionContext {
	/** Placeholder name proposed for "Reemplazar" (empty for a binary). */
	sugerido: string;
	/** False when the finding cannot be located in work/ (masked path, stale, structural). */
	puedeReemplazar: boolean;
	/** True for `binario`: "Reemplazar" deletes the file. */
	eliminar: boolean;
}

export interface ResumenAuto {
	reemplazos: { id: string; archivo: string; regla: string; nombre: string }[];
}

/** Injected decision-maker: core never prompts (the CLI wraps clack with isCancel and TTY checks). */
export interface Decisor {
	decidir(hallazgo: Readonly<Finding>, ctx: DecisionContext): Promise<Decision>;
	/** `--auto-placeholders` still needs a human "yes" on the summary. */
	confirmar(resumen: ResumenAuto): Promise<boolean>;
}

export interface RescanResult {
	hallazgos: Finding[];
	gitleaksVersion: string;
}

export interface SanitizeOptions {
	/** Absolute `.mct`. */
	raiz: string;
	/** `process.stdin.isTTY`: without it nothing is approved (SAN-004). */
	tty: boolean;
	decisor: Decisor;
	/** Injected fresh scan of the current tree (no previous findings; core reconciles). */
	rescan: (ctx: { signal?: AbortSignal }) => Promise<RescanResult>;
	adapter?: Pick<Adapter, "sanitize">;
	autoPlaceholders?: boolean;
	reopen?: string;
	/** Ctrl+C: aborts, restores the workspace and rejects with INTERRUMPIDO (130). */
	signal?: AbortSignal;
	mctVersion?: string;
	lang?: ReportLang;
	now?: () => string;
	usuario?: () => string;
}

export interface SanitizeResult {
	decididos: { resuelto: number; falsoPositivo: number; aceptado: number };
	abiertos: number;
	aprobacion: { arbolSha256: string } | null;
}

function validacion(
	mensaje: string,
	detalle?: Record<string, unknown>,
	accion?: string,
): MctError {
	return new MctError("VALIDACION", mensaje, {
		...(accion !== undefined && { accion }),
		...(detalle !== undefined && { detalle }),
	});
}

function interrumpido(): MctError {
	return new MctError("INTERRUMPIDO", "Interrumpido por la persona", {
		accion: "Vuelve a correr: mct sanitize",
		etapa: "sanitize",
	});
}

// ---------------------------------------------------------------- findings.json

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

const MOTORES = new Set(["mct", "gitleaks"]);
const TIPOS = new Set(["secreto", "pii", "estructura", "binario"]);
const ZONAS = new Set(["work", "quarantine"]);
const SEVERIDADES = new Set(["critico", "alto", "medio", "bajo"]);
const ESTADOS = new Set([
	"abierto",
	"resuelto",
	"falso-positivo",
	"aceptado",
	"obsoleto",
	"aislado",
]);

/** Strict copy: unknown fields are dropped so nothing extra ever reaches disk or the report. */
function toFinding(
	v: unknown,
	codigo: "WORKSPACE_INVALIDO" | "MOTOR_NO_DISPONIBLE",
): Finding {
	const mal = (campo: string): never => {
		throw new MctError(codigo, "Un hallazgo tiene una forma inválida", {
			detalle: { campo },
		});
	};
	if (!isObj(v)) return mal("raiz");
	const str = (k: string): string => {
		const x = v[k];
		return typeof x === "string" ? x : mal(k);
	};
	const int = (k: string): number => {
		const x = v[k];
		return typeof x === "number" && Number.isInteger(x) && x >= 0 ? x : mal(k);
	};
	const id = str("id");
	if (!SHA256.test(id)) mal("id");
	if (!MOTORES.has(str("motor"))) mal("motor");
	if (!TIPOS.has(str("tipo"))) mal("tipo");
	if (!ZONAS.has(str("zona"))) mal("zona");
	if (!SEVERIDADES.has(str("severidad"))) mal("severidad");
	if (!ESTADOS.has(str("estado"))) mal("estado");
	if (!isMaskedFragment(str("fragmento"))) mal("fragmento");
	const f: Finding = {
		id,
		motor: v.motor as Finding["motor"],
		regla: str("regla"),
		tipo: v.tipo as Finding["tipo"],
		zona: v.zona as Finding["zona"],
		archivo: str("archivo"),
		linea: int("linea"),
		columna: int("columna"),
		fragmento: str("fragmento"),
		severidad: v.severidad as Finding["severidad"],
		estado: v.estado as Finding["estado"],
	};
	for (const k of ["motivo", "decidio", "decididoEn"] as const) {
		if (v[k] !== undefined) f[k] = str(k);
	}
	return f;
}

async function readFindings(raiz: string): Promise<Finding[]> {
	const file = join(raiz, FINDINGS_FILE);
	let raw: string;
	try {
		if ((await lstat(file)).isSymbolicLink()) throw new Error("link");
		raw = await readFile(file, "utf8");
	} catch (cause) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"No hay un findings.json legible",
			{
				cause,
				accion: "Corre: mct scan",
			},
		);
	}
	let doc: unknown;
	try {
		doc = JSON.parse(raw);
	} catch (cause) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"findings.json no es JSON válido",
			{
				cause,
			},
		);
	}
	if (!isObj(doc) || doc.schemaVersion !== FINDINGS_SCHEMA_VERSION) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"findings.json trae un schemaVersion desconocido",
			{ detalle: { esperado: FINDINGS_SCHEMA_VERSION } },
		);
	}
	if (!Array.isArray(doc.hallazgos)) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"findings.json no tiene hallazgos",
		);
	}
	return doc.hallazgos.map((h) => toFinding(h, "WORKSPACE_INVALIDO"));
}

// ---------------------------------------------------------------- safe paths

/** Relative `/` path inside `root`, no masks, no links on the way, ending in a regular file. */
async function inside(root: string, rel: unknown): Promise<string | null> {
	if (
		typeof rel !== "string" ||
		rel === "" ||
		rel.includes("\0") ||
		rel.includes("\\") ||
		rel.startsWith("/") ||
		/^[A-Za-z]:/.test(rel) ||
		DIC_MASK.test(rel)
	) {
		return null;
	}
	const parts = rel.split("/");
	if (parts.some((p) => p === "" || p === "." || p === "..")) return null;
	let at = root;
	for (const p of parts) {
		at = join(at, p);
		let st: Stats;
		try {
			st = await lstat(at);
		} catch {
			return null;
		}
		if (st.isSymbolicLink()) return null;
	}
	const st = await lstat(at);
	return st.isFile() ? at : null;
}

/** Same rules for a path that may not exist yet (`crear`): returns the absolute target. */
async function targetInside(
	root: string,
	rel: unknown,
): Promise<string | null> {
	if (
		typeof rel !== "string" ||
		rel === "" ||
		rel.includes("\0") ||
		rel.includes("\\") ||
		rel.startsWith("/") ||
		/^[A-Za-z]:/.test(rel)
	) {
		return null;
	}
	const parts = rel.split("/");
	if (parts.some((p) => p === "" || p === "." || p === "..")) return null;
	let at = root;
	for (const p of parts) {
		at = join(at, p);
		try {
			if ((await lstat(at)).isSymbolicLink()) return null;
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code !== "ENOENT") return null;
		}
	}
	return at;
}

interface Exacto {
	raw: Buffer;
	text: string;
	mode: number;
}

/** Raw bytes plus decoded text; null if decoding would not round-trip (never edit those). */
async function leerExacto(abs: string): Promise<Exacto | null> {
	const [raw, st] = await Promise.all([readFile(abs), lstat(abs)]);
	const text = raw.toString("utf8");
	if (!Buffer.from(text, "utf8").equals(raw)) return null;
	return { raw, text, mode: st.mode & 0o777 };
}

// ---------------------------------------------------------------- journal

/** Backs up what is about to change so any failure or Ctrl+C leaves the workspace as before. */
class Journal {
	private readonly entradas = new Map<
		string,
		{ existia: boolean; backup?: string; modo?: number }
	>();
	private readonly dirs: string[] = [];
	private n = 0;

	private constructor(private readonly dir: string) {}

	static async crear(raiz: string): Promise<Journal> {
		const tmp = join(raiz, "tmp");
		await mkdir(tmp, { recursive: true, mode: 0o700 });
		const dir = join(
			tmp,
			`sanitize-${process.pid}-${randomBytes(4).toString("hex")}`,
		);
		await mkdir(dir, { mode: 0o700 });
		return new Journal(dir);
	}

	async proteger(abs: string): Promise<void> {
		if (this.entradas.has(abs)) return;
		let st: Stats | undefined;
		try {
			st = await lstat(abs);
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
		}
		if (st === undefined) {
			this.entradas.set(abs, { existia: false });
			return;
		}
		const backup = join(this.dir, String(this.n++));
		await copyFile(abs, backup);
		this.entradas.set(abs, {
			existia: true,
			backup,
			modo: st.mode & 0o777,
		});
	}

	/** Creates missing parents, remembering the top-most one so restore can remove it. */
	async asegurarDir(dir: string): Promise<void> {
		let falta: string | undefined;
		let at = dir;
		for (;;) {
			try {
				await lstat(at);
				break;
			} catch {
				falta = at;
				const up = dirname(at);
				if (up === at) break;
				at = up;
			}
		}
		if (falta !== undefined) this.dirs.push(falta);
		await mkdir(dir, { recursive: true });
	}

	async escribir(
		abs: string,
		data: string | Uint8Array,
		modo?: number,
	): Promise<void> {
		await this.proteger(abs);
		const previo = this.entradas.get(abs)?.modo;
		const m = modo ?? previo ?? 0o644;
		await writeFileAtomic(abs, data, m);
		await chmod(abs, m);
	}

	async borrar(abs: string): Promise<void> {
		await this.proteger(abs);
		await rm(abs, { force: true });
	}

	async restaurar(): Promise<void> {
		for (const [abs, e] of [...this.entradas].reverse()) {
			if (e.existia && e.backup !== undefined) {
				await mkdir(dirname(abs), { recursive: true });
				await copyFile(e.backup, abs);
				if (e.modo !== undefined) await chmod(abs, e.modo);
			} else {
				await rm(abs, { force: true });
			}
		}
		for (const d of this.dirs.reverse())
			await rm(d, { recursive: true, force: true });
	}

	async limpiar(): Promise<void> {
		await rm(this.dir, { recursive: true, force: true });
	}
}

// ---------------------------------------------------------------- locating a value

interface Span {
	inicio: number;
	fin: number;
	/** sha256 of the normalized value: groups equal values. Memory only. */
	clave: string;
	valor: string;
}

const sha256 = (t: string): string =>
	createHash("sha256").update(t, "utf8").digest("hex");

/**
 * Finds the exact span of the value of `h` in `text`. The finding keeps only a mask,
 * so the span is the shortest one starting at (linea, columna) whose findingId equals
 * `h.id`: the same formula as scan, so a stale or foreign finding never matches.
 */
function ubicar(text: string, h: Finding): Span | null {
	if (h.linea < 1 || h.columna < 1) return null;
	let at = 0;
	for (let n = 1; n < h.linea; n++) {
		const nl = text.indexOf("\n", at);
		if (nl < 0) return null;
		at = nl + 1;
	}
	const inicio = at + h.columna - 1;
	if (inicio >= text.length) return null;
	const limite = Math.min(text.length, inicio + MAX_VALUE_CHARS);
	for (let fin = inicio + 1; fin <= limite; fin++) {
		const ultimo = text.charCodeAt(fin - 1);
		if (ultimo <= 32 || (ultimo >= 0xd800 && ultimo <= 0xdbff)) continue;
		const valor = text.slice(inicio, fin);
		if (normalizeValue(valor).length === 0) continue;
		const id = findingId({
			motor: h.motor,
			regla: h.regla,
			archivo: h.archivo,
			linea: h.linea,
			value: valor,
		});
		if (id === h.id) {
			if (/private-key/i.test(h.regla)) {
				// A key is replaced whole: BEGIN through its END, or nothing (fail closed).
				const fila = new RegExp(PEM_END.source, "g");
				fila.lastIndex = inicio;
				const fim = fila.exec(text);
				if (fim === null) return null;
				const finBloque = fim.index + fim[0].length;
				const bloque = text.slice(inicio, finBloque);
				return {
					inicio,
					fin: finBloque,
					clave: sha256(normalizeValue(bloque)),
					valor: bloque,
				};
			}
			if (h.motor === "gitleaks") {
				// gitleaks reports the whole Match (key, operator, value). The value is
				// everything after the first operator, internal "=" or ":" included, and
				// only when what precedes it looks like a key name; else the whole Match.
				const op = CLAVE_OPERADOR.exec(valor);
				if (op !== null && pareceNombreDeClave(op[0])) {
					const desde = op[0].length;
					let hasta = valor.length;
					while (hasta > desde && /[\s"'`,;]/.test(valor.charAt(hasta - 1)))
						hasta--;
					if (hasta > desde) {
						const parte = valor.slice(desde, hasta);
						return {
							inicio: inicio + desde,
							fin: inicio + hasta,
							clave: sha256(normalizeValue(parte)),
							valor: parte,
						};
					}
				}
			}
			return { inicio, fin, clave: sha256(normalizeValue(valor)), valor };
		}
	}
	return null;
}

/** Key name (with a letter), gitleaks operator, optional opening quote. Anchored. */
const CLAVE_OPERADOR =
	/^\s*["'`]?(?=[\w.-]*[A-Za-z])[\w.-]+["'`]?\s*(?::{1,3}=|\|\|:|\|\||<=|=>|\?=|=|>|:|,)\s*["'`]?/;

const PALABRA_CLAVE =
	/(?:key|token|secret|pass|pwd|auth|cred|bearer|private|sign|salt|session|cookie|access|api|dsn|conn)/i;

/**
 * True only when the left side of a Match (as captured up to its operator) is really a
 * key name: it holds a credential word and no long unbroken alphanumeric run (that is
 * a token body, not a name). Otherwise the whole Match is the secret.
 */
function pareceNombreDeClave(izquierda: string): boolean {
	const nombre =
		izquierda.replace(/^[\s"'`]+/, "").split(/[\s"'`=:|<>,?]/)[0] ?? "";
	if (!PALABRA_CLAVE.test(nombre)) return false;
	// A run of 25+ alphanumerics, or of 12+ mixing letters and digits, is a token
	// body, not a name: the whole Match is replaced so nothing of it stays behind.
	for (const run of nombre.match(/[A-Za-z0-9]{12,}/g) ?? []) {
		if (run.length >= 25) return false;
		if (/\d/.test(run) && /[A-Za-z]/.test(run)) return false;
	}
	// Without separators the name can still be a token body split by `_`, `.` or `-`:
	// letters of both cases plus digits over 12+ characters is the shape of one.
	const junto = nombre.replace(/[_.-]/g, "");
	if (
		junto.length >= 12 &&
		/\d/.test(junto) &&
		/[a-z]/.test(junto) &&
		/[A-Z]/.test(junto)
	) {
		return false;
	}
	return true;
}

const PEM_END = /-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/;

// ---------------------------------------------------------------- reasons and names

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

/** SAN-002: >= 10 visible characters, one line, no invisible characters, no token or value inside. */
function validarMotivo(motivo: unknown, valor?: string): string {
	if (typeof motivo !== "string") {
		throw validacion(
			"El motivo es obligatorio",
			undefined,
			"Escribe un motivo de al menos 10 caracteres",
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
	if (valor !== undefined && valor.length >= 4 && limpio.includes(valor)) {
		throw validacion("El motivo no puede contener el valor del hallazgo");
	}
	return limpio;
}

function nombreDeRegla(regla: string): string {
	let n = regla
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "");
	if (n === "") n = "SECRET";
	if (/^[0-9]/.test(n)) n = `VAR_${n}`;
	return n.slice(0, 56);
}

function claveEnv(linea: string): string | null {
	const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(linea);
	return m?.[1] ?? null;
}

// ---------------------------------------------------------------- change application

interface Edicion {
	desde: number;
	hasta: number;
	texto: string;
}

function aplicarEdiciones(text: string, ediciones: readonly Edicion[]): string {
	const orden = [...ediciones].sort(
		(a, b) => a.desde - b.desde || a.hasta - b.hasta,
	);
	let out = "";
	let at = 0;
	for (const e of orden) {
		out += text.slice(at, e.desde) + e.texto;
		at = e.hasta;
	}
	return out + text.slice(at);
}

/** Collapses overlapping edits in one linear pass; the first placeholder text wins. */
function unirSolapes(ediciones: readonly Edicion[]): Edicion[] {
	const orden = [...ediciones].sort(
		(a, b) => a.desde - b.desde || a.hasta - b.hasta,
	);
	const out: Edicion[] = [];
	for (const e of orden) {
		const ult = out[out.length - 1];
		if (ult !== undefined && e.desde < ult.hasta) {
			ult.hasta = Math.max(ult.hasta, e.hasta);
		} else {
			out.push({ ...e });
		}
	}
	return out;
}

/** Overlap (equal spans are merged by the caller); throws VALIDACION. */
function comprobarSolapes(ediciones: readonly Edicion[]): void {
	const orden = [...ediciones].sort(
		(a, b) => a.desde - b.desde || a.hasta - b.hasta,
	);
	for (let i = 1; i < orden.length; i++) {
		const prev = orden[i - 1];
		const cur = orden[i];
		if (prev && cur && cur.desde < prev.hasta) {
			throw validacion("Dos cambios se solapan en el mismo archivo");
		}
	}
}

// ---------------------------------------------------------------- report

async function licencias(raiz: string): Promise<LicenseRow[]> {
	let doc: unknown;
	try {
		doc = JSON.parse(await readFile(join(raiz, "license-report.json"), "utf8"));
	} catch {
		return [];
	}
	if (!Array.isArray(doc)) return [];
	const rows: LicenseRow[] = [];
	for (const r of doc) {
		if (
			isObj(r) &&
			typeof r.paquete === "string" &&
			typeof r.version === "string" &&
			typeof r.spdx === "string" &&
			(r.origen === "directa" || r.origen === "transitiva") &&
			typeof r.veredicto === "string"
		) {
			rows.push({
				paquete: r.paquete,
				version: r.version,
				spdx: r.spdx,
				relacion: r.origen,
				veredicto: r.veredicto,
				...(typeof r.alternativa === "string" && {
					alternativa: r.alternativa,
				}),
			});
		}
	}
	return rows;
}

// ---------------------------------------------------------------- main

interface Info {
	puedeReemplazar: boolean;
	eliminar: boolean;
	abs?: string;
	span?: Span;
}

interface Salida {
	hallazgos: Finding[];
	abiertos: number;
	arbolSha256: string | null;
	eventos: { id: string; regla: string; evento: string }[];
}

/**
 * Sanitize core (SAN-001/003/006, SCAN-008): applies decisions and the adapter `Change`s inside
 * `work/`, writes `.env.example`, re-scans with the injected function, signs `approval.json` when
 * nothing is open, and regenerates `report.html`. Transactional: any error or Ctrl+C restores the
 * workspace to how it was. No prompts: the `Decisor` is injected.
 */
export async function sanitize(o: SanitizeOptions): Promise<SanitizeResult> {
	if (!o.tty) {
		throw new MctError(
			"PUERTA_BLOQUEADA",
			"Sin terminal interactiva no se puede aprobar",
			{
				accion: "Corre mct sanitize desde una terminal",
				etapa: "sanitize",
				detalle: { motivo: "sin-tty" },
			},
		);
	}
	if (o.signal?.aborted) throw interrumpido();
	const logger = (() => {
		try {
			return createLogger(o.raiz, "sanitize", o.now ? { now: o.now } : {});
		} catch {
			return undefined;
		}
	})();

	let salida: Salida;
	try {
		salida = await withLock(o.raiz, () => transaccion(o));
	} catch (err) {
		await logger?.error(err).catch(() => undefined);
		throw err;
	}
	for (const ev of salida.eventos) {
		await logger
			?.log({ evento: ev.evento, regla: ev.regla, hallazgoId: ev.id })
			.catch(() => undefined);
	}
	const cuenta = (e: string) =>
		salida.hallazgos.filter((h) => h.estado === e).length;
	const result: SanitizeResult = {
		decididos: {
			resuelto: cuenta("resuelto"),
			falsoPositivo: cuenta("falso-positivo"),
			aceptado: cuenta("aceptado"),
		},
		abiertos: salida.abiertos,
		aprobacion:
			salida.arbolSha256 === null ? null : { arbolSha256: salida.arbolSha256 },
	};
	if (salida.abiertos > 0) {
		const err = new MctError(
			"PUERTA_BLOQUEADA",
			"Quedan hallazgos sin resolver",
			{
				accion: "Corre: mct sanitize",
				etapa: "sanitize",
				detalle: { abiertos: salida.abiertos },
			},
		);
		await logger?.error(err).catch(() => undefined);
		throw err;
	}
	return result;
}

async function transaccion(o: SanitizeOptions): Promise<Salida> {
	const journal = await Journal.crear(o.raiz);
	try {
		return await ejecutar(o, journal);
	} catch (err) {
		try {
			await journal.restaurar();
		} catch (cause) {
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"No se pudo restaurar el workspace tras un error",
				{ cause, accion: "Recrea el workspace con init --force" },
			);
		}
		throw err;
	} finally {
		await journal.limpiar().catch(() => undefined);
	}
}

async function ejecutar(o: SanitizeOptions, journal: Journal): Promise<Salida> {
	const ws = workspacePaths(o.raiz);
	const signal = o.signal;
	const ahora = o.now ?? (() => new Date().toISOString());
	const usuario = (o.usuario ?? (() => userInfo().username))();
	const check = (): void => {
		if (signal?.aborted) throw interrumpido();
	};
	const cancelable = <T>(p: Promise<T>): Promise<T> => {
		if (signal === undefined) return p;
		return new Promise<T>((res, rej) => {
			const alAbortar = (): void => rej(interrumpido());
			if (signal.aborted) {
				p.catch(() => undefined);
				return alAbortar();
			}
			signal.addEventListener("abort", alAbortar, { once: true });
			p.then(
				(v) => {
					signal.removeEventListener("abort", alAbortar);
					res(v);
				},
				(e) => {
					signal.removeEventListener("abort", alAbortar);
					rej(e);
				},
			);
		});
	};

	let state: State = await readState(o.raiz);
	let hallazgos = await readFindings(o.raiz);
	const stateFile = join(o.raiz, "state.json");
	const findingsFile = join(o.raiz, FINDINGS_FILE);
	const approvalFile = join(o.raiz, APPROVAL_FILE);
	const reportFile = join(o.raiz, "report.html");
	const envExample = join(ws.work, ".env.example");

	// --reopen: validate before touching anything.
	if (o.reopen !== undefined) {
		const objetivo = hallazgos.find((h) => h.id === o.reopen);
		if (
			!SHA256.test(o.reopen) ||
			objetivo === undefined ||
			!DECIDIDOS.has(objetivo.estado)
		) {
			throw validacion(
				"--reopen necesita el ID de un hallazgo ya decidido",
				undefined,
				"Revisa el ID en findings.json o en report.html",
			);
		}
	}
	check();

	await journal.proteger(stateFile);
	await journal.proteger(findingsFile);
	await journal.proteger(approvalFile);
	await journal.proteger(reportFile);

	if (o.reopen !== undefined) {
		const ts = ahora();
		hallazgos = hallazgos.map((h) => {
			if (h.id !== o.reopen) return h;
			const { motivo: _m, decidio: _d, decididoEn: _e, ...resto } = h;
			return { ...resto, estado: "abierto" };
		});
		await invalidateApproval(o.raiz);
		const etapas = { ...state.etapas };
		for (const e of ["sanitize", "licenses", "package", "verify"] as Etapa[]) {
			etapas[e] = { estado: "pendiente", ts };
		}
		state = { ...state, etapas };
		await writeState(o.raiz, state);
		await writeFileAtomic(
			findingsFile,
			docFindings(hallazgos, state, o, ts, ""),
		);
	}

	// Structural cleanups from the adapter (Change inside work/), before reviewing.
	if (o.adapter?.sanitize !== undefined) {
		const cambios = await cancelable(o.adapter.sanitize(ws));
		check();
		await aplicarCambios(ws.work, cambios, journal, check);
	}

	const resueltosCorrida = new Set<string>();
	const eventos: Salida["eventos"] = [];
	const nombres = new Map<string, string>(); // value key -> placeholder
	const usados = new Set<string>();
	let gitleaksVersion = "";

	const sincronizarAislados = async (
		lista: readonly Finding[],
	): Promise<boolean> => {
		const nombresAislados = new Set<string>();
		for (const h of lista) {
			if (h.estado !== "aislado" || h.zona !== "quarantine" || h.linea < 1)
				continue;
			const abs = await inside(ws.quarantine, h.archivo);
			if (abs === null) continue;
			const texto = (await readFile(abs)).toString("utf8");
			const linea = texto.split("\n")[h.linea - 1]?.replace(/\r$/, "");
			const clave = linea === undefined ? null : claveEnv(linea);
			// the finding must sit in the value (after the first "="), never in the key
			if (
				linea !== undefined &&
				clave !== null &&
				ENV_NAME.test(clave) &&
				h.columna - 1 > linea.indexOf("=")
			) {
				nombresAislados.add(clave);
			}
		}
		return agregarEnv(nombresAislados);
	};

	const agregarEnv = async (agregar: ReadonlySet<string>): Promise<boolean> => {
		if (agregar.size === 0) return false;
		let existente = "";
		try {
			if ((await lstat(envExample)).isSymbolicLink()) {
				throw validacion(".env.example no puede ser un enlace");
			}
			existente = await readFile(envExample, "utf8");
		} catch (cause) {
			if (cause instanceof MctError) throw cause;
			if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
		}
		const claves = new Set(
			existente
				.split("\n")
				.map((l) => claveEnv(l.replace(/\r$/, "")))
				.filter((k): k is string => k !== null),
		);
		const nuevas = [...agregar].filter((n) => !claves.has(n)).sort();
		if (nuevas.length === 0) return false;
		const eol = existente.includes("\r\n") ? "\r\n" : "\n";
		const cola = existente === "" || /\n$/.test(existente) ? "" : eol;
		await journal.escribir(
			envExample,
			existente + cola + nuevas.map((n) => `${n}=${eol}`).join(""),
		);
		return true;
	};

	const reconciliar = async (
		previos: readonly Finding[],
	): Promise<Finding[]> => {
		const r = await cancelable(
			o.rescan(signal === undefined ? {} : { signal }),
		);
		check();
		if (
			!isObj(r) ||
			!Array.isArray(r.hallazgos) ||
			typeof r.gitleaksVersion !== "string"
		) {
			throw new MctError(
				"MOTOR_NO_DISPONIBLE",
				"El re-scan devolvió una forma inválida",
			);
		}
		gitleaksVersion = r.gitleaksVersion;
		const frescos = r.hallazgos.map((h) => toFinding(h, "MOTOR_NO_DISPONIBLE"));
		const ids = new Set(frescos.map((f) => f.id));
		const ts = ahora();
		// `aislado` is recalculated on every scan: previous ones are not carried.
		const reconciliados = reconcileFindings(
			previos.filter((f) => f.estado !== "aislado"),
			frescos,
		);
		return reconciliados.map((f) => {
			if (resueltosCorrida.has(f.id) && f.estado === "obsoleto") {
				return { ...f, estado: "resuelto" as const };
			}
			if (f.estado === "abierto" && !ids.has(f.id) && f.id !== o.reopen) {
				// gone from the tree (structural cleanup, external edit): resolved
				return {
					...f,
					estado: "resuelto" as const,
					decidio: usuario,
					decididoEn: ts,
				};
			}
			return f;
		});
	};

	const ciclo = async (previos: readonly Finding[]): Promise<Finding[]> => {
		let cur = await reconciliar(previos);
		if (await sincronizarAislados(cur)) cur = await reconciliar(cur);
		return cur;
	};

	// Existing names in .env.example are never reused for a different value.
	try {
		for (const l of (await readFile(envExample, "utf8")).split("\n")) {
			const k = claveEnv(l.replace(/\r$/, ""));
			if (k !== null) usados.add(k);
		}
	} catch {
		// no .env.example yet
	}

	let actuales = await ciclo(hallazgos);

	const textos = new Map<string, Exacto | null>();
	const leer = async (abs: string): Promise<Exacto | null> => {
		if (!textos.has(abs)) textos.set(abs, await leerExacto(abs));
		return textos.get(abs) ?? null;
	};

	for (let ronda = 0; ; ronda++) {
		const abiertos = actuales.filter((h) => h.estado === "abierto");
		if (abiertos.length === 0 || ronda >= MAX_RONDAS) break;
		textos.clear();

		const info = new Map<string, Info>();
		for (const h of abiertos) {
			info.set(h.id, await informacion(h));
		}

		const sugerir = (h: Finding, i: Info): string => {
			if (i.eliminar) return "";
			const previo = i.span ? nombres.get(i.span.clave) : undefined;
			if (previo !== undefined) return previo;
			const base = nombreDeRegla(h.regla);
			let nombre = base;
			for (let k = 2; usados.has(nombre); k++) nombre = `${base}_${k}`;
			return nombre;
		};
		const fijar = (nombre: string, i: Info): void => {
			usados.add(nombre);
			if (i.span) nombres.set(i.span.clave, nombre);
		};

		const decisiones = new Map<string, Decision>();
		const asignados = new Map<string, string>();
		if (o.autoPlaceholders === true) {
			const candidatos = abiertos.filter((h) => {
				const i = info.get(h.id);
				return i?.puedeReemplazar === true && !i.eliminar;
			});
			if (candidatos.length > 0) {
				const resumen: ResumenAuto = { reemplazos: [] };
				for (const h of candidatos) {
					const i = info.get(h.id) as Info;
					const nombre = sugerir(h, i);
					fijar(nombre, i);
					asignados.set(h.id, nombre);
					resumen.reemplazos.push({
						id: h.id,
						archivo: h.archivo,
						regla: h.regla,
						nombre,
					});
				}
				const ok = await cancelable(o.decisor.confirmar(resumen));
				check();
				if (ok !== true) {
					throw new MctError("CANCELADO", "No se confirmó el resumen", {
						etapa: "sanitize",
					});
				}
				for (const h of candidatos) {
					decisiones.set(h.id, {
						accion: "reemplazar",
						nombre: asignados.get(h.id) as string,
					});
				}
			}
		}

		for (const h of abiertos) {
			if (decisiones.has(h.id)) continue;
			const i = info.get(h.id) as Info;
			const d = await cancelable(
				o.decisor.decidir(h, {
					sugerido: sugerir(h, i),
					puedeReemplazar: i.puedeReemplazar,
					eliminar: i.eliminar,
				}),
			);
			check();
			if (!isObj(d)) throw validacion("Decisión inválida");
			if (d.accion === "abortar") {
				throw new MctError("CANCELADO", "La persona abortó la revisión", {
					etapa: "sanitize",
				});
			}
			if (d.accion === "reemplazar") {
				if (!i.puedeReemplazar) {
					throw validacion(
						"Este hallazgo no se puede reemplazar automáticamente",
						undefined,
						"Márcalo como falso positivo o acéptalo con motivo",
					);
				}
				if (!i.eliminar) {
					const nombre = d.nombre ?? sugerir(h, i);
					if (!PLACEHOLDER.test(nombre)) {
						throw validacion(
							"El nombre del placeholder debe ser MAYUSCULAS, dígitos y _",
						);
					}
					fijar(nombre, i);
					asignados.set(h.id, nombre);
					decisiones.set(h.id, { accion: "reemplazar", nombre });
				} else {
					decisiones.set(h.id, { accion: "reemplazar" });
				}
			} else if (d.accion === "falso-positivo" || d.accion === "aceptar") {
				decisiones.set(h.id, {
					accion: d.accion,
					motivo: validarMotivo(d.motivo, i.span?.valor),
				} as Decision);
			} else {
				throw validacion("Acción desconocida");
			}
		}
		check();

		// Plan every write first (no partial application), then write.
		const ediciones = new Map<string, Edicion[]>();
		const borrados = new Set<string>();
		const nombresUsados = new Set<string>();
		for (const h of abiertos) {
			const d = decisiones.get(h.id);
			const i = info.get(h.id) as Info;
			if (d?.accion !== "reemplazar" || i.abs === undefined) continue;
			if (i.eliminar) {
				borrados.add(i.abs);
				continue;
			}
			const nombre = asignados.get(h.id) as string;
			const span = i.span as Span;
			const lista = ediciones.get(i.abs) ?? [];
			const texto = `\${${nombre}}`;
			lista.push({ desde: span.inicio, hasta: span.fin, texto });
			// Every exact repeat of the value on the same line gets the same placeholder
			// (findings are deduplicated per line, so repeats have no finding of their own).
			const t = (await leer(i.abs)) as Exacto;
			const ini = t.text.lastIndexOf("\n", span.inicio - 1) + 1;
			const nl = t.text.indexOf("\n", span.fin);
			const finLinea = nl < 0 ? t.text.length : nl;
			let at = t.text.indexOf(span.valor, ini);
			while (at >= 0 && at + span.valor.length <= finLinea) {
				lista.push({ desde: at, hasta: at + span.valor.length, texto });
				at = t.text.indexOf(span.valor, at + span.valor.length);
			}
			ediciones.set(i.abs, lista);
			nombresUsados.add(nombre);
		}
		// Overlapping spans: replace their transitive union so no character survives.
		for (const [abs, lista] of ediciones) {
			ediciones.set(abs, unirSolapes(lista));
		}
		for (const lista of ediciones.values()) comprobarSolapes(lista);

		for (const [abs, lista] of ediciones) {
			check();
			const t = (await leer(abs)) as Exacto;
			const editado = aplicarEdiciones(t.text, lista);
			for (const h of abiertos) {
				const inf = info.get(h.id);
				if (
					inf?.abs === abs &&
					inf.span !== undefined &&
					decisiones.get(h.id)?.accion === "reemplazar" &&
					editado.includes(inf.span.valor)
				) {
					throw validacion(
						"El valor sigue en el archivo tras reemplazarlo",
						{ archivo: h.archivo },
						"Revisa el archivo a mano o decide otra acción",
					);
				}
			}
			await journal.escribir(abs, editado, t.mode);
		}
		for (const abs of borrados) {
			check();
			await journal.borrar(abs);
		}
		await agregarEnv(nombresUsados);

		const ts = ahora();
		actuales = actuales.map((h) => {
			const d = decisiones.get(h.id);
			if (d === undefined) return h;
			eventos.push({
				id: h.id,
				regla: h.regla,
				evento: `sanitize.${d.accion}`,
			});
			if (d.accion === "reemplazar") {
				resueltosCorrida.add(h.id);
				return {
					...h,
					estado: "resuelto" as const,
					decidio: usuario,
					decididoEn: ts,
				};
			}
			if (d.accion === "falso-positivo") {
				return {
					...h,
					estado: "falso-positivo" as const,
					motivo: d.motivo,
					decidio: usuario,
					decididoEn: ts,
				};
			}
			if (d.accion === "aceptar") {
				return {
					...h,
					estado: "aceptado" as const,
					motivo: d.motivo,
					decidio: usuario,
					decididoEn: ts,
				};
			}
			return h;
		});
		actuales = await ciclo(actuales);
	}

	// Close the gate.
	check();
	const ts = ahora();
	const abiertos = actuales.filter((h) => h.estado === "abierto").length;
	const arbol = await hashTree(ws.work);
	state = applyCascade(await readState(o.raiz), { workSha256: arbol }, ts);
	let arbolSha256: string | null = null;
	if (abiertos === 0) {
		check();
		const firma = await signApproval({
			raiz: o.raiz,
			hallazgos: actuales,
			gitleaksVersion,
			mctVersion: o.mctVersion ?? state.mctVersion,
			now: ahora,
			user: () => usuario,
		});
		arbolSha256 = firma.arbolSha256;
	} else {
		await invalidateApproval(o.raiz);
	}
	state = {
		...state,
		etapas: {
			...state.etapas,
			sanitize: { estado: abiertos === 0 ? "ok" : "bloqueada", ts },
			// SAN-010: scan's gate closed only for open findings; once none remain it passes too.
			...(abiertos === 0 &&
				state.etapas.scan.estado === "bloqueada" && {
					scan: { estado: "ok" as const, ts },
				}),
		},
	};
	await writeFileAtomic(
		findingsFile,
		docFindings(actuales, state, o, ts, gitleaksVersion),
	);
	await writeState(o.raiz, state);
	const html = renderReport({
		lang: o.lang ?? "es",
		generadoEn: ts,
		puertas: ETAPAS.map((etapa) => ({
			etapa,
			estado: state.etapas[etapa].estado,
		})),
		hallazgos: actuales,
		licencias: await licencias(o.raiz),
	});
	await writeFileAtomic(reportFile, html);
	return { hallazgos: actuales, abiertos, arbolSha256, eventos };

	// -- helpers that need the closure above
	async function informacion(h: Finding): Promise<Info> {
		const no: Info = { puedeReemplazar: false, eliminar: false };
		if (h.zona !== "work") return no;
		const abs = await inside(ws.work, h.archivo);
		if (abs === null) return no;
		if (h.tipo === "binario") {
			return { puedeReemplazar: true, eliminar: true, abs };
		}
		if (h.tipo === "estructura" || h.linea < 1) return { ...no, abs };
		const t = await leer(abs);
		if (t === null) return { ...no, abs };
		const span = ubicar(t.text, h);
		if (span === null) return { ...no, abs };
		return { puedeReemplazar: true, eliminar: false, abs, span };
	}
}

function docFindings(
	hallazgos: readonly Finding[],
	state: State,
	o: SanitizeOptions,
	ts: string,
	gitleaksVersion: string,
): string {
	return `${JSON.stringify(
		{
			schemaVersion: FINDINGS_SCHEMA_VERSION,
			mctVersion: o.mctVersion ?? state.mctVersion,
			gitleaksVersion,
			generadoEn: ts,
			hallazgos,
		},
		null,
		2,
	)}\n`;
}

/** Validates every Change first, then applies them (offsets are UTF-16 units of the raw text). */
async function aplicarCambios(
	work: string,
	cambios: readonly Change[],
	journal: Journal,
	check: () => void,
): Promise<void> {
	if (!Array.isArray(cambios))
		throw validacion("El adaptador devolvió cambios inválidos");
	const ediciones = new Map<string, { exacto: Exacto; lista: Edicion[] }>();
	const creaciones: { abs: string; contenido: string }[] = [];
	const borrados: string[] = [];
	for (const [n, c] of cambios.entries()) {
		const mal = (m: string): MctError => validacion(m, { cambio: n });
		if (!isObj(c)) throw mal("Cambio inválido");
		if (c.tipo === "editar") {
			const abs = await inside(work, c.ruta);
			if (abs === null)
				throw mal("Un cambio apunta fuera de work/ o a un archivo inexistente");
			const entry = ediciones.get(abs);
			const exacto = entry?.exacto ?? (await leerExacto(abs));
			if (exacto === null) throw mal("El archivo no es UTF-8 válido");
			const { desde, hasta, texto } = c as Record<string, unknown>;
			if (
				typeof desde !== "number" ||
				typeof hasta !== "number" ||
				!Number.isInteger(desde) ||
				!Number.isInteger(hasta) ||
				desde < 0 ||
				hasta < desde ||
				hasta > exacto.text.length ||
				typeof texto !== "string"
			) {
				throw mal("Un cambio tiene un rango inválido");
			}
			const lista = entry?.lista ?? [];
			lista.push({ desde, hasta, texto });
			ediciones.set(abs, { exacto, lista });
		} else if (c.tipo === "crear") {
			const abs = await targetInside(work, c.ruta);
			if (abs === null || typeof c.contenido !== "string") {
				throw mal("Un cambio apunta fuera de work/");
			}
			if ((await lstat(abs).catch(() => null)) !== null) {
				throw mal("Un cambio intenta crear un archivo que ya existe");
			}
			creaciones.push({ abs, contenido: c.contenido });
		} else if (c.tipo === "borrar") {
			const abs = await targetInside(work, c.ruta);
			if (abs === null) throw mal("Un cambio apunta fuera de work/");
			borrados.push(abs);
		} else {
			throw mal("Tipo de cambio desconocido");
		}
	}
	for (const { lista } of ediciones.values()) comprobarSolapes(lista);
	for (const [abs, { exacto, lista }] of ediciones) {
		check();
		await journal.escribir(
			abs,
			aplicarEdiciones(exacto.text, lista),
			exacto.mode,
		);
	}
	for (const { abs, contenido } of creaciones) {
		check();
		await journal.asegurarDir(dirname(abs));
		await journal.escribir(abs, contenido);
	}
	for (const abs of borrados) {
		check();
		await journal.borrar(abs);
	}
}
