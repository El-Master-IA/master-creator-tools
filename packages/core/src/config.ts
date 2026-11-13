import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { ReadmeConfig, ReadmeContenido } from "@mct/contract/types";
import { parseAllow } from "@mct/licenses/verdict";

/** `<dest>/mct.config.json` (datos.md). No secrets. */
export interface MctConfig {
	holder?: string;
	year?: number;
	exclude?: string[];
	licenses?: {
		allow: { spdx: string; motivo: string; paquetes?: string[] }[];
		sinLock?: { motivo: string };
		gestorNoSoportado?: { motivo: string };
	};
	verify?: {
		remoto?: string;
		timeoutMin?: number;
		modo?: "compilar";
		ignorar?: string[];
		motivo?: string;
	};
	/** README template and its human-written content (CFG-003, PKG-008). */
	readme?: ReadmeConfig;
}

export const CONFIG_FILE = "mct.config.json";

const MAX_FILE_BYTES = 1_048_576;
const MAX_EXCLUDE = 1000;
const MAX_TEXT = 500;
const MIN_MOTIVO = 10;
const OMITIDO = "(omitido)";

function motivo10(v: unknown, campo: string): string {
	if (typeof v !== "string") throw bad(`${campo} debe ser texto`);
	const t = v.trim();
	if (
		t.length < MIN_MOTIVO ||
		t.length > MAX_TEXT ||
		/[\p{Cc}\p{Cf}]/u.test(t)
	) {
		throw bad(`${campo} debe tener de 10 a 500 caracteres`);
	}
	return t;
}

function motivoObj(v: unknown, campo: string): { motivo: string } {
	if (!isObj(v)) throw bad(`${campo} debe ser un objeto`);
	onlyKeys(v, ["motivo"], campo);
	return { motivo: motivo10(v.motivo, `${campo}.motivo`) };
}

function bad(mensaje: string, detalle?: Record<string, unknown>): MctError {
	return new MctError("VALIDACION", `mct.config.json: ${mensaje}`, {
		accion: "Corrige mct.config.json (formato en la documentación)",
		...(detalle !== undefined && { detalle }),
	});
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

function onlyKeys(
	obj: Record<string, unknown>,
	allowed: readonly string[],
	donde: string,
): void {
	const extra = Object.keys(obj).filter((k) => !allowed.includes(k));
	if (extra.length > 0) {
		throw bad(`clave desconocida en ${donde}`, { claves: extra.slice(0, 5) });
	}
}

function plainText(v: unknown, campo: string): string {
	if (typeof v !== "string") throw bad(`${campo} debe ser texto`);
	const t = v.trim();
	if (t === "" || t.length > MAX_TEXT || /[\p{Cc}\p{Cf}]/u.test(t)) {
		throw bad(`${campo} no es válido`);
	}
	return t;
}

function parseExclude(v: unknown): string[] {
	if (!Array.isArray(v) || v.length > MAX_EXCLUDE) {
		throw bad("exclude debe ser una lista de globs");
	}
	return v.map((raw, i) => {
		const g = plainText(raw, `exclude[${i}]`);
		if (
			g.startsWith("/") ||
			g.includes("\\") ||
			/^[A-Za-z]:/.test(g) ||
			g.split("/").includes("..")
		) {
			throw bad(`exclude[${i}] debe ser relativo al origen y sin ..`);
		}
		return g;
	});
}

function parseVerify(v: unknown): NonNullable<MctConfig["verify"]> {
	if (!isObj(v)) throw bad("verify debe ser un objeto");
	onlyKeys(v, ["remoto", "timeoutMin", "modo", "ignorar", "motivo"], "verify");
	const out: NonNullable<MctConfig["verify"]> = {};
	if (v.remoto !== undefined) {
		const alias = plainText(v.remoto, "verify.remoto");
		if (alias === OMITIDO) {
			throw bad('verify.remoto no puede ser "(omitido)"');
		}
		// SSH alias: never an option (no leading "-") and no spaces.
		if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(alias)) {
			throw bad("verify.remoto debe ser un alias de ~/.ssh/config");
		}
		out.remoto = alias;
	}
	if (v.timeoutMin !== undefined) {
		const t = v.timeoutMin;
		if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 1440) {
			throw bad("verify.timeoutMin debe ser un entero entre 1 y 1440");
		}
		out.timeoutMin = t;
	}
	if (v.modo !== undefined) {
		if (v.modo !== "compilar") throw bad('verify.modo solo admite "compilar"');
		out.modo = "compilar";
	}
	if (v.ignorar !== undefined) {
		out.ignorar = parseExclude(v.ignorar);
	}
	if (v.motivo !== undefined) out.motivo = motivo10(v.motivo, "verify.motivo");
	if (
		(out.modo !== undefined || out.ignorar !== undefined) &&
		out.motivo === undefined
	) {
		throw bad("verify.modo y verify.ignorar exigen verify.motivo");
	}
	return out;
}

function parseLicenses(v: unknown): NonNullable<MctConfig["licenses"]> {
	if (!isObj(v)) throw bad("licenses debe ser un objeto");
	onlyKeys(v, ["allow", "sinLock", "gestorNoSoportado"], "licenses");
	const extra: Pick<
		NonNullable<MctConfig["licenses"]>,
		"sinLock" | "gestorNoSoportado"
	> = {};
	if (v.sinLock !== undefined) {
		extra.sinLock = motivoObj(v.sinLock, "licenses.sinLock");
	}
	if (v.gestorNoSoportado !== undefined) {
		extra.gestorNoSoportado = motivoObj(
			v.gestorNoSoportado,
			"licenses.gestorNoSoportado",
		);
	}
	if (v.allow === undefined && Object.keys(extra).length > 0) {
		return { allow: [], ...extra };
	}
	if (!Array.isArray(v.allow)) throw bad("licenses.allow debe ser una lista");
	v.allow.forEach((entry, i) => {
		if (isObj(entry))
			onlyKeys(entry, ["spdx", "motivo", "paquetes"], `licenses.allow[${i}]`);
	});
	// Same rules as the licenses audit (LIC-003): SPDX id + motivo >= 5 visible chars.
	return { allow: parseAllow({ licenses: { allow: v.allow } }), ...extra };
}

// ---------- CFG-003 readme ----------

const RC = "readme.contenido";
// Line: no control or invisible characters. Text: also allows \n and \t.
const LINEA_PROHIBIDA = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const TEXTO_PROHIBIDO = {
	test: (t: string): boolean => LINEA_PROHIBIDA.test(t.replace(/[\n\t]/g, "")),
};
const FENCE = "`".repeat(3);
const estructura = (t: string): boolean =>
	t.includes("<%") || t.includes(FENCE) || t.includes("~~~");
// A line of a multi-line text cannot open a heading, rule, table or quote (PKG-008 order).
const LINEA_DE_ESTRUCTURA = /^\s*(?:#|-{3,}|={3,}|\||>|\*{3,}|_{3,})/;
// Author text cannot carry Markdown links or images (no tracking pixels, no phishing links).
const enlaceOImagen = (t: string): boolean =>
	t.includes("](") || t.includes("![");

function rLinea(v: unknown, campo: string, min: number, max: number): string {
	if (typeof v !== "string") throw bad(`${campo} debe ser texto`);
	const t = v.trim();
	const n = Array.from(t).length;
	if (
		n < min ||
		n > max ||
		LINEA_PROHIBIDA.test(t) ||
		estructura(t) ||
		enlaceOImagen(t)
	) {
		throw bad(
			`${campo} debe ser una línea de ${min} a ${max} caracteres, sin <%, ~~~, tres comillas invertidas, enlaces ni imágenes`,
		);
	}
	return t;
}

function rTexto(
	v: unknown,
	campo: string,
	min: number,
	max: number,
	bloque = false,
): string {
	if (typeof v !== "string") throw bad(`${campo} debe ser texto`);
	const t = v.replace(/\r\n/g, "\n").trim();
	const n = Array.from(t).length;
	if (
		n < min ||
		n > max ||
		TEXTO_PROHIBIDO.test(t) ||
		estructura(t) ||
		(!bloque &&
			(enlaceOImagen(t) ||
				t.split("\n").some((l) => LINEA_DE_ESTRUCTURA.test(l))))
	) {
		throw bad(
			`${campo} debe ser un texto de ${min} a ${max} caracteres, sin <%, ~~~, tres comillas invertidas, enlaces ni imágenes, y sin líneas que empiecen con #, ---, ===, | o >`,
		);
	}
	return t;
}

function rLista<T>(
	v: unknown,
	campo: string,
	min: number,
	max: number,
	item: (x: unknown, c: string) => T,
): T[] {
	if (!Array.isArray(v) || v.length < min || v.length > max) {
		throw bad(`${campo} debe ser una lista de ${min} a ${max} elementos`);
	}
	return v.map((x, i) => item(x, `${campo}[${i}]`));
}

function rObj<K extends string>(
	v: unknown,
	campo: string,
	claves: readonly K[],
	max: number,
	min = 1,
): Record<K, string> {
	if (!isObj(v)) throw bad(`${campo} debe ser un objeto`);
	onlyKeys(v, claves, campo);
	const out = {} as Record<K, string>;
	for (const k of claves) out[k] = rLinea(v[k], `${campo}.${k}`, min, max);
	return out;
}

const REPO =
	/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/;

function parseContenido(v: unknown): ReadmeContenido {
	if (!isObj(v)) throw bad(`${RC} debe ser un objeto`);
	onlyKeys(
		v,
		[
			"promesa",
			"porQueExiste",
			"queObtienes",
			"prompt",
			"queNecesitas",
			"comoFunciona",
			"faq",
			"siAlgoSaleMal",
			"buenasPracticas",
			"creditos",
			"repo",
			"laboratorio",
		],
		RC,
	);
	const linea =
		(min: number, max: number) =>
		(x: unknown, c: string): string =>
			rLinea(x, c, min, max);
	const out: ReadmeContenido = {
		promesa: rLinea(v.promesa, `${RC}.promesa`, 10, 200),
		porQueExiste: rTexto(v.porQueExiste, `${RC}.porQueExiste`, 10, 2000),
		queObtienes: rLista(
			v.queObtienes,
			`${RC}.queObtienes`,
			1,
			12,
			linea(3, 200),
		),
		prompt: rTexto(v.prompt, `${RC}.prompt`, 10, 4000, true),
		queNecesitas: rLista(
			v.queNecesitas ?? [],
			`${RC}.queNecesitas`,
			0,
			12,
			(x, c) => rObj(x, c, ["que", "paraQue", "costo"] as const, 120),
		),
		comoFunciona: rTexto(v.comoFunciona, `${RC}.comoFunciona`, 10, 2000),
		faq: rLista(v.faq ?? [], `${RC}.faq`, 0, 12, (x, c) => {
			if (!isObj(x)) throw bad(`${c} debe ser un objeto`);
			onlyKeys(x, ["p", "r"], c);
			return {
				p: rLinea(x.p, `${c}.p`, 3, 200),
				r: rTexto(x.r, `${c}.r`, 3, 1000),
			};
		}),
		siAlgoSaleMal: rLista(
			v.siAlgoSaleMal ?? [],
			`${RC}.siAlgoSaleMal`,
			0,
			12,
			(x, c) => rObj(x, c, ["sintoma", "solucion"] as const, 200, 3),
		),
		buenasPracticas: rLista(
			v.buenasPracticas ?? [],
			`${RC}.buenasPracticas`,
			0,
			12,
			linea(3, 200),
		),
		creditos: rLista(v.creditos ?? [], `${RC}.creditos`, 0, 12, linea(3, 200)),
	};
	if (v.repo !== undefined) {
		const r = rLinea(v.repo, `${RC}.repo`, 3, 140);
		if (!REPO.test(r) || r.includes("..")) {
			throw bad(`${RC}.repo debe ser owner/nombre de GitHub`);
		}
		out.repo = r;
	}
	if (v.laboratorio !== undefined) {
		const l = rLinea(v.laboratorio, `${RC}.laboratorio`, 9, 300);
		let ok = false;
		try {
			const u = new URL(l);
			ok =
				u.protocol === "https:" &&
				u.username === "" &&
				u.password === "" &&
				/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[A-Za-z0-9._~/-]*)?$/.test(l);
		} catch {
			ok = false;
		}
		if (!ok) throw bad(`${RC}.laboratorio debe ser una URL https`);
		out.laboratorio = l;
	}
	return out;
}

function parseReadme(v: unknown): ReadmeConfig {
	if (!isObj(v)) throw bad("readme debe ser un objeto");
	onlyKeys(v, ["plantilla", "contenido"], "readme");
	if (v.plantilla === "estandar") {
		if (v.contenido !== undefined) {
			throw bad('readme.contenido solo va con readme.plantilla "el-master-ia"');
		}
		return { plantilla: "estandar" };
	}
	if (v.plantilla === "el-master-ia") {
		if (v.contenido === undefined) {
			throw bad(
				'readme.contenido es obligatorio con readme.plantilla "el-master-ia"',
			);
		}
		return {
			plantilla: "el-master-ia",
			contenido: parseContenido(v.contenido),
		};
	}
	throw bad('readme.plantilla debe ser "estandar" o "el-master-ia"');
}

/** Strict validation of an already parsed config. Throws VALIDACION. */
export function validateConfig(raw: unknown): MctConfig {
	if (!isObj(raw)) throw bad("debe ser un objeto JSON");
	onlyKeys(
		raw,
		["holder", "year", "exclude", "licenses", "verify", "readme"],
		"la raíz",
	);
	const out: MctConfig = {};
	if (raw.holder !== undefined) out.holder = plainText(raw.holder, "holder");
	if (raw.year !== undefined) {
		const y = raw.year;
		if (typeof y !== "number" || !Number.isInteger(y) || y < 1970 || y > 9999) {
			throw bad("year debe ser un entero de 4 dígitos (1970 o más)");
		}
		out.year = y;
	}
	if (raw.exclude !== undefined) out.exclude = parseExclude(raw.exclude);
	if (raw.licenses !== undefined) out.licenses = parseLicenses(raw.licenses);
	if (raw.verify !== undefined) out.verify = parseVerify(raw.verify);
	if (raw.readme !== undefined) out.readme = parseReadme(raw.readme);
	return out;
}

/**
 * Loads `<dest>/mct.config.json`. A missing file is an empty config; an unreadable,
 * linked, oversized, malformed or invalid file fails with VALIDACION (never treated as empty).
 */
export async function loadConfig(dest: string): Promise<MctConfig> {
	const file = join(dest, CONFIG_FILE);
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(file);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return {};
		throw bad("no se pudo inspeccionar el archivo", { causa: "lstat" });
	}
	if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_FILE_BYTES) {
		throw bad("debe ser un archivo regular (no enlace) de menos de 1 MB");
	}
	let text: string;
	try {
		text = await readFile(file, "utf8");
	} catch {
		throw bad("no se pudo leer el archivo");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text.replace(/^﻿/, ""));
	} catch {
		throw bad("no es JSON válido");
	}
	return validateConfig(parsed);
}
