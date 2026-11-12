import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { parseAllow } from "@mct/licenses/verdict";

/** `<dest>/mct.config.json` (datos.md). No secrets. */
export interface MctConfig {
	holder?: string;
	year?: number;
	exclude?: string[];
	licenses?: {
		allow: { spdx: string; motivo: string; paquetes?: string[] }[];
	};
	verify?: { remoto?: string; timeoutMin?: number };
}

export const CONFIG_FILE = "mct.config.json";

const MAX_FILE_BYTES = 1_048_576;
const MAX_EXCLUDE = 1000;
const MAX_TEXT = 500;

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
	onlyKeys(v, ["remoto", "timeoutMin"], "verify");
	const out: NonNullable<MctConfig["verify"]> = {};
	if (v.remoto !== undefined) {
		const alias = plainText(v.remoto, "verify.remoto");
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
	return out;
}

function parseLicenses(v: unknown): NonNullable<MctConfig["licenses"]> {
	if (!isObj(v)) throw bad("licenses debe ser un objeto");
	onlyKeys(v, ["allow"], "licenses");
	if (!Array.isArray(v.allow)) throw bad("licenses.allow debe ser una lista");
	v.allow.forEach((entry, i) => {
		if (isObj(entry))
			onlyKeys(entry, ["spdx", "motivo", "paquetes"], `licenses.allow[${i}]`);
	});
	// Same rules as the licenses audit (LIC-003): SPDX id + motivo >= 5 visible chars.
	return { allow: parseAllow({ licenses: v }) };
}

/** Strict validation of an already parsed config. Throws VALIDACION. */
export function validateConfig(raw: unknown): MctConfig {
	if (!isObj(raw)) throw bad("debe ser un objeto JSON");
	onlyKeys(raw, ["holder", "year", "exclude", "licenses", "verify"], "la raíz");
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
