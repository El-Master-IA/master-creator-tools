import { createHash } from "node:crypto";
import type { Finding } from "@mct/contract/types";
import tarjetasData from "../data/tarjetas-prueba.json" with { type: "json" };

/** SAN-014: the fixed reason recorded on every finding marked by `--auto-fixtures`. */
export const MOTIVO_AUTO =
	"dato de prueba reconocible en ruta de test (auto-fixtures)";

/** SHA-256 of each published test card number (never the number itself, T05). */
const TARJETAS: ReadonlySet<string> = new Set(
	(tarjetasData as { sha256: string[] }).sha256,
);

const sha256 = (v: string): string =>
	createHash("sha256").update(v).digest("hex");

const DIRS_TEST = new Set([
	"test",
	"tests",
	"__tests__",
	"spec",
	"fixtures",
	"testdata",
]);

/** SAN-014 (a): closed list of test paths (`/` separated, relative to work/). */
export function esRutaDeTest(ruta: string): boolean {
	if (ruta === "" || ruta.includes("\\") || ruta.startsWith("[ruta:")) {
		return false;
	}
	const partes = ruta.split("/");
	const archivo = partes[partes.length - 1] ?? "";
	if (partes.slice(0, -1).some((p) => DIRS_TEST.has(p.toLowerCase()))) {
		return true;
	}
	return (
		/^.+\.test\..+$/i.test(archivo) ||
		/^.+\.spec\..+$/i.test(archivo) ||
		/^test_.+\.py$/.test(archivo) ||
		/^.+_test\.py$/.test(archivo) ||
		archivo === "conftest.py"
	);
}

function unSoloCaracter(v: string): boolean {
	const chars = Array.from(v);
	return chars.length >= 4 && chars.every((c) => c === chars[0]);
}

function secuencia(digitos: string): boolean {
	if (digitos.length < 6) return false;
	for (const paso of [1, 9]) {
		let ok = true;
		for (let i = 1; i < digitos.length; i++) {
			const prev = Number(digitos[i - 1]);
			if ((prev + paso) % 10 !== Number(digitos[i])) {
				ok = false;
				break;
			}
		}
		if (ok) return true;
	}
	return false;
}

/** `://user:pass@` or `://user@`: a value that carries credentials is never test data. */
function tieneCredenciales(v: string): boolean {
	return /:\/\/[^/?#\s]*@/.test(v);
}

function hostDePrueba(host: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, "");
	return (
		h === "localhost" ||
		h === "127.0.0.1" ||
		h === "example" ||
		h.startsWith("example.") ||
		h.endsWith(".test") ||
		h.endsWith(".invalid") ||
		h.endsWith(".local")
	);
}

function urlODominio(v: string): boolean {
	if (tieneCredenciales(v)) return false;
	const m =
		/^[a-z][a-z0-9+.-]*:\/\/([^/?#:\s]+)(?::\d{1,5})?(?:[/?#]\S*)?$/i.exec(v);
	if (m !== null) return hostDePrueba(m[1] as string);
	const bare = /^([^/?#:\s]+)(?::\d{1,5})?$/.exec(v);
	return bare !== null && hostDePrueba(bare[1] as string);
}

function correoDePrueba(v: string): boolean {
	const m = /^[^@\s]+@([^@\s]+)$/.exec(v);
	if (m === null) return false;
	const d = (m[1] as string).toLowerCase();
	return (
		d === "example.com" ||
		d === "example.org" ||
		d === "example.net" ||
		d === "localhost" ||
		d.endsWith(".test") ||
		d.endsWith(".example") ||
		d.endsWith(".invalid")
	);
}

function tarjetaDePrueba(v: string): boolean {
	const d = v.replace(/[\s-]/g, "");
	if (!/^\d{13,19}$/.test(d)) return false;
	return TARJETAS.has(sha256(d)) || unSoloCaracter(d) || secuencia(d);
}

function telefonoDePrueba(v: string): boolean {
	if (!/^[+\d\s().-]{7,20}$/.test(v)) return false;
	const d = v.replace(/\D/g, "");
	if (d.length < 7) return false;
	// NANP fictional range only: optional 1, area code, 555-01xx (a 10-digit mobile is real).
	return /^1?\d{3}55501\d{2}$/.test(d) || /^0+$/.test(d) || unSoloCaracter(d);
}

/** Closed list of vendor prefixes a test token may carry (never an arbitrary one). */
const PREFIJO_TOKEN =
	/^(?:AKIA|ASIA|AIza|gh[pousr]_|github_pat_|sk_(?:test|live)_|pk_(?:test|live)_|rk_(?:test|live)_|xox[abpr]-|sk-(?:proj-)?|glpat-|npm_)/;
/** Filler allowed after the prefix: one repeated character or only these words. */
const RELLENO = /^(?:(?:example|dummy|fake|test)+|x+|X+|0+)$/i;

/**
 * Whole-value rule for secrets (SAN-014): a single repeated character of 8+, or the
 * filler words alone, or one known vendor prefix followed by 8+ characters of filler.
 * A value made only of digits is never test data.
 */
function tokenDePrueba(v: string): boolean {
	if (/^[0-9]+$/.test(v)) return false;
	if (v.length >= 8 && unSoloCaracter(v)) return true;
	if (/^(?:example|dummy|fake)+$/i.test(v)) return true;
	const p = PREFIJO_TOKEN.exec(v);
	if (p === null) return false;
	const resto = v.slice(p[0].length);
	return resto.length >= 8 && (unSoloCaracter(resto) || RELLENO.test(resto));
}

/**
 * SAN-014 (c): closed patterns of test data. For `secreto` the pattern must cover
 * the whole value; a value with credentials in userinfo never matches.
 */
export function esValorDePrueba(tipo: Finding["tipo"], valor: string): boolean {
	const v = valor.trim();
	if (v === "" || tieneCredenciales(v)) return false;
	if (tipo === "secreto") return tokenDePrueba(v) || urlODominio(v);
	if (tipo === "pii") {
		return (
			tarjetaDePrueba(v) ||
			correoDePrueba(v) ||
			telefonoDePrueba(v) ||
			urlODominio(v) ||
			unSoloCaracter(v)
		);
	}
	return false;
}

/**
 * Whether a finding qualifies (SAN-014). `valor` is the in-memory value or null when it
 * cannot be located (then it never qualifies). Never dictionary, binary, quarantine,
 * gitleaks, nor a `critico` that is not a secret of the `mct` engine.
 */
export function esCandidato(h: Finding, valor: string | null): boolean {
	if (h.estado !== "abierto" || h.zona !== "work" || valor === null) {
		return false;
	}
	if (h.motor !== "mct" || h.regla === "dict-match") return false;
	if (h.tipo !== "pii" && h.tipo !== "secreto" && h.tipo !== "estructura") {
		return false;
	}
	if (h.severidad === "critico" && h.tipo !== "secreto") return false;
	if (!esRutaDeTest(h.archivo)) return false;
	return esValorDePrueba(h.tipo, valor);
}

/** SHA-256 of the sorted ids joined by "\n" (UTF-8). */
export function huellaLista(ids: readonly string[]): string {
	return createHash("sha256")
		.update([...ids].sort().join("\n"), "utf8")
		.digest("hex");
}
