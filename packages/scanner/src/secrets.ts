import { MctError } from "@mct/contract/errors";
import { DIGEST_PATTERN, PROVIDER_RULES, type SecretRule } from "./rules.js";

/** Tamaño máximo por archivo (seguridad.md): 50 MB. */
export const MAX_TEXT_BYTES = 50 * 1024 * 1024;

export interface SecretMatch {
	readonly rule: string;
	/** Base 1. */
	readonly line: number;
	/** Base 1, en el texto original. */
	readonly column: number;
	/** Valor tal cual aparece (en base64, la cadena codificada; partido, el valor unido). */
	readonly value: string;
}

export interface DetectOptions {
	readonly maxBytes?: number;
}

export const ENTROPY_RULE = "high-entropy";
const ENTROPY_MIN_LENGTH = 32;
const ENTROPY_THRESHOLD = 4.2;
// Quantifiers are bounded: an unbounded one over a 10 MB token overflows the regex stack (SEG-009).
const ENTROPY_CANDIDATE = /[A-Za-z0-9_-]{32,8192}/g;
const BASE64_CANDIDATE = /[A-Za-z0-9+/]{24,8192}={0,2}/g;
const HEX_LIKE = /^[0-9a-fA-F-]+$/;
const JOINTS: readonly RegExp[] = [
	// Each optional part is delimited by a different character: no ambiguity, linear.
	/["'`][ \t]*(?:[+.][ \t]*)?\r?\n[ \t]*(?:[+.][ \t]*)?["'`]/g,
	// Line continuation: a backslash right before CRLF or LF.
	/\\\r?\n[ \t]*/g,
];

/**
 * Base64 with `+` or `=`, or with only `/` when it does not look like a path
 * (`looksLikePath`): a path or URL without `+`/`=` is not a candidate.
 */
const BASE64_ENTROPY_CANDIDATE = /[A-Za-z0-9+/]{32,8192}={0,2}/g;

/**
 * A token with `/` is a path when some segment of 3+ characters is all
 * lowercase letters and digits (`src`, `components`, `v1`): a random base64
 * segment of that length is rare, and a token has few of them.
 */
function looksLikePath(token: string): boolean {
	return token
		.split("/")
		.some((seg) => seg.length >= 3 && /^[a-z0-9]+$/.test(seg));
}

interface Range {
	readonly start: number;
	readonly end: number;
}

function shannon(s: string): number {
	const counts = new Map<string, number>();
	for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
	let h = 0;
	for (const n of counts.values()) {
		const p = n / s.length;
		h -= p * Math.log2(p);
	}
	return h;
}

/** Sorts and merges ranges so `overlaps` can binary-search them. */
function normalize(ranges: readonly Range[]): Range[] {
	const sorted = [...ranges].sort((a, b) => a.start - b.start);
	const out: { start: number; end: number }[] = [];
	for (const r of sorted) {
		const last = out[out.length - 1];
		if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
		else out.push({ start: r.start, end: r.end });
	}
	return out;
}

/** `ranges` must come from `normalize` (sorted and disjoint). O(log n). */
function overlaps(ranges: readonly Range[], start: number, end: number) {
	let lo = 0;
	let hi = ranges.length - 1;
	let candidate = -1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		if ((ranges[mid] as Range).start < end) {
			candidate = mid;
			lo = mid + 1;
		} else hi = mid - 1;
	}
	return candidate >= 0 && (ranges[candidate] as Range).end > start;
}

function lineStarts(text: string): number[] {
	const starts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) === 10) starts.push(i + 1);
	}
	return starts;
}

function position(starts: readonly number[], offset: number) {
	let lo = 0;
	let hi = starts.length - 1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if ((starts[mid] ?? 0) <= offset) lo = mid;
		else hi = mid - 1;
	}
	return { line: lo + 1, column: offset - (starts[lo] ?? 0) + 1 };
}

function providerMatches(text: string, rules: readonly SecretRule[]) {
	const out: { rule: string; index: number; value: string }[] = [];
	for (const rule of rules) {
		for (const m of text.matchAll(rule.pattern)) {
			out.push({ rule: rule.id, index: m.index ?? 0, value: m[0] });
		}
	}
	return out;
}

const UNESCAPES: Readonly<Record<string, string>> = {
	n: "\n",
	r: "\r",
	t: "\t",
	'"': '"',
	"'": "'",
};

/**
 * Vista del texto con escapes de JSON decodificados y las uniones de cadenas
 * (`"a" +\n "b"`, continuación con `\`) eliminadas. `map[i]` es el índice
 * original del carácter `i` de la vista.
 */
function joinedView(text: string): { view: string; map: Int32Array } | null {
	// Without escapes or a candidate joint there is nothing to rebuild (and no copy of the text).
	if (!text.includes("\\") && !new RegExp(JOINTS[0]?.source ?? "").test(text)) {
		return null;
	}
	let chars: string[] = [];
	let map: number[] = [];
	for (let i = 0; i < text.length; i++) {
		const ch = text[i] as string;
		const next = text[i + 1];
		const decoded = ch === "\\" && next ? UNESCAPES[next] : undefined;
		if (decoded !== undefined) {
			chars.push(decoded);
			map.push(i);
			i++;
		} else {
			chars.push(ch);
			map.push(i);
		}
	}
	let changed = false;
	for (const joint of JOINTS) {
		const view = chars.join("");
		const keepChars: string[] = [];
		const keepMap: number[] = [];
		let last = 0;
		for (const m of view.matchAll(joint)) {
			const at = m.index ?? 0;
			for (let k = last; k < at; k++) {
				keepChars.push(chars[k] as string);
				keepMap.push(map[k] as number);
			}
			last = at + m[0].length;
			changed = true;
		}
		for (let k = last; k < chars.length; k++) {
			keepChars.push(chars[k] as string);
			keepMap.push(map[k] as number);
		}
		chars = keepChars;
		map = keepMap;
	}
	if (!changed) return null;
	return { view: chars.join(""), map: Int32Array.from(map) };
}

function isPrintable(s: string): boolean {
	if (s.length === 0) return false;
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c !== 9 && c !== 10 && c !== 13 && (c < 32 || c > 126)) return false;
	}
	return true;
}

/**
 * Detecta secretos en un texto: reglas por proveedor, base64 de candidatos,
 * cadenas partidas en varias líneas y entropía. Función pura: no enmascara ni escribe.
 * Si el texto supera `maxBytes` lanza MctError (jamás devuelve vacío por no mirar).
 */
function analyze(text: string, options: DetectOptions): SecretMatch[] {
	const maxBytes = options.maxBytes ?? MAX_TEXT_BYTES;
	if (Buffer.byteLength(text, "utf8") > maxBytes) {
		throw new MctError(
			"VALIDACION",
			"El texto supera el tamaño máximo que el detector analiza.",
			{
				accion: "Excluye el archivo o redúcelo antes de escanear.",
				etapa: "scan",
				detalle: { maxBytes },
			},
		);
	}

	const starts = lineStarts(text);
	const seen = new Set<string>();
	const results: SecretMatch[] = [];
	const claimed: Range[] = [];

	const push = (rule: string, offset: number, value: string) => {
		const { line, column } = position(starts, offset);
		const key = `${rule}:${line}:${column}:${value}`;
		if (seen.has(key)) return;
		seen.add(key);
		results.push({ rule, line, column, value });
	};

	// 1. Reglas por proveedor sobre el texto original.
	for (const m of providerMatches(text, PROVIDER_RULES)) {
		push(m.rule, m.index, m.value);
		claimed.push({ start: m.index, end: m.index + m.value.length });
	}

	// 2. Cadenas partidas: vista con uniones eliminadas y escapes decodificados.
	const joined = joinedView(text);
	if (joined) {
		for (const m of providerMatches(joined.view, PROVIDER_RULES)) {
			const start = joined.map[m.index] as number;
			const end = (joined.map[m.index + m.value.length - 1] as number) + 1;
			push(m.rule, start, m.value);
			claimed.push({ start, end });
		}
	}

	// 3. Huellas (integrity, digests): ni base64 ni entropía.
	const digests: Range[] = [];
	for (const m of text.matchAll(DIGEST_PATTERN)) {
		const start = m.index ?? 0;
		digests.push({ start, end: start + m[0].length });
	}

	// 4. Candidatos en base64: se decodifican y pasan por las reglas.
	for (const m of text.matchAll(BASE64_CANDIDATE)) {
		const start = m.index ?? 0;
		const end = start + m[0].length;
		if (overlaps(digests, start, end)) continue;
		const decoded = Buffer.from(m[0], "base64").toString("latin1");
		if (!isPrintable(decoded)) continue;
		const inner = providerMatches(decoded, PROVIDER_RULES);
		if (inner.length === 0) continue;
		for (const hit of inner) push(hit.rule, start, m[0]);
		claimed.push({ start, end });
	}

	// 5. Entropía en cadenas largas que no son huellas ni ya reportadas.
	const taken = normalize(claimed);
	const entropyHits: Range[] = [];
	const isRandom = (token: string) =>
		/\d/.test(token) &&
		/[A-Za-z]/.test(token) &&
		shannon(token) >= ENTROPY_THRESHOLD;
	for (const m of text.matchAll(ENTROPY_CANDIDATE)) {
		const start = m.index ?? 0;
		const end = start + m[0].length;
		const token = m[0];
		if (token.length < ENTROPY_MIN_LENGTH) continue;
		if (overlaps(digests, start, end) || overlaps(taken, start, end)) continue;
		if (HEX_LIKE.test(token)) continue;
		if (!isRandom(token)) continue;
		push(ENTROPY_RULE, start, token);
		entropyHits.push({ start, end });
	}

	// 6. Base64 aleatorio con `+` o `=`, o solo con `/` si no parece ruta. Si parece
	// ruta, no se salta el token entero: cada segmento de 32+ se evalúa aparte.
	const mixedCase = (t: string) => /[A-Z]/.test(t) && /[a-z]/.test(t);
	const consider = (token: string, start: number) => {
		const end = start + token.length;
		if (overlaps(digests, start, end) || overlaps(taken, start, end)) return;
		if (overlaps(entropyHits, start, end)) return;
		if (!isRandom(token)) return;
		push(ENTROPY_RULE, start, token);
	};
	for (const m of text.matchAll(BASE64_ENTROPY_CANDIDATE)) {
		const token = m[0];
		const start = m.index ?? 0;
		if (token.includes("+") || token.includes("=")) {
			consider(token, start);
			continue;
		}
		if (!token.includes("/") || !mixedCase(token)) continue;
		if (!looksLikePath(token)) {
			consider(token, start);
			continue;
		}
		let at = 0;
		for (const seg of token.split("/")) {
			if (seg.length >= ENTROPY_MIN_LENGTH && mixedCase(seg)) {
				consider(seg, start + at);
			}
			at += seg.length + 1;
		}
	}

	return results.sort((a, b) => a.line - b.line || a.column - b.column);
}

export function detectSecrets(
	text: string,
	options: DetectOptions = {},
): SecretMatch[] {
	try {
		return analyze(text, options);
	} catch (e) {
		if (e instanceof MctError) throw e;
		if (e instanceof RangeError) {
			// Fail closed: never "0 findings" because the engine could not look (SEG-009).
			throw new MctError(
				"VALIDACION",
				"El texto es demasiado grande o anómalo para el detector.",
				{
					accion: "Excluye el archivo o divídelo antes de escanear.",
					etapa: "scan",
				},
			);
		}
		throw e;
	}
}
