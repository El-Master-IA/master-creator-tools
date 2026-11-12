import { MctError } from "@mct/contract/errors";
import { maskValue } from "./masking.js";
import { MAX_TEXT_BYTES } from "./secrets.js";

export interface DetectPiiOptions {
	/** Same limit as `detectSecrets` (50 MB by default). */
	readonly maxBytes?: number;
}

export interface PiiMatch {
	/** Rule id, e.g. `pii-email`, `pii-curp`. */
	readonly regla: string;
	/** Start offset (inclusive) in the analysed text. */
	readonly inicio: number;
	/** End offset (exclusive). */
	readonly fin: number;
	/** 1-based line. */
	readonly linea: number;
	/** 1-based column. */
	readonly columna: number;
	/** Masked: at most 4 real characters. */
	readonly fragmento: string;
}

interface Candidate {
	readonly regla: string;
	readonly inicio: number;
	readonly fin: number;
}

interface Rule {
	readonly regla: string;
	readonly pattern: RegExp;
	/** Receives the capture used as the value (group 1 when present). */
	readonly validate?: (value: string) => boolean;
	/** Narrows a match to the sub-spans (offsets relative to the value) that are real hits. */
	readonly locate?: (value: string) => readonly (readonly [number, number])[];
}

const LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

function digitsOf(value: string): string {
	return value.replace(/\D/g, "");
}

function luhn(digits: string): boolean {
	let sum = 0;
	let double = false;
	for (let i = digits.length - 1; i >= 0; i--) {
		let d = Number(digits[i]);
		if (double) {
			d *= 2;
			if (d > 9) d -= 9;
		}
		sum += d;
		double = !double;
	}
	return sum % 10 === 0;
}

const CARD_MIN = 13;
const CARD_MAX = 19;

/**
 * Brand prefix and length of the main schemes: Visa, Mastercard, Amex,
 * Discover, JCB, Diners, UnionPay (62), Maestro (50, 56-69) and Mir (2200-2204).
 * It only gates the windows of a run with extra digits glued to a card.
 */
function plausibleBrand(d: string): boolean {
	const n = d.length;
	const p2 = Number(d.slice(0, 2));
	const p3 = Number(d.slice(0, 3));
	const p4 = Number(d.slice(0, 4));
	if (d[0] === "4") return n === 13 || n === 16 || n === 19;
	if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16;
	if (p2 === 34 || p2 === 37) return n === 15;
	if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649)) {
		return n >= 16 && n <= 19;
	}
	if (p2 === 35) return n >= 16 && n <= 19;
	if (p4 >= 2200 && p4 <= 2204) return n >= 16 && n <= 19;
	if (p2 === 62) return n >= 16 && n <= 19;
	if (p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) {
		return n >= 14 && n <= 16;
	}
	if (p2 === 50 || (p2 >= 56 && p2 <= 69)) return n >= 13 && n <= 19;
	return false;
}

/**
 * Luhn-valid card spans inside a run of digits (separators allowed). A run of
 * 13-19 digits must be valid as a whole; a longer one is scanned with
 * sub-windows of 19 down to 13 digits, taking non-overlapping hits left to right.
 */
function locateCards(value: string): [number, number][] {
	const at: number[] = [];
	let digits = "";
	for (let i = 0; i < value.length; i++) {
		const ch = value[i] as string;
		if (ch >= "0" && ch <= "9") {
			at.push(i);
			digits += ch;
		}
	}
	const spans: [number, number][] = [];
	if (digits.length < CARD_MIN) return spans;
	if (digits.length <= CARD_MAX) {
		if (luhn(digits)) {
			spans.push([0, value.length]);
			return spans;
		}
		// A card with 1 to 3 digits glued before or after it: only windows at an
		// edge of the run, with a known brand prefix and length, to keep precision.
		const end = digits.length;
		for (let len = end - 1; len >= CARD_MIN; len--) {
			const head = digits.slice(0, len);
			const tail = digits.slice(end - len);
			if (plausibleBrand(head) && luhn(head)) {
				spans.push([0, (at[len - 1] as number) + 1]);
				return spans;
			}
			if (plausibleBrand(tail) && luhn(tail)) {
				spans.push([at[end - len] as number, value.length]);
				return spans;
			}
		}
		return spans;
	}
	let i = 0;
	while (i + CARD_MIN <= digits.length) {
		let hit = 0;
		for (
			let len = Math.min(CARD_MAX, digits.length - i);
			len >= CARD_MIN;
			len--
		) {
			if (luhn(digits.slice(i, i + len))) {
				hit = len;
				break;
			}
		}
		if (hit > 0) {
			spans.push([at[i] as number, (at[i + hit - 1] as number) + 1]);
			i += hit;
		} else i++;
	}
	return spans;
}

function validDniEs(value: string): boolean {
	return LETTERS[Number(value.slice(0, 8)) % 23] === value[8];
}

function validNie(value: string): boolean {
	const lead = "XYZ".indexOf(value[0] ?? "");
	return LETTERS[Number(`${lead}${value.slice(1, 8)}`) % 23] === value[8];
}

function validCuit(value: string): boolean {
	const digits = digitsOf(value);
	const weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
	let sum = 0;
	for (let i = 0; i < 10; i++) sum += Number(digits[i]) * (weights[i] ?? 0);
	const r = 11 - (sum % 11);
	const dv = r === 11 ? 0 : r === 10 ? 9 : r;
	return dv === Number(digits[10]);
}

function validRut(value: string): boolean {
	const body = digitsOf(value.slice(0, -2));
	let sum = 0;
	let factor = 2;
	for (let i = body.length - 1; i >= 0; i--) {
		sum += Number(body[i]) * factor;
		factor = factor === 7 ? 2 : factor + 1;
	}
	const r = 11 - (sum % 11);
	const dv = r === 11 ? "0" : r === 10 ? "K" : String(r);
	return dv === value.slice(-1).toUpperCase();
}

function validSsn(value: string): boolean {
	const [area, group, serial] = value.split("-");
	return (
		area !== "000" && area !== "666" && group !== "00" && serial !== "0000"
	);
}

function validYymmdd(value: string): boolean {
	const m = Number(value.slice(2, 4));
	const d = Number(value.slice(4, 6));
	return m >= 1 && m <= 12 && d >= 1 && d <= 31;
}

function validRfc(value: string): boolean {
	return validYymmdd(value.slice(value.length - 9, value.length - 3));
}

const NOREPLY_DOMAIN = "users.noreply.github.com";
const LOCAL_MAX = 64;
const DOMAIN_MAX = 255;
const LABEL_MAX = 63;
// Built from character code ranges: a 62-character literal alphabet looks like a
// high-entropy secret to the scanner itself.
const ALNUM = [
	[65, 90],
	[97, 122],
	[48, 57],
]
	.flatMap(([from, to]) =>
		Array.from({ length: (to as number) - (from as number) + 1 }, (_, i) =>
			String.fromCharCode((from as number) + i),
		),
	)
	.join("");
const LOCAL_CHARS = new Set(`${ALNUM}.!#$%&'*+/=?^_\`{|}~-`);
const DOMAIN_CHARS = new Set(`${ALNUM}.-`);

function validDomain(domain: string): boolean {
	const labels = domain.split(".");
	if (labels.length < 2) return false;
	for (const label of labels) {
		if (label.length === 0 || label.length > LABEL_MAX) return false;
		if (label.startsWith("-") || label.endsWith("-")) return false;
	}
	// The TLD is alphabetic (or punycode): `pkg@4.17.21` is a version, not a mailbox.
	return /^(?:[A-Za-z]{2,}|xn--[A-Za-z0-9-]+)$/.test(
		labels[labels.length - 1] as string,
	);
}

/**
 * Emails without a backtracking regex: each `@` expands to the left (the 64
 * chars nearest the `@`, longer runs are trimmed, not dropped) and to the right
 * (up to 255), so the cost per `@` is bounded (SEG-003).
 */
function findEmails(text: string): Candidate[] {
	const found: Candidate[] = [];
	let from = 0;
	for (;;) {
		const at = text.indexOf("@", from);
		if (at < 0) break;
		from = at + 1;
		let start = at;
		while (
			start > 0 &&
			at - start < LOCAL_MAX &&
			LOCAL_CHARS.has(text[start - 1] as string)
		) {
			start--;
		}
		while (start < at && text[start] === ".") start++;
		if (start === at) continue;
		let end = at + 1;
		while (
			end < text.length &&
			end - at <= DOMAIN_MAX &&
			DOMAIN_CHARS.has(text[end] as string)
		) {
			end++;
		}
		while (end > at + 1 && (text[end - 1] === "." || text[end - 1] === "-")) {
			end--;
		}
		if (end - at - 1 > DOMAIN_MAX || !validDomain(text.slice(at + 1, end))) {
			continue;
		}
		// GitHub's own no-reply addresses do not point to a real mailbox.
		if (text.slice(at + 1, end).toLowerCase() === NOREPLY_DOMAIN) {
			from = end;
			continue;
		}
		found.push({ regla: "pii-email", inicio: start, fin: end });
		from = end;
	}
	return found;
}

// Rules in priority order: the first one to claim a range wins.
const RULES: readonly Rule[] = [
	{
		regla: "pii-card",
		pattern: /(?<!\d)\d(?:[ -]?\d){12,}(?!\d)/g,
		locate: locateCards,
	},
	{
		regla: "pii-curp",
		pattern:
			/(?<![A-Za-z0-9])[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d(?![A-Za-z0-9])/g,
		validate: (v) => validYymmdd(v.slice(4, 10)),
	},
	{
		regla: "pii-rfc-mx",
		pattern: /(?<![A-Za-z0-9])[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}(?![A-Za-z0-9])/g,
		validate: validRfc,
	},
	{
		regla: "pii-cuit-ar",
		pattern: /(?<!\d)(?:20|23|24|27|30|33|34)(?:-\d{8}-|\d{8})\d(?!\d)/g,
		validate: validCuit,
	},
	{
		regla: "pii-nie-es",
		pattern: /(?<![A-Za-z0-9])[XYZ]\d{7}[A-Z](?![A-Za-z0-9])/g,
		validate: validNie,
	},
	{
		regla: "pii-dni-es",
		pattern: /(?<![A-Za-z0-9])\d{8}[A-Z](?![A-Za-z0-9])/g,
		validate: validDniEs,
	},
	{
		regla: "pii-rut-cl",
		pattern: /(?<![\d.])(?:\d{1,2}\.\d{3}\.\d{3}|\d{7,8})-[\dkK](?![\w])/g,
		validate: validRut,
	},
	{
		regla: "pii-ssn",
		pattern: /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g,
		validate: validSsn,
	},
	{
		// DNI AR/PE, with the keyword so bare 8-digit numbers do not match.
		regla: "pii-dni",
		pattern: /\bDNI\W{0,3}((?:\d{1,2}(?:\.\d{3}){2}|\d{7,8})(?![\d.]\d))/gi,
	},
	{
		regla: "pii-cedula-co",
		pattern: /(?<![\d.])\d{1,3}(?:\.\d{3}){2,3}(?![\d]|\.\d)/g,
	},
	{
		regla: "pii-cedula-co",
		pattern: /(?:c[eé]dula|\bc\.?\s?c\.?|documento)\W{0,4}(\d{6,10})(?!\d)/gi,
	},
	{
		regla: "pii-phone",
		pattern: /(?<![\w+])\+[1-9](?:[ .-]?\d){7,14}(?!\d)/g,
	},
	{
		// National formats: CO, MX, AR, ES, CL, PE and US.
		regla: "pii-phone",
		pattern:
			/(?<![\w.+-])(?:\(\d{3}\)\s?\d{3}[-. ]\d{4}|\d{3}[-. ]\d{3}[-. ]\d{4}|3\d{9}|[6-9]\d{2}[ -]?\d{3}[ -]?\d{3}|[2-9]\d{9}|\(0?\d{2,3}\)\s?(?:\d{4}[-. ]?\d{4}|\d{3,4}[ ]\d{4}|\d{7,8})|\(1\)\s?\d{3}[-. ]?\d{4}|[89]\d[ -]\d{3}[ -]\d{2}[ -]\d{2}|[6-9]\d{2}[ -]\d{2}[ -]\d{2}[ -]\d{2}|\d{2}[ -]\d{3}[ -]\d{4}|\d{2}[ -]\d{4}[ -]\d{4}|\d{2}[ -]?\d{4}-\d{4}|[2-9][ -]\d{4}[ -]?\d{4})(?![\w-]|\.\d)/g,
	},
];

function overlaps(a: Candidate, taken: readonly Candidate[]): boolean {
	return taken.some((t) => a.inicio < t.fin && t.inicio < a.fin);
}

/**
 * Pure PII detector (SCAN-006): email, E.164 and national phones,
 * CO/MX/AR/ES/CL/PE/US documents and Luhn-valid cards. Returns masked
 * matches ordered by position, never overlapping.
 */
export function detectPii(
	text: string,
	options: DetectPiiOptions = {},
): PiiMatch[] {
	if (typeof text !== "string") {
		throw new MctError("VALIDACION", "El texto a analizar debe ser una cadena");
	}
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
	const taken: Candidate[] = findEmails(text);
	for (const rule of RULES) {
		for (const m of text.matchAll(
			new RegExp(rule.pattern.source, `${rule.pattern.flags}d`),
		)) {
			const span = m.indices?.[1] ?? m.indices?.[0];
			if (!span) continue;
			const [base, baseEnd] = span;
			const value = text.slice(base, baseEnd);
			const spans = rule.locate
				? rule.locate(value).map(([a, b]) => [base + a, base + b] as const)
				: rule.validate && !rule.validate(value)
					? []
					: [[base, baseEnd] as const];
			for (const [inicio, fin] of spans) {
				const candidate = { regla: rule.regla, inicio, fin };
				if (!overlaps(candidate, taken)) taken.push(candidate);
			}
		}
	}
	taken.sort((a, b) => a.inicio - b.inicio);

	const lineStarts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text[i] === "\n") lineStarts.push(i + 1);
	}
	return taken.map((c) => {
		let lo = 0;
		let hi = lineStarts.length - 1;
		while (lo < hi) {
			const mid = Math.ceil((lo + hi) / 2);
			if ((lineStarts[mid] ?? 0) <= c.inicio) lo = mid;
			else hi = mid - 1;
		}
		return {
			regla: c.regla,
			inicio: c.inicio,
			fin: c.fin,
			linea: lo + 1,
			columna: c.inicio - (lineStarts[lo] ?? 0) + 1,
			fragmento: maskValue(text.slice(c.inicio, c.fin)),
		};
	});
}
