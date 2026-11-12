import { open } from "node:fs/promises";
import { MctError } from "@mct/contract/errors";
import { maskDictionary } from "./masking.js";
import { MAX_TEXT_BYTES } from "./secrets.js";

/** Rule id for every dictionary hit. */
export const DICT_RULE = "dict-match";
/** Max size of `sensible.txt` (fail closed above it). */
export const MAX_DICT_BYTES = 256 * 1024;
/** Max number of terms (fail closed above it). */
export const MAX_DICT_TERMS = 10_000;
/** Max length of one term, in UTF-16 units. */
export const MAX_TERM_LENGTH = 256;

export interface DictMatch {
	readonly regla: typeof DICT_RULE;
	/** Start offset (inclusive) in the analysed text. */
	readonly inicio: number;
	/** End offset (exclusive). */
	readonly fin: number;
	/** 1-based line. */
	readonly linea: number;
	/** 1-based column. */
	readonly columna: number;
	/** `[dic:n]`: the index of the term, never the term. */
	readonly fragmento: string;
}

export interface DetectDictionaryOptions {
	/** Same limit as `detectSecrets` (50 MB by default). */
	readonly maxBytes?: number;
}

/**
 * Parses the dictionary text: one term per line, `#` comments and blank lines
 * ignored. A file without terms yields none. Fails closed above the limits. Messages
 * never include a term.
 */
export function parseDictionary(content: string): readonly string[] {
	const terms: string[] = [];
	const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
	for (const raw of text.split(/\r?\n/)) {
		const line = raw.trim();
		if (line.length === 0 || line.startsWith("#")) continue;
		if (line.length > MAX_TERM_LENGTH) {
			throw new MctError(
				"VALIDACION",
				"A dictionary term exceeds the length limit",
			);
		}
		terms.push(line);
		if (terms.length > MAX_DICT_TERMS) {
			throw new MctError("VALIDACION", "The dictionary exceeds the term limit");
		}
	}
	return terms;
}

/**
 * Strict decoding: UTF-8 (fatal), or UTF-16 LE/BE when a BOM says so. Never a
 * lossy conversion: NUL and U+FFFD are rejected. Messages never include content.
 */
function decodeDictionary(buffer: Buffer): string {
	const invalid = (): MctError =>
		new MctError(
			"VALIDACION",
			"The dictionary file is not valid UTF-8 or UTF-16 text",
		);
	let text: string;
	try {
		if (buffer[0] === 0xff && buffer[1] === 0xfe) {
			text = new TextDecoder("utf-16le", { fatal: true }).decode(
				buffer.subarray(2),
			);
		} else if (buffer[0] === 0xfe && buffer[1] === 0xff) {
			const body = Buffer.from(buffer.subarray(2));
			if (body.length % 2 !== 0) throw invalid();
			text = new TextDecoder("utf-16le", { fatal: true }).decode(body.swap16());
		} else {
			text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
		}
	} catch {
		throw invalid();
	}
	if (text.includes("\u0000") || text.includes("\ufffd")) throw invalid();
	return text;
}

/**
 * Reads the dictionary (read only). A missing file means zero terms; any other
 * failure (unreadable, a directory, too big, invalid text) is an error, never "0 hits".
 */
export async function loadDictionary(path: string): Promise<readonly string[]> {
	let handle: Awaited<ReturnType<typeof open>>;
	try {
		handle = await open(path, "r");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
		throw new MctError("VALIDACION", "The dictionary file cannot be read");
	}
	try {
		const info = await handle.stat();
		if (!info.isFile()) {
			throw new MctError("VALIDACION", "The dictionary path is not a file");
		}
		if (info.size > MAX_DICT_BYTES) {
			throw new MctError(
				"VALIDACION",
				"The dictionary file exceeds the size limit",
			);
		}
		const buffer = await handle.readFile();
		if (buffer.length > MAX_DICT_BYTES) {
			throw new MctError(
				"VALIDACION",
				"The dictionary file exceeds the size limit",
			);
		}
		return parseDictionary(decodeDictionary(buffer));
	} catch (error) {
		if (error instanceof MctError) throw error;
		throw new MctError("VALIDACION", "The dictionary file cannot be read");
	} finally {
		await handle.close();
	}
}

/** Lowercase that keeps the UTF-16 length, so offsets map 1:1 to the original. */
function fold(text: string): string {
	let out = "";
	for (const ch of text) {
		const lower = ch.toLowerCase();
		out += lower.length === ch.length ? lower : ch;
	}
	return out;
}

interface Automaton {
	readonly next: Map<number, number>[];
	readonly fail: number[];
	/** Index of the term that ends at this node, or -1. */
	readonly term: number[];
	readonly length: number[];
	/** Nearest proper-suffix node that ends a term, or 0. */
	readonly link: number[];
}

/** Aho-Corasick: one linear pass whatever the number of terms (no backtracking). */
function build(terms: readonly string[]): Automaton {
	const next: Map<number, number>[] = [new Map()];
	const term = [-1];
	const length = [0];
	const seen = new Set<string>();
	terms.forEach((raw, index) => {
		const t = fold(raw);
		if (seen.has(t)) return;
		seen.add(t);
		let node = 0;
		for (let i = 0; i < t.length; i++) {
			const c = t.charCodeAt(i);
			let child = (next[node] as Map<number, number>).get(c);
			if (child === undefined) {
				child = next.length;
				next.push(new Map());
				term.push(-1);
				length.push(0);
				(next[node] as Map<number, number>).set(c, child);
			}
			node = child;
		}
		term[node] = index;
		length[node] = t.length;
	});
	const fail = new Array<number>(next.length).fill(0);
	const link = new Array<number>(next.length).fill(0);
	const queue: number[] = [];
	for (const child of (next[0] as Map<number, number>).values()) {
		queue.push(child);
	}
	for (let head = 0; head < queue.length; head++) {
		const node = queue[head] as number;
		for (const [c, child] of next[node] as Map<number, number>) {
			let f = fail[node] as number;
			while (f !== 0 && !(next[f] as Map<number, number>).has(c)) {
				f = fail[f] as number;
			}
			const target = (next[f] as Map<number, number>).get(c);
			const failure = target !== undefined && target !== child ? target : 0;
			fail[child] = failure;
			link[child] =
				(term[failure] as number) >= 0 ? failure : (link[failure] as number);
			queue.push(child);
		}
	}
	return { next, fail, term, length, link };
}

/**
 * Finds every occurrence of every term (case-insensitive, literal) and reports
 * it as `dict-match` with `[dic:n]`. The term is never part of the result.
 */
export function detectDictionary(
	text: string,
	terms: readonly string[],
	options: DetectDictionaryOptions = {},
): DictMatch[] {
	const maxBytes = options.maxBytes ?? MAX_TEXT_BYTES;
	if (Buffer.byteLength(text, "utf8") > maxBytes) {
		throw new MctError("VALIDACION", "Text exceeds the maximum size to scan");
	}
	if (terms.length > MAX_DICT_TERMS) {
		throw new MctError("VALIDACION", "The dictionary exceeds the term limit");
	}
	for (const t of terms) {
		if (t.trim().length === 0 || t.length > MAX_TERM_LENGTH) {
			throw new MctError("VALIDACION", "Invalid dictionary term");
		}
	}
	if (terms.length === 0 || text.length === 0) return [];

	const ac = build(terms);
	const folded = fold(text);
	const lineStarts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
	}
	const locate = (offset: number): [number, number] => {
		let lo = 0;
		let hi = lineStarts.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if ((lineStarts[mid] as number) <= offset) lo = mid;
			else hi = mid - 1;
		}
		return [lo + 1, offset - (lineStarts[lo] as number) + 1];
	};

	const hits: DictMatch[] = [];
	const emit = (node: number, end: number): void => {
		const inicio = end - (ac.length[node] as number);
		const [linea, columna] = locate(inicio);
		hits.push({
			regla: DICT_RULE,
			inicio,
			fin: end,
			linea,
			columna,
			fragmento: maskDictionary(ac.term[node] as number),
		});
	};

	let state = 0;
	for (let i = 0; i < folded.length; i++) {
		const c = folded.charCodeAt(i);
		while (state !== 0 && !(ac.next[state] as Map<number, number>).has(c)) {
			state = ac.fail[state] as number;
		}
		state = (ac.next[state] as Map<number, number>).get(c) ?? 0;
		if ((ac.term[state] as number) >= 0) emit(state, i + 1);
		for (let n = ac.link[state] as number; n !== 0; n = ac.link[n] as number) {
			emit(n, i + 1);
		}
	}
	return hits.sort((a, b) => a.inicio - b.inicio || a.fin - b.fin);
}
