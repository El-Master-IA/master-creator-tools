import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding, Severidad } from "@mct/contract/types";
import { findingId } from "./finding-id.js";
import { MAX_TEXT_BYTES } from "./secrets.js";

/** Bytes inspected per file to classify it (content, never the extension). */
export const HEAD_BYTES = 8192;

export type ContentClass =
	| "text"
	| "utf16"
	| "image"
	| "pdf"
	| "office"
	| "unknown";

export interface ScanBinariesOptions {
	/** Same limit as the text engines (50 MB by default). */
	readonly maxBytes?: number;
	readonly zona?: "work" | "quarantine";
	/** HMAC key of the workspace (SCAN-015). */
	readonly clave: Uint8Array;
}

type RuleKind = Exclude<ContentClass, "text"> | "oversize" | "unreadable";

const RULES: Readonly<
	Record<RuleKind, { regla: string; severidad: Severidad }>
> = {
	image: { regla: "binary-image", severidad: "medio" },
	pdf: { regla: "binary-pdf", severidad: "medio" },
	office: { regla: "binary-office", severidad: "medio" },
	utf16: { regla: "binary-utf16", severidad: "medio" },
	unknown: { regla: "binary-unknown", severidad: "alto" },
	oversize: { regla: "binary-oversize", severidad: "alto" },
	unreadable: { regla: "binary-unreadable", severidad: "alto" },
};

function startsWith(buf: Uint8Array, sig: readonly number[], at = 0): boolean {
	if (buf.length < at + sig.length) return false;
	for (let i = 0; i < sig.length; i++) {
		if (buf[at + i] !== sig[i]) return false;
	}
	return true;
}

function ascii(text: string): number[] {
	return Array.from(text, (c) => c.charCodeAt(0));
}

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG = [0xff, 0xd8, 0xff];
const GIF87 = ascii("GIF87a");
const GIF89 = ascii("GIF89a");
const BMP = ascii("BM");
const ICO = [0x00, 0x00, 0x01, 0x00];
const TIFF_LE = [0x49, 0x49, 0x2a, 0x00];
const TIFF_BE = [0x4d, 0x4d, 0x00, 0x2a];
const RIFF = ascii("RIFF");
const WEBP = ascii("WEBP");
const PDF = ascii("%PDF-");
const ZIP = [0x50, 0x4b, 0x03, 0x04];
const OLE2 = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const PDF_SEARCH_WINDOW = 1024;
const MAX_CONTROL_RATIO = 0.1;
const CHUNK_BYTES = 64 * 1024;

function hasNul(head: Uint8Array): boolean {
	for (const byte of head) {
		if (byte === 0) return true;
	}
	return false;
}

function isImage(head: Uint8Array): boolean {
	if (startsWith(head, PNG) || startsWith(head, JPEG)) return true;
	if (startsWith(head, GIF87) || startsWith(head, GIF89)) return true;
	if (startsWith(head, TIFF_LE) || startsWith(head, TIFF_BE)) return true;
	if (startsWith(head, RIFF) && startsWith(head, WEBP, 8)) return true;
	// BMP has a weak two-letter signature: also require a NUL in the header.
	if (startsWith(head, BMP) && head.length >= 14 && hasNul(head)) return true;
	return startsWith(head, ICO) && head.length >= 6;
}

function indexOfBytes(
	hay: Uint8Array,
	needle: readonly number[],
	limit = hay.length,
): number {
	const end = Math.min(hay.length, limit) - needle.length;
	for (let i = 0; i <= end; i++) {
		if (hay[i] === needle[0] && startsWith(hay, needle, i)) return i;
	}
	return -1;
}

const OFFICE_ZIP_MARKERS = [
	ascii("[Content_Types].xml"),
	ascii("word/"),
	ascii("xl/"),
	ascii("ppt/"),
	ascii("application/vnd.oasis.opendocument"),
];

function isOfficeZip(head: Uint8Array): boolean {
	return OFFICE_ZIP_MARKERS.some((marker) => indexOfBytes(head, marker) >= 0);
}

function hasUtf16Bom(head: Uint8Array): boolean {
	return startsWith(head, [0xff, 0xfe]) || startsWith(head, [0xfe, 0xff]);
}

/** Valid UTF-16 text (real BOM): decodes strictly, no NULs, few control chars. */
function isValidUtf16(data: Uint8Array, final: boolean): boolean {
	let bytes = data;
	if (!final && bytes.length % 2 === 1) bytes = bytes.subarray(0, -1);
	if (final && bytes.length % 2 === 1) return false;
	const le = bytes[0] === 0xff;
	let text: string;
	try {
		text = new TextDecoder(le ? "utf-16le" : "utf-16be", {
			fatal: true,
		}).decode(bytes.subarray(2), { stream: !final });
	} catch {
		return false;
	}
	if (text.length === 0) return true;
	let control = 0;
	for (let i = 0; i < text.length; i++) {
		const code = text.charCodeAt(i);
		if (code === 0) return false;
		const allowed = code === 9 || code === 10 || code === 12 || code === 13;
		if (code < 32 && code !== 27 && !allowed) control++;
	}
	return control / text.length <= MAX_CONTROL_RATIO;
}

/** Incremental UTF-8 text check: no NULs, few control bytes, strict UTF-8. */
class Utf8TextCheck {
	private readonly decoder = new TextDecoder("utf-8", { fatal: true });
	private control = 0;
	private total = 0;
	private ok = true;

	push(chunk: Uint8Array, final: boolean): void {
		if (!this.ok) return;
		for (const byte of chunk) {
			if (byte === 0) {
				this.ok = false;
				return;
			}
			const allowed = byte === 9 || byte === 10 || byte === 12 || byte === 13;
			if (byte < 32 && byte !== 27 && !allowed) this.control++;
		}
		this.total += chunk.length;
		try {
			this.decoder.decode(chunk, { stream: !final });
		} catch {
			this.ok = false;
		}
	}

	get isText(): boolean {
		if (!this.ok) return false;
		return this.total === 0 || this.control / this.total <= MAX_CONTROL_RATIO;
	}
}

function looksLikeText(head: Uint8Array): boolean {
	if (head.length === 0) return true;
	const check = new Utf8TextCheck();
	// Not final: a multi-byte sequence may be cut at the end of the head.
	check.push(head, false);
	return check.isText;
}

/** Classifies a file by its first bytes. The extension plays no role. */
export function classifyContent(head: Uint8Array): ContentClass {
	if (isImage(head)) return "image";
	if (startsWith(head, PDF)) return "pdf";
	if (startsWith(head, OLE2)) return "office";
	if (startsWith(head, ZIP)) return isOfficeZip(head) ? "office" : "unknown";
	if (hasUtf16Bom(head)) return isValidUtf16(head, false) ? "utf16" : "unknown";
	if (looksLikeText(head)) return "text";
	// A PDF header may be preceded by junk, but only in non-text content.
	return indexOfBytes(head, PDF, PDF_SEARCH_WINDOW) >= 0 ? "pdf" : "unknown";
}

/** Whole-file check for what the head said was text or UTF-16 (SEG-105). */
async function verifyWholeFile(
	path: string,
	kind: "text" | "utf16",
): Promise<ContentClass> {
	const handle = await open(path, "r");
	try {
		if (kind === "utf16") {
			const data = await handle.readFile();
			return isValidUtf16(data, true) ? "utf16" : "unknown";
		}
		const check = new Utf8TextCheck();
		const buf = Buffer.alloc(CHUNK_BYTES);
		for (;;) {
			const { bytesRead } = await handle.read(buf, 0, CHUNK_BYTES, null);
			if (bytesRead === 0) break;
			check.push(buf.subarray(0, bytesRead), false);
			if (!check.isText) return "unknown";
		}
		check.push(new Uint8Array(0), true);
		return check.isText ? "text" : "unknown";
	} finally {
		await handle.close();
	}
}

/** SHA-256 of a whole file read as a stream (memory stays flat). */
function hashFile(path: string): Promise<string> {
	return new Promise((resolvePromise, reject) => {
		const hash = createHash("sha256");
		const stream = createReadStream(path);
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("error", reject);
		stream.on("end", () => resolvePromise(hash.digest("hex")));
	});
}

/** Id of a binary finding: the rule and the SHA-256 of the file content. */
export function binaryFindingId(
	regla: string,
	archivo: string,
	contenido: string,
	clave: Uint8Array,
): string {
	return findingId(
		{
			motor: "mct",
			regla,
			archivo,
			linea: 0,
			value: `${regla}:${contenido}`,
		},
		clave,
	);
}

/**
 * The id carries the content (datos.md, finding id): a decision taken on a
 * binary does not survive the file being replaced by another one.
 */
function makeFinding(
	clave: Uint8Array,
	kind: RuleKind,
	archivo: string,
	zona: "work" | "quarantine",
	contenido?: string,
): Finding {
	const rule = RULES[kind];
	if (!rule) throw new MctError("INTERNO", "Unknown binary rule");
	return {
		id:
			contenido === undefined
				? findingId(
						{
							motor: "mct",
							regla: rule.regla,
							archivo,
							linea: 0,
							value: rule.regla,
						},
						clave,
					)
				: binaryFindingId(rule.regla, archivo, contenido, clave),
		motor: "mct",
		regla: rule.regla,
		tipo: "binario",
		zona,
		archivo,
		linea: 0,
		columna: 0,
		fragmento: "****",
		severidad: rule.severidad,
		estado: zona === "quarantine" ? "aislado" : "abierto",
	};
}

async function readHead(path: string): Promise<Uint8Array> {
	const handle = await open(path, "r");
	try {
		const buf = Buffer.alloc(HEAD_BYTES);
		const { bytesRead } = await handle.read(buf, 0, HEAD_BYTES, 0);
		return buf.subarray(0, bytesRead);
	} finally {
		await handle.close();
	}
}

/**
 * Open `binario` findings, one per file, for every file in `files` (paths
 * relative to `root`, with `/`) that is not text by content, is over the size
 * limit, or cannot be read. Fail closed: nothing is skipped silently.
 */
export async function scanBinaries(
	root: string,
	files: readonly string[],
	options: ScanBinariesOptions,
): Promise<Finding[]> {
	const clave = options.clave;
	const maxBytes = options.maxBytes ?? MAX_TEXT_BYTES;
	const zona = options.zona ?? "work";
	const findings: Finding[] = [];
	for (const archivo of files) {
		const path = join(root, archivo);
		try {
			const info = await lstat(path);
			if (!info.isFile()) {
				findings.push(makeFinding(clave, "unreadable", archivo, zona));
				continue;
			}
			if (info.size > maxBytes) {
				findings.push(
					makeFinding(clave, "oversize", archivo, zona, await hashFile(path)),
				);
				continue;
			}
			let kind = classifyContent(await readHead(path));
			if (kind === "text" || kind === "utf16") {
				kind = await verifyWholeFile(path, kind);
			}
			if (kind !== "text") {
				findings.push(
					makeFinding(clave, kind, archivo, zona, await hashFile(path)),
				);
			}
		} catch {
			findings.push(makeFinding(clave, "unreadable", archivo, zona));
		}
	}
	return findings;
}
