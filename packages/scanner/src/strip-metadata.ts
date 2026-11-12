import { crc32 } from "node:zlib";
import { MctError } from "@mct/contract/errors";

/**
 * Pure EXIF/XMP removal for JPEG and PNG (SCAN-011). Everything else is copied
 * byte for byte, so pixel data is never touched. Fail closed: a corrupt,
 * truncated or unsupported image throws a MctError instead of passing through.
 */

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const MAX_KEYWORD_BYTES = 79;

function fail(reason: string): never {
	throw new MctError("VALIDACION", `Imagen no válida para limpiar: ${reason}`);
}

function startsWithAscii(buf: Uint8Array, text: string, at: number): boolean {
	if (buf.length < at + text.length) return false;
	for (let i = 0; i < text.length; i++) {
		if (buf[at + i] !== text.charCodeAt(i)) return false;
	}
	return true;
}

// ---------------------------------------------------------------- JPEG

const EXIF_PREFIX = "Exif\0";
const XMP_PREFIXES = [
	"http://ns.adobe.com/xap/1.0/\0",
	"http://ns.adobe.com/xmp/extension/\0",
];

function isMetadataApp1(data: Uint8Array, start: number): boolean {
	return (
		startsWithAscii(data, EXIF_PREFIX, start) ||
		XMP_PREFIXES.some((prefix) => startsWithAscii(data, prefix, start))
	);
}

function stripJpeg(data: Uint8Array): Uint8Array {
	const out: Uint8Array[] = [data.subarray(0, 2)];
	let pos = 2;
	let copyFrom = 2;
	let sawEoi = false;

	const flush = (end: number): void => {
		if (end > copyFrom) out.push(data.subarray(copyFrom, end));
	};

	while (pos < data.length) {
		if (data[pos] !== 0xff) fail("marcador JPEG esperado");
		let markerAt = pos + 1;
		while (data[markerAt] === 0xff) markerAt++;
		const marker = data[markerAt];
		if (marker === undefined) fail("JPEG truncado");
		const segStart = pos;
		pos = markerAt + 1;

		if (marker === 0xd9) {
			sawEoi = true;
			break;
		}
		// Standalone markers carry no length.
		if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) continue;
		if (marker === 0x00) fail("marcador JPEG inválido");

		if (pos + 2 > data.length) fail("JPEG truncado");
		const length = ((data[pos] ?? 0) << 8) | (data[pos + 1] ?? 0);
		if (length < 2 || pos + length > data.length)
			fail("segmento JPEG inválido");
		const payloadStart = pos + 2;
		const segEnd = pos + length;

		if (marker === 0xe1 && isMetadataApp1(data, payloadStart)) {
			flush(segStart);
			copyFrom = segEnd;
		}
		pos = segEnd;

		if (marker === 0xda) {
			// Entropy-coded data: skip to the next real marker.
			for (;;) {
				if (pos >= data.length) fail("JPEG truncado en los datos de imagen");
				if (data[pos] !== 0xff) {
					pos++;
					continue;
				}
				let next = pos + 1;
				while (data[next] === 0xff) next++;
				const nextByte = data[next];
				if (nextByte === undefined) fail("JPEG truncado");
				if (nextByte === 0x00 || (nextByte >= 0xd0 && nextByte <= 0xd7)) {
					pos = next + 1;
					continue;
				}
				break;
			}
		}
	}
	if (!sawEoi) fail("JPEG sin marcador final");
	// Only zero padding may follow EOI; appended images (MPF) or trailers could
	// carry their own EXIF/XMP, so anything else fails closed.
	for (let i = pos; i < data.length; i++) {
		if (data[i] !== 0x00) fail("datos tras el final del JPEG");
	}
	flush(data.length);
	return concat(out);
}

// ----------------------------------------------------------------- PNG

function readU32(data: Uint8Array, at: number): number {
	return (
		(((data[at] ?? 0) << 24) |
			((data[at + 1] ?? 0) << 16) |
			((data[at + 2] ?? 0) << 8) |
			(data[at + 3] ?? 0)) >>>
		0
	);
}

function chunkType(data: Uint8Array, at: number): string {
	let type = "";
	for (let i = 0; i < 4; i++) {
		const code = data[at + i] ?? 0;
		const letter = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
		if (!letter) fail("tipo de chunk PNG inválido");
		type += String.fromCharCode(code);
	}
	return type;
}

function keywordOf(data: Uint8Array, start: number, end: number): string {
	const limit = Math.min(end, start + MAX_KEYWORD_BYTES + 1);
	let nul = -1;
	for (let i = start; i < limit; i++) {
		if (data[i] === 0) {
			nul = i;
			break;
		}
	}
	if (nul < 0) fail("palabra clave PNG inválida");
	let word = "";
	for (let i = start; i < nul; i++) word += String.fromCharCode(data[i] ?? 0);
	return word.toLowerCase();
}

const META_KEYWORD_PREFIXES = [
	"exif:",
	"xmp:",
	"raw profile type ",
	"xml:com.adobe.xmp",
];

function isMetadataChunk(
	type: string,
	data: Uint8Array,
	start: number,
	end: number,
): boolean {
	// eXIf is the standard chunk; exIf and zxIf are pre-standard variants.
	if (type === "eXIf" || type === "exIf" || type === "zxIf") return true;
	if (type === "iTXt" || type === "tEXt" || type === "zTXt") {
		const key = keywordOf(data, start, end).trim();
		return META_KEYWORD_PREFIXES.some((prefix) => key.startsWith(prefix));
	}
	return false;
}

function stripPng(data: Uint8Array): Uint8Array {
	const out: Uint8Array[] = [data.subarray(0, 8)];
	let pos = 8;
	let copyFrom = 8;
	let first = true;
	let sawIend = false;

	while (pos < data.length) {
		if (pos + 12 > data.length) fail("chunk PNG truncado");
		const length = readU32(data, pos);
		if (length > 0x7fffffff || pos + 12 + length > data.length) {
			fail("longitud de chunk PNG inválida");
		}
		const type = chunkType(data, pos + 4);
		if (first && type !== "IHDR") fail("PNG sin IHDR inicial");
		first = false;
		const dataStart = pos + 8;
		const dataEnd = dataStart + length;
		const expected = crc32(data.subarray(pos + 4, dataEnd)) >>> 0;
		if (readU32(data, dataEnd) !== expected) fail("CRC de chunk PNG inválido");
		const chunkEnd = dataEnd + 4;

		if (isMetadataChunk(type, data, dataStart, dataEnd)) {
			if (pos > copyFrom) out.push(data.subarray(copyFrom, pos));
			copyFrom = chunkEnd;
		}
		pos = chunkEnd;
		if (type === "IEND") {
			sawIend = true;
			break;
		}
	}
	if (!sawIend) fail("PNG sin IEND");
	if (pos !== data.length) fail("datos tras el final del PNG");
	if (data.length > copyFrom) out.push(data.subarray(copyFrom));
	return concat(out);
}

// -------------------------------------------------------------- shared

function concat(parts: readonly Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) total += part.length;
	const result = new Uint8Array(total);
	let at = 0;
	for (const part of parts) {
		result.set(part, at);
		at += part.length;
	}
	return result;
}

/** Returns a copy of a JPEG or PNG without EXIF/XMP; pixels are unchanged. */
export function stripMetadata(data: Uint8Array): Uint8Array {
	if (
		data.length >= 3 &&
		data[0] === 0xff &&
		data[1] === 0xd8 &&
		data[2] === 0xff
	) {
		return stripJpeg(data);
	}
	if (PNG_SIGNATURE.every((byte, i) => data[i] === byte)) {
		return stripPng(data);
	}
	return fail("formato no soportado (solo JPEG y PNG)");
}
