import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32, deflateSync } from "node:zlib";
import { MctError } from "@mct/contract/errors";
import { afterEach, describe, expect, it } from "vitest";
import {
	type ScanBinariesOptions,
	scanBinaries as scanBinariesConClave,
} from "../src/binary.js";
import { stripMetadata } from "../src/strip-metadata.js";
import { CLAVE_PRUEBA } from "./clave.js";

const scanBinaries = (
	root: string,
	files: readonly string[],
	options: Partial<ScanBinariesOptions> = {},
) => scanBinariesConClave(root, files, { clave: CLAVE_PRUEBA, ...options });

const dirs: string[] = [];

afterEach(async () => {
	for (const dir of dirs.splice(0)) {
		await rm(dir, { recursive: true, force: true });
	}
});

// Markers for the fixtures are built from fragments (no literal payloads).
const EXIF_TAG = ["Ex", "if"].join("");
const GPS_MARK = ["GPS", "-LAT-", "40.4"].join("");
const XMP_NS = ["http://ns.adobe.com", "/xap/1.0/"].join("");
const XMP_BODY = ["<x:xmpmeta>", "creator-name", "</x:xmpmeta>"].join("");

function u16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n);
	return b;
}

function jpegSegment(marker: number, payload: Buffer): Buffer {
	return Buffer.concat([
		Buffer.from([0xff, marker]),
		u16(payload.length + 2),
		payload,
	]);
}

const JFIF = Buffer.concat([
	Buffer.from("JFIF\0"),
	Buffer.from([1, 1, 0, 0, 1, 0, 1, 0, 0]),
]);
const EXIF_APP1 = Buffer.concat([
	Buffer.from(`${EXIF_TAG}\0\0`),
	Buffer.from("MM\0*\0\0\0\b"),
	Buffer.from(GPS_MARK),
]);
const XMP_APP1 = Buffer.concat([
	Buffer.from(`${XMP_NS}\0`),
	Buffer.from(XMP_BODY),
]);
const SOF0 = Buffer.from([8, 0, 8, 0, 8, 1, 1, 0x11, 0]);
const DQT = Buffer.concat([Buffer.from([0]), Buffer.alloc(64, 3)]);
// Entropy data with stuffed FF00 bytes and a restart marker.
const SCAN = Buffer.from([
	0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56, 0xff, 0x00,
]);
const SOS_HEADER = Buffer.from([1, 1, 0, 0, 63, 0]);

function buildJpeg(withMeta: boolean): Buffer {
	const parts = [
		Buffer.from([0xff, 0xd8]),
		jpegSegment(0xe0, JFIF),
		...(withMeta
			? [jpegSegment(0xe1, EXIF_APP1), jpegSegment(0xe1, XMP_APP1)]
			: []),
		jpegSegment(0xdb, DQT),
		jpegSegment(0xc0, SOF0),
		jpegSegment(0xda, SOS_HEADER),
		SCAN,
		Buffer.from([0xff, 0xd9]),
	];
	return Buffer.concat(parts);
}

function pngChunk(type: string, data: Buffer): Buffer {
	const head = Buffer.concat([Buffer.from(type, "latin1"), data]);
	const len = Buffer.alloc(4);
	len.writeUInt32BE(data.length);
	const crc = Buffer.alloc(4);
	crc.writeUInt32BE(crc32(head) >>> 0);
	return Buffer.concat([len, head, crc]);
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function buildPng(withMeta: boolean): Buffer {
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(2, 0);
	ihdr.writeUInt32BE(2, 4);
	ihdr[8] = 8;
	ihdr[9] = 2;
	const raw = Buffer.from([0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 0, 0]);
	const raw2 = Buffer.concat([
		Buffer.from([0, 255, 0, 0, 0, 255, 0]),
		Buffer.from([0, 0, 0, 255, 9, 9, 9]),
	]);
	const xmp = Buffer.concat([
		Buffer.from("XML:com.adobe.xmp\0\0\0\0\0"),
		Buffer.from(XMP_BODY),
	]);
	return Buffer.concat([
		PNG_SIG,
		pngChunk("IHDR", ihdr),
		...(withMeta
			? [
					pngChunk("eXIf", Buffer.from(`MM\0*${GPS_MARK}`)),
					pngChunk("iTXt", xmp),
				]
			: []),
		pngChunk("tEXt", Buffer.from("Comment\0keep-me")),
		pngChunk("IDAT", deflateSync(Buffer.concat([raw2, raw.subarray(0, 0)]))),
		pngChunk("IEND", Buffer.alloc(0)),
	]);
}

describe("SCAN-011 quitar EXIF/XMP", () => {
	it("SCAN-011 un JPEG con EXIF y XMP queda sin ellos y con los mismos píxeles", () => {
		const input = buildJpeg(true);
		const out = stripMetadata(input);
		expect(Buffer.from(out).includes(Buffer.from(EXIF_TAG))).toBe(false);
		expect(Buffer.from(out).includes(Buffer.from(GPS_MARK))).toBe(false);
		expect(Buffer.from(out).includes(Buffer.from(XMP_NS))).toBe(false);
		// Identical to the same image built without metadata: pixels untouched.
		expect(Buffer.from(out).equals(buildJpeg(false))).toBe(true);
		expect(Buffer.from(out).includes(SCAN)).toBe(true);
	});

	it("SCAN-011 un PNG con eXIf y XMP queda sin ellos y conserva IDAT", () => {
		const input = buildPng(true);
		const out = stripMetadata(input);
		expect(Buffer.from(out).includes(Buffer.from("eXIf"))).toBe(false);
		expect(Buffer.from(out).includes(Buffer.from("XML:com.adobe.xmp"))).toBe(
			false,
		);
		expect(Buffer.from(out).includes(Buffer.from(GPS_MARK))).toBe(false);
		expect(Buffer.from(out).equals(buildPng(false))).toBe(true);
	});

	it("SCAN-011 un PNG con variantes de EXIF/XMP en texto o chunks antiguos las pierde todas", () => {
		const clean = buildPng(false);
		const idat = clean.indexOf(Buffer.from("tEXt")) - 4;
		const variants: Array<[string, Buffer]> = [
			[
				"tEXt",
				Buffer.from(`${EXIF_TAG.toLowerCase()}:GPSLatitude\0${GPS_MARK}`),
			],
			["tEXt", Buffer.from(` ${EXIF_TAG}:Make \0${GPS_MARK}`)],
			["tEXt", Buffer.from(`${["XM", "P"].join("")}:CreatorTool\0${GPS_MARK}`)],
			[
				"zTXt",
				Buffer.concat([
					Buffer.from(`${["Raw profile", " type 8bim"].join("")}\0\0`),
					deflateSync(Buffer.from(GPS_MARK)),
				]),
			],
			[
				"iTXt",
				Buffer.concat([
					Buffer.from(`${["XML:com.adobe", ".xmp"].join("")} \0\0\0\0\0`),
					Buffer.from(XMP_BODY),
				]),
			],
			["exIf", Buffer.from(`MM\0*${GPS_MARK}`)],
			[
				"zxIf",
				Buffer.concat([Buffer.from([0]), deflateSync(Buffer.from(GPS_MARK))]),
			],
		];
		for (const [type, data] of variants) {
			const dirty = Buffer.concat([
				clean.subarray(0, idat),
				pngChunk(type, data),
				clean.subarray(idat),
			]);
			const out = Buffer.from(stripMetadata(dirty));
			expect(out.equals(clean)).toBe(true);
		}
	});

	it("SCAN-011 una imagen sin metadatos sale idéntica", () => {
		const jpg = buildJpeg(false);
		const png = buildPng(false);
		expect(Buffer.from(stripMetadata(jpg)).equals(jpg)).toBe(true);
		expect(Buffer.from(stripMetadata(png)).equals(png)).toBe(true);
	});

	it("SCAN-011 no modifica la entrada", () => {
		const input = buildJpeg(true);
		const copy = Buffer.from(input);
		stripMetadata(input);
		expect(input.equals(copy)).toBe(true);
	});

	it("SCAN-011 una imagen corrupta falla cerrada con MctError", () => {
		const cases = [
			buildJpeg(true).subarray(0, 30),
			Buffer.concat([buildJpeg(true).subarray(0, 12), Buffer.from([0xff])]),
			buildPng(true).subarray(0, 40),
			Buffer.concat([PNG_SIG, Buffer.from("garbage-not-a-chunk")]),
			Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff, 1, 2, 3]),
		];
		for (const bad of cases) {
			expect(() => stripMetadata(bad)).toThrow(MctError);
		}
	});

	it("SCAN-011 un JPEG con datos tras el EOI falla cerrado", () => {
		const clean = buildJpeg(false);
		expect(() =>
			stripMetadata(Buffer.concat([clean, buildJpeg(true)])),
		).toThrow(MctError);
		expect(() =>
			stripMetadata(Buffer.concat([clean, Buffer.from("trailer-crudo")])),
		).toThrow(MctError);
		const padded = Buffer.concat([clean, Buffer.alloc(4)]);
		expect(Buffer.from(stripMetadata(padded)).equals(padded)).toBe(true);
	});

	it("SCAN-011 un PNG con CRC roto falla cerrado", () => {
		const png = Buffer.from(buildPng(true));
		png[png.length - 1] = (png[png.length - 1] ?? 0) ^ 0xff;
		expect(() => stripMetadata(png)).toThrow(MctError);
	});

	it("SCAN-011 un formato no soportado falla cerrado", () => {
		expect(() => stripMetadata(Buffer.from("GIF89a-lo-que-sea"))).toThrow(
			MctError,
		);
		expect(() => stripMetadata(Buffer.alloc(0))).toThrow(MctError);
	});
});

describe("SCAN-011 hallazgos abiertos de media", () => {
	async function tmp(): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "mct-media-"));
		dirs.push(dir);
		return dir;
	}

	it("SCAN-011 imagen, PDF y oficina crean un hallazgo binario abierto cada uno", async () => {
		const root = await tmp();
		const pdf = Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n", "latin1");
		const docx = Buffer.concat([
			Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0, 8, 0]),
			Buffer.from("[Content_Types].xml"),
		]);
		await writeFile(join(root, "a.jpg"), buildJpeg(true));
		await writeFile(join(root, "b.png"), buildPng(true));
		await writeFile(join(root, "c.pdf"), pdf);
		await writeFile(join(root, "d.docx"), docx);
		const found = await scanBinaries(root, [
			"a.jpg",
			"b.png",
			"c.pdf",
			"d.docx",
		]);
		expect(found.map((f) => f.regla)).toEqual([
			"binary-image",
			"binary-image",
			"binary-pdf",
			"binary-office",
		]);
		expect(found.every((f) => f.tipo === "binario")).toBe(true);
		expect(found.every((f) => f.estado === "abierto")).toBe(true);
	});

	it("SCAN-011 una imagen corrupta deja el hallazgo abierto", async () => {
		const root = await tmp();
		const bad = buildJpeg(true).subarray(0, 30);
		await writeFile(join(root, "rota.jpg"), bad);
		const found = await scanBinaries(root, ["rota.jpg"]);
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({ tipo: "binario", estado: "abierto" });
		expect(() => stripMetadata(bad)).toThrow(MctError);
	});
});
