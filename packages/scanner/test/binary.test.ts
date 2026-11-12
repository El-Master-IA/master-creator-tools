import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	classifyContent,
	type ScanBinariesOptions,
	scanBinaries as scanBinariesConClave,
} from "../src/binary.js";
import { CLAVE_PRUEBA } from "./clave.js";

const scanBinaries = (
	root: string,
	files: readonly string[],
	options: Partial<ScanBinariesOptions> = {},
) => scanBinariesConClave(root, files, { clave: CLAVE_PRUEBA, ...options });

const dirs: string[] = [];

async function tmp(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "mct-bin-"));
	dirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of dirs.splice(0)) {
		await rm(dir, { recursive: true, force: true });
	}
});

const PNG = Buffer.concat([
	Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
	Buffer.from([0, 0, 0, 13]),
	Buffer.from("IHDR"),
	Buffer.alloc(16),
]);
const JPEG = Buffer.from([
	0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46, 0x49, 0x46, 0,
]);
const GIF = Buffer.concat([
	Buffer.from("GIF89a"),
	Buffer.from([1, 0, 1, 0, 0, 0]),
]);
const WEBP = Buffer.concat([
	Buffer.from("RIFF"),
	Buffer.from([0x24, 0, 0, 0]),
	Buffer.from("WEBPVP8 "),
]);
const PDF = Buffer.from("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n", "latin1");
const DOCX = Buffer.concat([
	Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0, 8, 0]),
	Buffer.from("[Content_Types].xml"),
	Buffer.alloc(8),
	Buffer.from("word/document.xml"),
]);
const ZIP_PLAIN = Buffer.concat([
	Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0, 8, 0]),
	Buffer.from("datos/archivo.csv"),
]);
const OLE2 = Buffer.concat([
	Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
	Buffer.alloc(32),
]);
const ELF = Buffer.concat([
	Buffer.from([0x7f]),
	Buffer.from("ELF"),
	Buffer.alloc(20, 1),
]);

describe("SCAN-008 clasificación por contenido", () => {
	it("SCAN-008 reconoce imágenes por magic bytes", () => {
		for (const img of [PNG, JPEG, GIF, WEBP]) {
			expect(classifyContent(img)).toBe("image");
		}
	});

	it("SCAN-008 reconoce PDF y documentos de oficina", () => {
		expect(classifyContent(PDF)).toBe("pdf");
		expect(classifyContent(DOCX)).toBe("office");
		expect(classifyContent(OLE2)).toBe("office");
	});

	it("SCAN-008 un zip sin marcas de oficina y un ELF son desconocidos", () => {
		expect(classifyContent(ZIP_PLAIN)).toBe("unknown");
		expect(classifyContent(ELF)).toBe("unknown");
	});

	it("SEG-105 BOM UTF-16 con bytes binarios no es texto", () => {
		expect(
			classifyContent(Buffer.from([0xff, 0xfe, 0, 0, 0, 0, 1, 2, 3, 0])),
		).toBe("unknown");
	});

	it("SEG-105 %PDF- tras texto no es PDF; tras basura binaria sí", () => {
		expect(classifyContent(Buffer.from("hola\n%PDF-1.4 es solo texto"))).toBe(
			"text",
		);
		expect(classifyContent(Buffer.concat([Buffer.from([0, 1, 2]), PDF]))).toBe(
			"pdf",
		);
	});

	it("SCAN-008 texto UTF-8, vacío son texto; UTF-16 válido se marca", () => {
		expect(classifyContent(Buffer.from("hola ñandú\nlinea\n"))).toBe("text");
		expect(classifyContent(Buffer.alloc(0))).toBe("text");
		expect(classifyContent(Buffer.from([0xff, 0xfe, 0x68, 0, 0x69, 0]))).toBe(
			"utf16",
		);
	});

	it("SCAN-008 clasifica en tiempo lineal una entrada hostil", () => {
		const hostile = Buffer.alloc(8192, 0x50);
		const start = Date.now();
		classifyContent(hostile);
		expect(Date.now() - start).toBeLessThan(500);
	});
});

describe("SCAN-008 hallazgos binarios", () => {
	it("SCAN-008 un binario no reconocido crea un hallazgo binario abierto", async () => {
		const root = await tmp();
		await writeFile(join(root, "tool.dat"), ELF);
		const [f, ...rest] = await scanBinaries(root, ["tool.dat"]);
		expect(rest).toHaveLength(0);
		expect(f).toMatchObject({
			tipo: "binario",
			estado: "abierto",
			zona: "work",
			archivo: "tool.dat",
			regla: "binary-unknown",
			motor: "mct",
		});
		expect(f?.id).toMatch(/^[0-9a-f]{64}$/);
	});

	it("SCAN-008 imagen, PDF y oficina dan un hallazgo por archivo", async () => {
		const root = await tmp();
		await mkdir(join(root, "docs"));
		await writeFile(join(root, "a.png"), PNG);
		await writeFile(join(root, "docs", "b.pdf"), PDF);
		await writeFile(join(root, "docs", "c.docx"), DOCX);
		const found = await scanBinaries(root, [
			"a.png",
			"docs/b.pdf",
			"docs/c.docx",
		]);
		expect(found.map((f) => f.regla)).toEqual([
			"binary-image",
			"binary-pdf",
			"binary-office",
		]);
		expect(new Set(found.map((f) => f.id)).size).toBe(3);
	});

	it("SCAN-008 un texto con extensión de binario se clasifica por contenido", async () => {
		const root = await tmp();
		await writeFile(join(root, "notas.png"), "esto es solo texto\n");
		await writeFile(join(root, "falso.txt"), PNG);
		const found = await scanBinaries(root, ["notas.png", "falso.txt"]);
		expect(found.map((f) => f.archivo)).toEqual(["falso.txt"]);
		expect(found[0]?.regla).toBe("binary-image");
	});

	it("SCAN-008 un archivo ilegible crea hallazgo abierto y no se omite", async () => {
		const root = await tmp();
		const found = await scanBinaries(root, ["no-existe.bin"]);
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({
			regla: "binary-unreadable",
			estado: "abierto",
			tipo: "binario",
		});
	});

	it("SCAN-008 un directorio o symlink se reporta, no se ignora", async () => {
		const root = await tmp();
		await mkdir(join(root, "carpeta"));
		await writeFile(join(root, "real.txt"), "x");
		let linked = true;
		try {
			await symlink(join(root, "real.txt"), join(root, "enlace.txt"));
		} catch {
			linked = false;
		}
		const names = linked ? ["carpeta", "enlace.txt"] : ["carpeta"];
		const found = await scanBinaries(root, names);
		expect(found).toHaveLength(names.length);
		expect(found.every((f) => f.regla === "binary-unreadable")).toBe(true);
	});

	it("SCAN-008 un archivo sobre el límite crea hallazgo abierto", async () => {
		const root = await tmp();
		await writeFile(join(root, "grande.txt"), "a".repeat(64));
		const found = await scanBinaries(root, ["grande.txt"], { maxBytes: 32 });
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({
			regla: "binary-oversize",
			estado: "abierto",
		});
	});

	it("SCAN-008 en cuarentena el hallazgo nace aislado", async () => {
		const root = await tmp();
		await writeFile(join(root, "x.bin"), ELF);
		const found = await scanBinaries(root, ["x.bin"], { zona: "quarantine" });
		expect(found[0]).toMatchObject({ zona: "quarantine", estado: "aislado" });
	});

	it("SCAN-008 el hallazgo es estable y no expone contenido", async () => {
		const root = await tmp();
		await writeFile(join(root, "x.bin"), ELF);
		const a = await scanBinaries(root, ["x.bin"]);
		const b = await scanBinaries(root, ["x.bin"]);
		expect(a).toEqual(b);
		expect(a[0]?.fragmento).toBe("****");
	});
});

describe("SEG-105 archivo completo", () => {
	it("SEG-105 un binario tras 8 KB de texto se detecta", async () => {
		const root = await tmp();
		await writeFile(
			join(root, "trampa.txt"),
			Buffer.concat([Buffer.alloc(20000, 0x61), Buffer.from([0, 1, 2, 3])]),
		);
		const found = await scanBinaries(root, ["trampa.txt"]);
		expect(found.map((f) => f.regla)).toEqual(["binary-unknown"]);
	});

	it("SEG-105 UTF-8 inválido tras 8 KB de texto se detecta", async () => {
		const root = await tmp();
		await writeFile(
			join(root, "malo.txt"),
			Buffer.concat([Buffer.alloc(20000, 0x61), Buffer.from([0xc3, 0x28])]),
		);
		const found = await scanBinaries(root, ["malo.txt"]);
		expect(found.map((f) => f.regla)).toEqual(["binary-unknown"]);
	});

	it("SEG-105 un texto largo válido no da hallazgo", async () => {
		const root = await tmp();
		await writeFile(join(root, "largo.txt"), "ñandú\n".repeat(30000));
		expect(await scanBinaries(root, ["largo.txt"])).toEqual([]);
	});

	it("SEG-105 UTF-16 válido nunca pasa sin revisar", async () => {
		const root = await tmp();
		await writeFile(
			join(root, "u16.txt"),
			Buffer.concat([
				Buffer.from([0xff, 0xfe]),
				Buffer.from("hola\n", "utf16le"),
			]),
		);
		const found = await scanBinaries(root, ["u16.txt"]);
		expect(found.map((f) => f.regla)).toEqual(["binary-utf16"]);
	});

	it("SEG-105 BOM UTF-16 con binario es desconocido", async () => {
		const root = await tmp();
		await writeFile(
			join(root, "fake.txt"),
			Buffer.from([0xff, 0xfe, 0, 0, 0, 0, 1, 2]),
		);
		const found = await scanBinaries(root, ["fake.txt"]);
		expect(found.map((f) => f.regla)).toEqual(["binary-unknown"]);
	});
});

describe("SCAN-009 el id de un binario incluye su contenido (backlog MAJOR)", () => {
	async function idOf(root: string, content: Buffer): Promise<string> {
		await writeFile(join(root, "logo.png"), content);
		const [found] = await scanBinaries(root, ["logo.png"]);
		return found?.id ?? "";
	}

	it("SCAN-009 el mismo contenido da el mismo id y otro contenido del mismo tipo da otro", async () => {
		const root = await tmp();
		const first = await idOf(root, PNG);
		expect(first).toMatch(/^[0-9a-f]{64}$/);
		expect(await idOf(root, PNG)).toBe(first);
		const other = Buffer.concat([PNG, Buffer.from([1, 2, 3])]);
		expect(await idOf(root, other)).not.toBe(first);
	});

	it("SCAN-009 un oversize que cambia solo después del primer MiB cambia de id", async () => {
		const root = await tmp();
		const MIB = 1024 * 1024;
		const body = Buffer.alloc(MIB + 4096, 7);
		await writeFile(join(root, "big.bin"), body);
		const [a] = await scanBinaries(root, ["big.bin"], { maxBytes: 1024 });
		const tail = Buffer.from(body);
		tail[tail.length - 1] = 9;
		await writeFile(join(root, "big.bin"), tail);
		const [b] = await scanBinaries(root, ["big.bin"], { maxBytes: 1024 });
		expect(a?.regla).toBe("binary-oversize");
		expect(a?.id).not.toBe(b?.id);
	});

	it("SCAN-009 un binario oversize reemplazado por otro del mismo tamaño cambia de id", async () => {
		const root = await tmp();
		await writeFile(join(root, "big.bin"), Buffer.alloc(64, 1));
		const [a] = await scanBinaries(root, ["big.bin"], { maxBytes: 16 });
		await writeFile(join(root, "big.bin"), Buffer.alloc(64, 2));
		const [b] = await scanBinaries(root, ["big.bin"], { maxBytes: 16 });
		expect(a?.regla).toBe("binary-oversize");
		expect(a?.id).not.toBe(b?.id);
	});
});
