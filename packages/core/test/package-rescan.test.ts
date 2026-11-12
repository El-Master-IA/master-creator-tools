import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import { nodeAdapter } from "@mct/adapter-node/index";
import { MctError } from "@mct/contract/errors";
import type { Finding } from "@mct/contract/types";
import { binaryFindingId } from "@mct/scanner/binary";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signApproval } from "../src/approval.js";
import { hashTree } from "../src/hash.js";
import {
	inheritStripped,
	type StagePackageOptions,
	stagePackage,
} from "../src/package.js";
import { type StageScanOptions, stageScan } from "../src/stage-scan.js";
import { createWorkspace, readState, updateState } from "../src/workspace.js";

// Fixture values are assembled from fragments: no literal secret lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const EXIF_MARK = ["Ex", "if"].join("");
const CAMERA = ["serial", "-", "ZX81"].join("");

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-package-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	await mkdir(join(home, ".mct"), { recursive: true });
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

function gitleaks(): StageScanOptions["gitleaks"] {
	return {
		binary: process.execPath,
		installDir: join(base, "bin"),
		tmpDir: join(raiz, "tmp"),
		run: okRunner,
	};
}

function opts(over: Partial<StagePackageOptions> = {}): StagePackageOptions {
	return {
		holder: "Acme Labs",
		year: 2026,
		home,
		gitleaks: gitleaks(),
		...over,
	};
}

/** Workspace with the scan done, every finding accepted and a signed approval. */
async function approved(files: Record<string, string | Uint8Array>) {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "demo-app" },
		adapter: "node",
	});
	await writeFile(
		join(ws.work, "package.json"),
		'{"name":"demo","version":"1.0.0"}\n',
	);
	for (const [rel, data] of Object.entries(files)) {
		const full = join(ws.work, rel);
		await mkdir(join(full, ".."), { recursive: true });
		await writeFile(full, data);
	}
	await stageScan(raiz, { home, gitleaks: gitleaks() }).catch((e: unknown) => {
		if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA") throw e;
	});
	const doc = JSON.parse(
		await readFile(join(raiz, "findings.json"), "utf8"),
	) as { hallazgos: Finding[] };
	doc.hallazgos = doc.hallazgos.map((h) =>
		h.estado === "abierto" ? { ...h, estado: "aceptado", motivo: "test" } : h,
	);
	await writeFile(join(raiz, "findings.json"), JSON.stringify(doc));
	await updateState(raiz, (s) => ({
		...s,
		etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
	}));
	await signApproval({
		raiz,
		hallazgos: doc.hallazgos,
		gitleaksVersion: "8.30.1",
		mctVersion: "0.0.0",
	});
	return ws;
}

function chunk(type: string, data: Uint8Array): Buffer {
	const head = Buffer.alloc(4);
	head.writeUInt32BE(data.length);
	const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
	const crc = Buffer.alloc(4);
	crc.writeUInt32BE(crc32(body) >>> 0);
	return Buffer.concat([head, body, crc]);
}

/** Real PNG layout: signature, IHDR, eXIf with a camera tag, IDAT, IEND. */
function pngWithExif(): Buffer {
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(1, 0);
	ihdr.writeUInt32BE(1, 4);
	ihdr[8] = 8;
	ihdr[9] = 2;
	return Buffer.concat([
		Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
		chunk("IHDR", ihdr),
		chunk("eXIf", Buffer.from(`MM\0*${CAMERA}`, "latin1")),
		chunk(
			"IDAT",
			Buffer.from([0x78, 0x9c, 0x63, 0x60, 0x60, 0x60, 0, 0, 0, 4, 0, 1]),
		),
		chunk("IEND", Buffer.alloc(0)),
	]);
}

/** Real JPEG layout: SOI, APP1 Exif, SOS with entropy data, EOI. */
function jpegWithExif(): Buffer {
	const exif = Buffer.from(`${EXIF_MARK}\0\0MM\0*${CAMERA}`, "latin1");
	const app1 = Buffer.alloc(4);
	app1.writeUInt16BE(0xffe1, 0);
	app1.writeUInt16BE(exif.length + 2, 2);
	return Buffer.concat([
		Buffer.from([0xff, 0xd8]),
		app1,
		exif,
		Buffer.from([0xff, 0xda, 0x00, 0x08, 1, 1, 0, 0, 0x3f, 0, 0x12, 0x34]),
		Buffer.from([0xff, 0xd9]),
	]);
}

describe("etapa package: re-scan y contenido de dist", {
	timeout: 60_000,
}, () => {
	it("PKG-003 CUANDO termina EL SISTEMA DEBE dar cero abiertos en dist y registrar distSha256", async () => {
		const ws = await approved({ "src/index.js": "export const a = 1;\n" });
		await updateState(raiz, (s) => ({
			...s,
			verificado: { distSha256: "a".repeat(64), destino: "local", ts: "x" },
			etapas: { ...s.etapas, verify: { estado: "ok", ts: "x" } },
		}));
		const r = await stagePackage(raiz, opts());
		const st = await readState(raiz);
		expect(st.etapas.package.estado).toBe("ok");
		expect(st.etapas.verify.estado).toBe("pendiente");
		expect(st.distSha256).toBe(r.distSha256);
		expect(await hashTree(ws.dist)).toBe(r.distSha256);
		for (const f of ["README.md", "README.es.md", "LICENSE", "SECURITY.md"]) {
			await stat(join(ws.dist, f));
		}
		expect(await readFile(join(ws.dist, "LICENSE"), "utf8")).toContain(
			"Acme Labs",
		);
		expect(r.archivos).toBeGreaterThan(5);
	});

	it("PKG-003 CUANDO dist queda con hallazgos abiertos EL SISTEMA DEBE salir con PUERTA_BLOQUEADA y package bloqueada", async () => {
		await approved({});
		const leaky = {
			...nodeAdapter,
			generalize: async () => [
				{
					tipo: "crear" as const,
					ruta: "src/leak.js",
					contenido: `const t = "${TOKEN}";\n`,
				},
			],
		};
		let codigo = "NINGUNO";
		try {
			await stagePackage(raiz, opts({ adapters: [leaky] }));
		} catch (e) {
			if (e instanceof MctError) codigo = e.codigo;
		}
		expect(codigo).toBe("PUERTA_BLOQUEADA");
		expect((await readState(raiz)).etapas.package.estado).toBe("bloqueada");
		expect(
			JSON.stringify(
				await readFile(join(raiz, "logs", "package.jsonl"), "utf8").catch(
					() => "",
				),
			),
		).not.toContain(TOKEN);
	});

	it("SCAN-011 CUANDO una imagen con EXIF pasa a dist EL SISTEMA DEBE dejarla sin metadatos", async () => {
		const ws = await approved({
			"img/foto.png": pngWithExif(),
			"img/foto.jpg": jpegWithExif(),
		});
		const r = await stagePackage(raiz, opts());
		expect(r.distSha256).toHaveLength(64);
		for (const f of ["img/foto.png", "img/foto.jpg"]) {
			const out = await readFile(join(ws.dist, f));
			expect(out.includes(CAMERA)).toBe(false);
			expect(out.includes(EXIF_MARK)).toBe(false);
		}
		// work/ is never rewritten.
		expect(
			(await readFile(join(ws.work, "img/foto.png"))).includes(CAMERA),
		).toBe(true);
	});

	it("SCAN-011 CUANDO una imagen está corrupta EL SISTEMA DEBE fallar sin tocar dist", async () => {
		const ws = await approved({
			"img/rota.png": pngWithExif().subarray(0, 40),
		});
		await writeFile(join(ws.dist, "previo.txt"), "intacto\n");
		await expect(stagePackage(raiz, opts())).rejects.toBeInstanceOf(MctError);
		expect(await readFile(join(ws.dist, "previo.txt"), "utf8")).toBe(
			"intacto\n",
		);
	});

	it("SCAN-011 CUANDO un favicon.ico embebe un PNG con eXIf EL SISTEMA DEBE fallar cerrado nombrando la ruta", async () => {
		const png = pngWithExif();
		const dir = Buffer.alloc(22);
		dir.writeUInt16LE(1, 2);
		dir.writeUInt16LE(1, 4);
		dir[6] = 1;
		dir[7] = 1;
		dir.writeUInt16LE(1, 10);
		dir.writeUInt16LE(32, 12);
		dir.writeUInt32LE(png.length, 14);
		dir.writeUInt32LE(22, 18);
		const ws = await approved({ "favicon.ico": Buffer.concat([dir, png]) });
		await writeFile(join(ws.dist, "previo.txt"), "intacto\n");
		const err = await stagePackage(raiz, opts()).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(
			JSON.stringify((err as MctError).detalle ?? {}) +
				(err as MctError).message,
		).toContain("favicon.ico");
		expect(await readFile(join(ws.dist, "previo.txt"), "utf8")).toBe(
			"intacto\n",
		);
	});

	it("SCAN-011 CUANDO un .bmp trae bytes tras los píxeles EL SISTEMA DEBE fallar cerrado nombrando la ruta", async () => {
		const header = Buffer.alloc(58);
		header.write("BM", 0, "latin1");
		header.writeUInt32LE(58 + 4, 2);
		header.writeUInt32LE(54, 10);
		header.writeUInt32LE(40, 14);
		header.writeInt32LE(1, 18);
		header.writeInt32LE(1, 22);
		header.writeUInt16LE(1, 26);
		header.writeUInt16LE(24, 28);
		const bmp = Buffer.concat([header, Buffer.from(`GPS:${CAMERA}`, "latin1")]);
		await approved({ "img/foto.bmp": bmp });
		const err = await stagePackage(raiz, opts()).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(
			JSON.stringify((err as MctError).detalle ?? {}) +
				(err as MctError).message,
		).toContain("img/foto.bmp");
	});

	it("PKG-003 CUANDO generalize quita campos de package.json y desplaza líneas EL SISTEMA DEBE conservar la decisión humana y dar package ok", async () => {
		const pkg = `${JSON.stringify(
			{
				name: "demo",
				version: "1.0.0",
				author: "Alguien <alguien@example.com>",
				homepage: "https://example.com/demo",
				scripts: { deploy: `curl -H "Authorization: ${TOKEN}" https://x.test` },
			},
			null,
			2,
		)}\n`;
		const ws = await approved({});
		await writeFile(join(ws.work, "package.json"), pkg);
		await stageScan(raiz, { home, gitleaks: gitleaks() }).catch(
			(e: unknown) => {
				if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA")
					throw e;
			},
		);
		const doc = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(doc.hallazgos.some((h) => h.archivo === "package.json")).toBe(true);
		doc.hallazgos = doc.hallazgos.map((h) =>
			h.estado === "abierto" ? { ...h, estado: "aceptado", motivo: "test" } : h,
		);
		await writeFile(join(raiz, "findings.json"), JSON.stringify(doc));
		await updateState(raiz, (s) => ({
			...s,
			etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
		}));
		await signApproval({
			raiz,
			hallazgos: doc.hallazgos,
			gitleaksVersion: "8.30.1",
			mctVersion: "0.0.0",
		});
		await stagePackage(raiz, opts());
		expect((await readState(raiz)).etapas.package.estado).toBe("ok");
		const out = await readFile(join(ws.dist, "package.json"), "utf8");
		expect(out.includes("author")).toBe(false);
	});

	for (const [nombre, brand, compat] of [
		["foto.heic", "heic", "mif1heic"],
		["foto.avif", "avif", "mif1avif"],
		["foto2.heic", "MiHE", "mif1MiHB"],
	] as const) {
		it(`SCAN-011 CUANDO work trae ${nombre} con EXIF EL SISTEMA DEBE fallar cerrado sin escribir dist`, async () => {
			const ftyp = Buffer.alloc(16 + compat.length);
			ftyp.writeUInt32BE(ftyp.length, 0);
			ftyp.write("ftyp", 4, "latin1");
			ftyp.write(brand, 8, "latin1");
			ftyp.write(compat, 16, "latin1");
			const img = Buffer.concat([
				ftyp,
				Buffer.from(`${EXIF_MARK}\0\0GPS ${CAMERA}`, "latin1"),
			]);
			const ws = await approved({ [`img/${nombre}`]: img });
			await writeFile(join(ws.dist, "previo.txt"), "intacto\n");
			const err = await stagePackage(raiz, opts()).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(MctError);
			expect(
				JSON.stringify((err as MctError).detalle ?? {}) +
					(err as MctError).message,
			).toContain(`img/${nombre}`);
			expect(await readFile(join(ws.dist, "previo.txt"), "utf8")).toBe(
				"intacto\n",
			);
		});
	}

	for (const [nombre, head] of [
		[
			"foto.jp2",
			[0, 0, 0, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a],
		],
		["foto.cr3", [0, 0, 0, 0x18, ...Buffer.from("ftypcrx \0\0\0\0crx isom")]],
		["foto.tif", [0x49, 0x49, 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00]],
		["foto.orf", [0x49, 0x49, 0x52, 0x4f, 0x08, 0x00, 0x00, 0x00]],
		["foto.rw2", [0x49, 0x49, 0x55, 0x00, 0x18, 0x00, 0x00, 0x00]],
		["capa.psd", [0x38, 0x42, 0x50, 0x53, 0x00, 0x01]],
		[
			"larga.heic",
			[
				0,
				0,
				0,
				1,
				...Buffer.from("ftyp"),
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0x20,
				...Buffer.from("heic\0\0\0\0mif1"),
			],
		],
		[
			"hasta-eof.heic",
			[0, 0, 0, 0, ...Buffer.from("ftypisom\0\0\0\0isomheic")],
		],
	] as const) {
		it(`SCAN-011 CUANDO work trae ${nombre} con metadatos EL SISTEMA DEBE fallar cerrado`, async () => {
			await approved({
				[`img/${nombre}`]: Buffer.concat([
					Buffer.from(head),
					Buffer.from(`${EXIF_MARK}\0\0GPS ${CAMERA}`, "latin1"),
				]),
			});
			const err = await stagePackage(raiz, opts()).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(MctError);
			expect(JSON.stringify((err as MctError).detalle ?? {})).toContain(
				`img/${nombre}`,
			);
		});
	}

	it("SCAN-011 CUANDO work trae un MP4 EL SISTEMA DEBE copiarlo sin bloquear", async () => {
		const ws = await approved({
			"media/clip.mp4": Buffer.concat([
				Buffer.from([0, 0, 0, 0x18]),
				Buffer.from("ftypisom\0\0\0\0isommp41", "latin1"),
				Buffer.alloc(64, 7),
			]),
		});
		await stagePackage(raiz, opts());
		expect((await stat(join(ws.dist, "media/clip.mp4"))).size).toBeGreaterThan(
			0,
		);
	});

	it("PKG-003 CUANDO generalize reformatea un package.json compacto EL SISTEMA DEBE conservar la decisión del mismo secreto", async () => {
		const ws = await approved({});
		await writeFile(
			join(ws.work, "package.json"),
			`{"name":"demo","version":"1.0.0","author":"x","config":{"k":"${TOKEN}"}}`,
		);
		await stageScan(raiz, { home, gitleaks: gitleaks() }).catch(
			(e: unknown) => {
				if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA")
					throw e;
			},
		);
		const doc = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(doc.hallazgos.some((h) => h.archivo === "package.json")).toBe(true);
		doc.hallazgos = doc.hallazgos.map((h) =>
			h.estado === "abierto" ? { ...h, estado: "aceptado", motivo: "test" } : h,
		);
		await writeFile(join(raiz, "findings.json"), JSON.stringify(doc));
		await updateState(raiz, (s) => ({
			...s,
			etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
		}));
		await signApproval({
			raiz,
			hallazgos: doc.hallazgos,
			gitleaksVersion: "8.30.1",
			mctVersion: "0.0.0",
		});
		await stagePackage(raiz, opts());
		expect((await readState(raiz)).etapas.package.estado).toBe("ok");
		const out = await readFile(join(ws.dist, "package.json"), "utf8");
		expect(out.includes("author")).toBe(false);
		expect(out.split("\n").length).toBeGreaterThan(2);
	});

	it("PKG-003 CUANDO generalize reformatea el match de gitleaks del mismo secreto EL SISTEMA DEBE conservar la decisión", async () => {
		// Fake gitleaks: reports generic-api-key on whatever line of package.json holds the token.
		const reporting: Runner = async (_c, args, o) => {
			if (args.includes("version")) return okRunner(_c, args, o);
			const src = args[args.indexOf("dir") + 1] ?? "";
			const rp = args[args.indexOf("--report-path") + 1] as string;
			const text = await readFile(join(src, "package.json"), "utf8").catch(
				() => "",
			);
			const lines = text.split("\n");
			const i = lines.findIndex((l) => l.includes(TOKEN));
			const report =
				i < 0
					? []
					: [
							{
								RuleID: "generic-api-key",
								File: "package.json",
								StartLine: i + 1,
								EndLine: i + 1,
								// Real gitleaks reports both columns +1 outside the first line.
								StartColumn:
									(lines[i]?.indexOf('"k"') ?? 0) + 1 + (i > 0 ? 1 : 0),
								EndColumn:
									(lines[i]?.indexOf(TOKEN) ?? 0) +
									TOKEN.length +
									1 +
									(i > 0 ? 1 : 0),
								Match: lines[i]?.slice(
									lines[i].indexOf('"k"'),
									lines[i].indexOf(TOKEN) + TOKEN.length + 1,
								),
								Secret: "REDACTED",
								Fingerprint: "x",
							},
						];
			await writeFile(rp, JSON.stringify(report));
			return {
				code: report.length > 0 ? 2 : 0,
				signal: null,
				stdout: "",
				timedOut: false,
			};
		};
		const g = { ...gitleaks(), run: reporting };
		const ws = await approved({});
		await writeFile(
			join(ws.work, "package.json"),
			`{"name":"demo","version":"1.0.0","author":"x","config":{"k":"${TOKEN}"}}`,
		);
		await stageScan(raiz, { home, gitleaks: g }).catch((e: unknown) => {
			if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA") throw e;
		});
		const doc = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(
			doc.hallazgos.some(
				(h) => h.motor === "gitleaks" && h.archivo === "package.json",
			),
		).toBe(true);
		doc.hallazgos = doc.hallazgos.map((h) =>
			h.estado === "abierto" ? { ...h, estado: "aceptado", motivo: "test" } : h,
		);
		await writeFile(join(raiz, "findings.json"), JSON.stringify(doc));
		await updateState(raiz, (s) => ({
			...s,
			etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
		}));
		await signApproval({
			raiz,
			hallazgos: doc.hallazgos,
			gitleaksVersion: "8.30.1",
			mctVersion: "0.0.0",
		});
		await stagePackage(raiz, opts({ gitleaks: g }));
		expect((await readState(raiz)).etapas.package.estado).toBe("ok");
		expect(await readFile(join(ws.dist, "package.json"), "utf8")).toContain(
			'"k": "',
		);
	});

	it("SCAN-011 CUANDO work trae un JPEG XL EL SISTEMA DEBE fallar cerrado", async () => {
		await approved({
			"img/foto.jxl": Buffer.concat([
				Buffer.from([0xff, 0x0a]),
				Buffer.from(`${EXIF_MARK} ${CAMERA}`, "latin1"),
			]),
		});
		await expect(stagePackage(raiz, opts())).rejects.toBeInstanceOf(MctError);
	});

	it("PKG-003 CUANDO generalize pone otro secreto con la misma máscara EL SISTEMA DEBE dejarlo abierto", async () => {
		const otro = `${TOKEN.slice(0, 6)}${"Z".repeat(TOKEN.length - 10)}${TOKEN.slice(-4)}`;
		expect(otro).toHaveLength(TOKEN.length);
		await approved({ "src/a.js": `const a = "${TOKEN}";\n` });
		const original = `const a = "${TOKEN}";\n`;
		const swap = {
			...nodeAdapter,
			generalize: async () => [
				{
					tipo: "editar" as const,
					ruta: "src/a.js",
					desde: 0,
					hasta: original.length,
					texto: `// nota\nconst a = "${otro}";\n`,
				},
			],
		};
		let codigo = "NINGUNO";
		try {
			await stagePackage(raiz, opts({ adapters: [swap] }));
		} catch (e) {
			if (e instanceof MctError) codigo = e.codigo;
		}
		expect(codigo).toBe("PUERTA_BLOQUEADA");
	});

	it("PKG-003 CUANDO generalize solo desplaza la línea del secreto aceptado EL SISTEMA DEBE conservar la decisión", async () => {
		const original = `const a = "${TOKEN}";\n`;
		await approved({ "src/a.js": original });
		const shift = {
			...nodeAdapter,
			generalize: async () => [
				{
					tipo: "editar" as const,
					ruta: "src/a.js",
					desde: 0,
					hasta: 0,
					texto: "// nota\n",
				},
			],
		};
		await stagePackage(raiz, opts({ adapters: [shift] }));
		expect((await readState(raiz)).etapas.package.estado).toBe("ok");
	});

	it("SCAN-011 CUANDO work trae un GIF EL SISTEMA DEBE fallar cerrado con MctError que nombra la ruta", async () => {
		await approved({
			"img/anim.gif": Buffer.concat([
				Buffer.from("GIF89a"),
				Buffer.alloc(20, 1),
			]),
		});
		const err = await stagePackage(raiz, opts()).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(
			JSON.stringify((err as MctError).detalle ?? {}) +
				(err as MctError).message,
		).toContain("img/anim.gif");
	});

	it("SCAN-008 CUANDO un binario fue eliminado de work EL SISTEMA DEBE no incluirlo en dist", async () => {
		const ws = await approved({ "img/logo.png": pngWithExif() });
		await writeFile(
			join(ws.dist, "img-vieja.png"),
			"resto de un dist anterior",
		);
		await rm(join(ws.work, "img", "logo.png"));
		// The deletion changes work/: sign again over the new tree.
		const doc = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		await stageScan(raiz, { home, gitleaks: gitleaks() });
		await updateState(raiz, (s) => ({
			...s,
			etapas: { ...s.etapas, sanitize: { estado: "ok", ts: "x" } },
		}));
		await signApproval({
			raiz,
			hallazgos: doc.hallazgos.map((h) => ({ ...h, estado: "obsoleto" })),
			gitleaksVersion: "8.30.1",
			mctVersion: "0.0.0",
		});
		await stagePackage(raiz, opts());
		await expect(stat(join(ws.dist, "img", "logo.png"))).rejects.toThrow();
		await expect(stat(join(ws.dist, "img-vieja.png"))).rejects.toThrow();
	});

	it("PKG-002 CUANDO work ya trae .github/workflows/ci.yml EL SISTEMA DEBE conservarlo en dist", async () => {
		const ws = await approved({
			".github/workflows/ci.yml": "name: del-proyecto\non: push\njobs: {}\n",
		});
		await stagePackage(raiz, opts());
		expect(
			await readFile(join(ws.dist, ".github/workflows/ci.yml"), "utf8"),
		).toBe("name: del-proyecto\non: push\njobs: {}\n");
		await stat(join(ws.dist, ".github/pull_request_template.md"));
	});

	it("PKG-002 CUANDO work no trae workflow EL SISTEMA DEBE generar el de la plantilla", async () => {
		const ws = await approved({});
		await stagePackage(raiz, opts());
		expect(
			await readFile(join(ws.dist, ".github/workflows/ci.yml"), "utf8"),
		).not.toContain("del-proyecto");
	});

	it("PKG-003 CUANDO se regenera dist EL SISTEMA DEBE dar el mismo hash desde el mismo work", async () => {
		await approved({ "src/a.js": "export const a = 1;\n" });
		const a = await stagePackage(raiz, opts());
		const b = await stagePackage(raiz, opts());
		expect(b.distSha256).toBe(a.distSha256);
	});
});

const CLAVE_PRUEBA = Buffer.alloc(32, 7);

describe("PKG-003 decisiones de binarios con metadatos limpiados", () => {
	const base = {
		motor: "mct",
		tipo: "binario",
		zona: "work",
		linea: 0,
		columna: 0,
		fragmento: "****",
		severidad: "medio",
	} as const;
	const original = "1".repeat(64);
	const aceptado = {
		...base,
		id: binaryFindingId("binary-image", "img/foto.png", original, CLAVE_PRUEBA),
		regla: "binary-image",
		archivo: "img/foto.png",
		estado: "aceptado",
		motivo: "logo de la empresa sin datos personales",
	} as const;
	const abierto = (id: string, regla: string, archivo: string) => ({
		...base,
		id,
		regla,
		archivo,
		estado: "abierto" as const,
	});

	it("PKG-003 la imagen limpiada con los mismos bytes originales hereda la decisión; otro archivo o regla no", () => {
		const final = [
			abierto("b".repeat(64), "binary-image", "img/foto.png"),
			abierto("c".repeat(64), "binary-image", "img/otra.png"),
			abierto("d".repeat(64), "binary-unknown", "img/foto.png"),
		];
		const out = inheritStripped(
			[aceptado],
			final,
			new Map([
				["img/foto.png", original],
				["img/otra.png", original],
			]),
			CLAVE_PRUEBA,
		);
		expect(out.map((f) => f.estado)).toEqual([
			"aceptado",
			"abierto",
			"abierto",
		]);
		expect(out[0]?.motivo).toBe(aceptado.motivo);
	});

	it("PKG-003 una imagen reemplazada con el mismo nombre y regla queda abierta", () => {
		const out = inheritStripped(
			[aceptado],
			[abierto("b".repeat(64), "binary-image", "img/foto.png")],
			new Map([["img/foto.png", "2".repeat(64)]]),
			CLAVE_PRUEBA,
		);
		expect(out[0]?.estado).toBe("abierto");
	});

	it("PKG-003 un binario que no pasó por la limpieza no hereda con otro id", () => {
		const out = inheritStripped(
			[aceptado],
			[abierto("b".repeat(64), "binary-image", "img/foto.png")],
			new Map(),
			CLAVE_PRUEBA,
		);
		expect(out[0]?.estado).toBe("abierto");
	});

	it("PKG-003 un hallazgo de cuarentena no hereda ni se toca", () => {
		const q = {
			...abierto("b".repeat(64), "binary-image", "img/foto.png"),
			zona: "quarantine" as const,
		};
		const out = inheritStripped(
			[aceptado],
			[q],
			new Map([["img/foto.png", original]]),
			CLAVE_PRUEBA,
		);
		expect(out[0]?.estado).toBe("abierto");
	});
});
