import { createHash } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Change, Finding } from "@mct/contract/types";
import { findingId } from "@mct/scanner/finding-id";
import { detectPii } from "@mct/scanner/pii";
import { detectSecrets } from "@mct/scanner/secrets";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeSecrets } from "../../scanner/test/fixtures/secretos.js";
import {
	type Decision,
	type Decisor,
	type SanitizeOptions,
	sanitize,
} from "../src/sanitize.js";
import { createWorkspace, readState, updateState } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
// Synthetic values built from fragments (T05): no literal secret lives here.
const SECRET = ["tok", "en-", "a1b2c3d4e5f6a7b8c9d0"].join("");
const SECRET_B = ["tok", "en-", "z9y8x7w6v5u4t3s2r1q0"].join("");
const DB_VALUE = ["pw", "-", "m4n5b6v7c8x9z0"].join("");
const NAME = ["DB", "PASS"].join("_");

let base: string;
let raiz: string;
let work: string;
let quarantine: string;

async function put(root: string, rel: string, content: string | Buffer) {
	const full = join(root, ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, content);
}

function lineCol(text: string, index: number): [number, number] {
	const before = text.slice(0, index);
	const linea = before.split("\n").length;
	return [linea, index - (before.lastIndexOf("\n") + 1) + 1];
}

function mkFinding(
	archivo: string,
	text: string,
	value: string,
	zona: "work" | "quarantine" = "work",
	regla = "generic-token",
): Finding {
	const [linea, columna] = lineCol(text, text.indexOf(value));
	return {
		id: findingId({ motor: "mct", regla, archivo, linea, value }),
		motor: "mct",
		regla,
		tipo: "secreto",
		zona,
		archivo,
		linea,
		columna,
		fragmento: `${value.slice(0, 4)}****`,
		severidad: "critico",
		estado: zona === "quarantine" ? "aislado" : "abierto",
	};
}

function binFinding(archivo: string): Finding {
	return {
		id: findingId({
			motor: "mct",
			regla: "binary-unknown",
			archivo,
			linea: 0,
			value: "bin",
		}),
		motor: "mct",
		regla: "binary-unknown",
		tipo: "binario",
		zona: "work",
		archivo,
		linea: 0,
		columna: 0,
		fragmento: "****",
		severidad: "medio",
		estado: "abierto",
	};
}

async function writeFindings(hallazgos: Finding[]) {
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({
			schemaVersion: 1,
			mctVersion: "0.0.0",
			gitleaksVersion: "8.30.1",
			generadoEn: T0,
			hallazgos,
		}),
	);
}

async function readFindings(): Promise<Finding[]> {
	return JSON.parse(await readFile(join(raiz, "findings.json"), "utf8"))
		.hallazgos;
}

async function files(dir: string, rel = ""): Promise<string[]> {
	const out: string[] = [];
	for (const e of await readdir(join(dir, rel), { withFileTypes: true })) {
		const r = rel === "" ? e.name : `${rel}/${e.name}`;
		if (e.isDirectory()) out.push(...(await files(dir, r)));
		else out.push(r);
	}
	return out;
}

/** Fake re-scan: looks for known values in work (open) and quarantine (aislado). */
function fakeRescan(valores: string[]): SanitizeOptions["rescan"] {
	return async () => {
		const hallazgos: Finding[] = [];
		for (const [dir, zona] of [
			[work, "work"],
			[quarantine, "quarantine"],
		] as const) {
			for (const rel of await files(dir)) {
				const buf = await readFile(join(dir, rel));
				if (buf.includes(0)) {
					if (zona === "work") hallazgos.push(binFinding(rel));
					continue;
				}
				const text = buf.toString("utf8");
				for (const v of valores) {
					let at = text.indexOf(v);
					while (at >= 0) {
						const [linea, columna] = lineCol(text, at);
						hallazgos.push({
							...mkFinding(rel, text.slice(0, at) + v, v, zona),
							linea,
							columna,
							id: findingId({
								motor: "mct",
								regla: "generic-token",
								archivo: rel,
								linea,
								value: v,
							}),
						});
						at = text.indexOf(v, at + v.length);
					}
				}
			}
		}
		return { hallazgos, gitleaksVersion: "8.30.1" };
	};
}

/** Re-scan that always reports the given findings (used when the tree cannot be re-derived). */
function fixedRescan(lista: Finding[]): SanitizeOptions["rescan"] {
	return async () => ({
		hallazgos: lista.map((f) => ({ ...f })),
		gitleaksVersion: "8.30.1",
	});
}

const ph = (n: string) => `\${${n}}`;
const FP = "Es un dato de ejemplo del manual";

function decisor(fn: (h: Finding) => Decision): Decisor & {
	visto: Finding[];
	confirmar: ReturnType<typeof vi.fn>;
	ctxs: unknown[];
} {
	const visto: Finding[] = [];
	const ctxs: unknown[] = [];
	return {
		visto,
		ctxs,
		decidir: async (h, ctx) => {
			visto.push(h);
			ctxs.push(ctx);
			return fn(h);
		},
		confirmar: vi.fn(async () => true),
	};
}

function opts(
	over: Partial<SanitizeOptions> & Pick<SanitizeOptions, "decisor">,
): SanitizeOptions {
	return {
		raiz,
		tty: true,
		mctVersion: "0.0.0",
		now: () => T0,
		usuario: () => "tester",
		rescan: fakeRescan([SECRET, SECRET_B]),
		...over,
	};
}

const sha = (b: Buffer | string) =>
	createHash("sha256").update(b).digest("hex");

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t19-"));
	raiz = join(base, ".mct");
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "x" },
		adapter: "node",
		now: () => T0,
	});
	work = join(raiz, "work");
	quarantine = join(raiz, "quarantine");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("sanitize · reemplazo", () => {
	it("SAN-001 reemplazar pone el placeholder y agrega NOMBRE= a .env.example", async () => {
		const text = `export const k = "${SECRET}";\n`;
		await put(work, "src/config.ts", text);
		await writeFindings([mkFinding("src/config.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "reemplazar", nombre: "API_TOKEN" }));
		const res = await sanitize(opts({ decisor: d }));
		const out = await readFile(join(work, "src/config.ts"), "utf8");
		expect(out).toBe(`export const k = "${ph("API_TOKEN")}";\n`);
		expect(out).not.toContain(SECRET);
		expect(await readFile(join(work, ".env.example"), "utf8")).toContain(
			"API_TOKEN=\n",
		);
		expect(res.abiertos).toBe(0);
		expect(res.decididos.resuelto).toBe(1);
		expect(res.aprobacion?.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
	});

	it("SAN-001 sugiere un nombre a partir de la regla y respeta CRLF y multibyte", async () => {
		const text = `// ñandú 😀 línea\r\nconst a = "${SECRET}"; // fin\r\nlisto\r\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await sanitize(opts({ decisor: d }));
		const out = await readFile(join(work, "a.ts"));
		expect(out.toString("utf8")).toBe(
			text.replace(SECRET, ph("GENERIC_TOKEN")),
		);
		expect(out.includes(Buffer.from("\r\n"))).toBe(true);
	});

	it("SAN-001 el mismo valor en dos lugares comparte placeholder y una sola línea en .env.example", async () => {
		const t1 = `a=${SECRET}\n`;
		const t2 = `b: ${SECRET}\nc: ${SECRET_B}\n`;
		await put(work, "a.env.txt", t1);
		await put(work, "b.yml", t2);
		await writeFindings([
			mkFinding("a.env.txt", t1, SECRET),
			mkFinding("b.yml", t2, SECRET),
			{
				...mkFinding("b.yml", t2, SECRET_B),
			},
		]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await sanitize(opts({ decisor: d }));
		const a = await readFile(join(work, "a.env.txt"), "utf8");
		const b = await readFile(join(work, "b.yml"), "utf8");
		expect(a).toBe(`a=${ph("GENERIC_TOKEN")}\n`);
		expect(b).toBe(`b: ${ph("GENERIC_TOKEN")}\nc: ${ph("GENERIC_TOKEN_2")}\n`);
		const env = await readFile(join(work, ".env.example"), "utf8");
		expect(env.split("\n").filter(Boolean).sort()).toEqual([
			"GENERIC_TOKEN=",
			"GENERIC_TOKEN_2=",
		]);
	});

	it("SAN-001 conserva el modo del archivo editado", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "run.sh", text);
		await chmod(join(work, "run.sh"), 0o755);
		const before = (await stat(join(work, "run.sh"))).mode & 0o777;
		await writeFindings([mkFinding("run.sh", text, SECRET)]);
		await sanitize(
			opts({ decisor: decisor(() => ({ accion: "reemplazar" })) }),
		);
		expect((await stat(join(work, "run.sh"))).mode & 0o777).toBe(before);
	});

	it("SAN-001 un nombre de placeholder inválido sale con VALIDACION sin tocar nada", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "reemplazar", nombre: "no valido!" }));
		await expect(sanitize(opts({ decisor: d }))).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(await readFile(join(work, "a.ts"), "utf8")).toBe(text);
	});

	it("SAN-001 un hallazgo que ya no coincide con el archivo no se puede reemplazar (falla cerrado)", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		const f = mkFinding("a.ts", text, SECRET);
		await writeFindings([f]);
		await put(work, "a.ts", `// movido\n${text}`);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await expect(
			sanitize(opts({ decisor: d, rescan: fixedRescan([f]) })),
		).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(d.ctxs[0]).toMatchObject({ puedeReemplazar: false });
	});

	it("SAN-001 un hallazgo con [dic:n] en el archivo no resuelve a ruta real y solo admite falso positivo", async () => {
		const f: Finding = {
			...binFinding("[dic:0]/notas.txt"),
			tipo: "pii",
			regla: "dict-match",
			fragmento: "[dic:0]",
		};
		await put(work, "real/notas.txt", "hola\n");
		await writeFindings([f]);
		const malo = decisor(() => ({ accion: "reemplazar" }));
		const rescan = fixedRescan([f]);
		await expect(
			sanitize(opts({ decisor: malo, rescan })),
		).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(malo.ctxs[0]).toMatchObject({ puedeReemplazar: false });
		const bueno = decisor(() => ({ accion: "falso-positivo", motivo: FP }));
		const res = await sanitize(opts({ decisor: bueno, rescan }));
		expect(res.decididos.falsoPositivo).toBe(1);
		expect(await readFile(join(work, "real/notas.txt"), "utf8")).toBe("hola\n");
	});

	it("SAN-001 rechaza rutas de hallazgo que salen de work/", async () => {
		await put(base, "afuera.txt", "intacto\n");
		const f = { ...binFinding("../afuera.txt") };
		await writeFindings([f]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await expect(
			sanitize(opts({ decisor: d, rescan: fixedRescan([f]) })),
		).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(await readFile(join(base, "afuera.txt"), "utf8")).toBe("intacto\n");
	});
});

describe("sanitize · aislados", () => {
	it("SAN-001 los aislados no se ofrecen y solo aportan el nombre de su variable", async () => {
		const env = `${NAME}=${DB_VALUE}\nOTRA=1\n`;
		await put(quarantine, ".env", env);
		const f = mkFinding(".env", env, DB_VALUE, "quarantine");
		await writeFindings([f]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		const res = await sanitize(
			opts({ decisor: d, rescan: fakeRescan([DB_VALUE]) }),
		);
		expect(d.visto).toHaveLength(0);
		expect(res.abiertos).toBe(0);
		const example = await readFile(join(work, ".env.example"), "utf8");
		expect(example).toBe(`${NAME}=\n`);
		expect(example).not.toContain(DB_VALUE);
		// quarantine is never written
		expect(await readFile(join(quarantine, ".env"), "utf8")).toBe(env);
		for (const rel of ["findings.json", "approval.json", "report.html"]) {
			expect(await readFile(join(raiz, rel), "utf8")).not.toContain(DB_VALUE);
		}
		const logs = await readdir(join(raiz, "logs")).catch(() => []);
		for (const l of logs) {
			expect(await readFile(join(raiz, "logs", l), "utf8")).not.toContain(
				DB_VALUE,
			);
		}
	});

	it("SAN-001 no duplica un nombre que ya está en .env.example", async () => {
		const env = `${NAME}=${DB_VALUE}\n`;
		await put(quarantine, ".env", env);
		await put(work, ".env.example", `FOO=\n${NAME}=\n`);
		await writeFindings([mkFinding(".env", env, DB_VALUE, "quarantine")]);
		await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "abortar" })),
				rescan: fakeRescan([DB_VALUE]),
			}),
		);
		expect(await readFile(join(work, ".env.example"), "utf8")).toBe(
			`FOO=\n${NAME}=\n`,
		);
	});

	it("SAN-001 una línea de .npmrc sin nombre de variable válido no aporta nada", async () => {
		const npmrc = `//registro.ejemplo/:_authToken=${DB_VALUE}\n`;
		await put(quarantine, ".npmrc", npmrc);
		await writeFindings([mkFinding(".npmrc", npmrc, DB_VALUE, "quarantine")]);
		await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "abortar" })),
				rescan: fakeRescan([DB_VALUE]),
			}),
		);
		await expect(stat(join(work, ".env.example"))).rejects.toThrow();
	});
});

describe("sanitize · binarios", () => {
	it("SCAN-008 eliminar un binario lo borra de work y cierra su hallazgo", async () => {
		await put(work, "assets/blob.bin", Buffer.from([0, 1, 2, 3, 0, 255]));
		await put(quarantine, "x.bin", Buffer.from([0, 9]));
		await writeFindings([binFinding("assets/blob.bin")]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		const res = await sanitize(opts({ decisor: d }));
		await expect(stat(join(work, "assets/blob.bin"))).rejects.toThrow();
		expect(await files(quarantine)).toEqual(["x.bin"]);
		expect(res.abiertos).toBe(0);
		const f = (await readFindings()).find((x) => x.tipo === "binario");
		expect(f?.estado).toBe("resuelto");
		expect(d.ctxs[0]).toMatchObject({ puedeReemplazar: true, eliminar: true });
	});

	it("SCAN-008 un binario aceptado con motivo se conserva", async () => {
		await put(work, "logo.bin", Buffer.from([0, 7, 7]));
		await writeFindings([binFinding("logo.bin")]);
		const d = decisor(() => ({ accion: "aceptar", motivo: FP }));
		const res = await sanitize(opts({ decisor: d }));
		expect(res.decididos.aceptado).toBe(1);
		expect((await stat(join(work, "logo.bin"))).isFile()).toBe(true);
	});
});

describe("sanitize · motivos y controles", () => {
	it.each([
		["corto", "demasiado"],
		["con salto de línea", "motivo valido\nsegunda línea"],
		["con carácter invisible", `motivo valido${"\u200b"}ok`],
		["solo espacios", "           "],
		["con relleno braille", `motivo${"\u2800".repeat(8)}`],
	])("SAN-002 motivo %s sale con VALIDACION", async (_n, motivo) => {
		await put(work, "logo.bin", Buffer.from([0, 7, 7]));
		await writeFindings([binFinding("logo.bin")]);
		const d = decisor(() => ({ accion: "falso-positivo", motivo }));
		await expect(sanitize(opts({ decisor: d }))).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect((await stat(join(work, "logo.bin"))).isFile()).toBe(true);
	});

	it("SAN-002 un motivo que contiene el valor del hallazgo se rechaza", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({
			accion: "falso-positivo",
			motivo: `es de prueba: ${SECRET}`,
		}));
		const err = await sanitize(opts({ decisor: d })).catch((e) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(err.codigo).toBe("VALIDACION");
		expect(JSON.stringify(err.toJSON())).not.toContain(SECRET);
	});

	it("SAN-004 sin TTY no aprueba y sale con PUERTA_BLOQUEADA sin cambiar nada", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await expect(
			sanitize(opts({ decisor: d, tty: false })),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
		expect(await readFile(join(work, "a.ts"), "utf8")).toBe(text);
		expect(d.visto).toHaveLength(0);
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
	});

	it("CLI-008 abortar sale con CANCELADO y deja el workspace como estaba", async () => {
		const t1 = `a="${SECRET}"\n`;
		const t2 = `b="${SECRET_B}"\n`;
		await put(work, "a.ts", t1);
		await put(work, "b.ts", t2);
		await writeFindings([
			mkFinding("a.ts", t1, SECRET),
			mkFinding("b.ts", t2, SECRET_B),
		]);
		let n = 0;
		const d = decisor(() =>
			n++ === 0 ? { accion: "reemplazar" } : { accion: "abortar" },
		);
		await expect(sanitize(opts({ decisor: d }))).rejects.toMatchObject({
			codigo: "CANCELADO",
		});
		expect(await readFile(join(work, "a.ts"), "utf8")).toBe(t1);
		expect(await readFile(join(work, "b.ts"), "utf8")).toBe(t2);
		await expect(stat(join(work, ".env.example"))).rejects.toThrow();
	});
});

describe("sanitize · auto-placeholders", () => {
	it("SAN-001 --auto-placeholders aplica los sugeridos pero igual pide confirmar", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "abortar" }));
		const res = await sanitize(opts({ decisor: d, autoPlaceholders: true }));
		expect(d.confirmar).toHaveBeenCalledTimes(1);
		const resumen = d.confirmar.mock.calls[0]?.[0];
		expect(JSON.stringify(resumen)).not.toContain(SECRET);
		expect(d.visto).toHaveLength(0);
		expect(await readFile(join(work, "a.ts"), "utf8")).toBe(
			`x="${ph("GENERIC_TOKEN")}"\n`,
		);
		expect(res.aprobacion).not.toBeNull();
	});

	it("SAN-001 --auto-placeholders sin confirmación sale con CANCELADO y no cambia nada", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		d.confirmar.mockResolvedValue(false);
		await expect(
			sanitize(opts({ decisor: d, autoPlaceholders: true })),
		).rejects.toMatchObject({ codigo: "CANCELADO" });
		expect(await readFile(join(work, "a.ts"), "utf8")).toBe(text);
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
	});

	it("SAN-001 --auto-placeholders deja los binarios a la decisión de la persona", async () => {
		await put(work, "blob.bin", Buffer.from([0, 1]));
		await writeFindings([binFinding("blob.bin")]);
		const d = decisor(() => ({ accion: "reemplazar" }));
		await sanitize(opts({ decisor: d, autoPlaceholders: true }));
		expect(d.visto).toHaveLength(1);
		await expect(stat(join(work, "blob.bin"))).rejects.toThrow();
	});
});

describe("sanitize · Change del adaptador", () => {
	const adapter = (changes: Change[]) => ({
		sanitize: async () => changes,
	});

	it("SAN-001 aplica los Change dentro de work con offsets exactos del contenido crudo", async () => {
		const text = "ñ😀 uno\r\ndos TRES cuatro\r\n";
		await put(work, "doc.txt", text);
		await writeFindings([]);
		const desde = text.indexOf("TRES");
		await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "abortar" })),
				adapter: adapter([
					{
						tipo: "editar",
						ruta: "doc.txt",
						desde,
						hasta: desde + 4,
						texto: "3",
					},
					{ tipo: "crear", ruta: "nuevo/leeme.txt", contenido: "hola\n" },
					{ tipo: "borrar", ruta: "sobra.txt" },
				]),
			}),
		);
		expect(await readFile(join(work, "doc.txt"), "utf8")).toBe(
			text.replace("TRES", "3"),
		);
		expect(await readFile(join(work, "nuevo/leeme.txt"), "utf8")).toBe(
			"hola\n",
		);
	});

	it.each([
		["con ..", "../fuera.txt"],
		["absoluta", "/etc/passwd"],
		["con barra invertida", "a\\b.txt"],
		["con letra de unidad", "C:/x.txt"],
	])(
		"SAN-001 un Change con ruta %s se rechaza con VALIDACION y no escribe",
		async (_n, ruta) => {
			await put(work, "ok.txt", "igual\n");
			await writeFindings([]);
			await expect(
				sanitize(
					opts({
						decisor: decisor(() => ({ accion: "abortar" })),
						adapter: adapter([
							{ tipo: "crear", ruta: "primero.txt", contenido: "x" },
							{ tipo: "crear", ruta, contenido: "x" },
						]),
					}),
				),
			).rejects.toMatchObject({ codigo: "VALIDACION" });
			await expect(stat(join(work, "primero.txt"))).rejects.toThrow();
			await expect(stat(join(base, "fuera.txt"))).rejects.toThrow();
		},
	);

	it("SAN-001 un editar fuera de rango o solapado se rechaza", async () => {
		await put(work, "d.txt", "abcdef");
		await writeFindings([]);
		const run = (changes: Change[]) =>
			sanitize(
				opts({
					decisor: decisor(() => ({ accion: "abortar" })),
					adapter: adapter(changes),
				}),
			);
		await expect(
			run([{ tipo: "editar", ruta: "d.txt", desde: 2, hasta: 99, texto: "" }]),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
		await expect(
			run([
				{ tipo: "editar", ruta: "d.txt", desde: 0, hasta: 3, texto: "x" },
				{ tipo: "editar", ruta: "d.txt", desde: 2, hasta: 4, texto: "y" },
			]),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
		expect(await readFile(join(work, "d.txt"), "utf8")).toBe("abcdef");
	});
});

describe("sanitize · estado y puerta", () => {
	it("SAN-003 cambia el árbol: el estado se actualiza con la cascada y sanitize queda ok", async () => {
		const text = `x="${SECRET}"\n`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		const res = await sanitize(
			opts({ decisor: decisor(() => ({ accion: "reemplazar" })) }),
		);
		const st = await readState(raiz);
		expect(st.workSha256).toBe(res.aprobacion?.arbolSha256);
		expect(st.etapas.sanitize.estado).toBe("ok");
		expect(st.etapas.licenses.estado).toBe("pendiente");
		await expect(stat(join(raiz, "report.html"))).resolves.toBeTruthy();
		await expect(stat(join(raiz, "lock"))).rejects.toThrow();
	});

	it("SAN-010 sin abiertos al terminar, la puerta de scan bloqueada pasa a ok", async () => {
		const text = `x="${SECRET}"
`;
		await put(work, "a.ts", text);
		await writeFindings([mkFinding("a.ts", text, SECRET)]);
		await updateState(raiz, (s) => ({
			...s,
			etapas: {
				...s.etapas,
				scan: { estado: "bloqueada", ts: s.etapas.scan.ts },
			},
		}));
		await sanitize(
			opts({ decisor: decisor(() => ({ accion: "reemplazar" })) }),
		);
		const st = await readState(raiz);
		expect(st.etapas.sanitize.estado).toBe("ok");
		expect(st.etapas.scan.estado).toBe("ok");
	});

	it("SAN-003 si el re-scan sigue trayendo abiertos tras 3 rondas sale con PUERTA_BLOQUEADA", async () => {
		await put(work, "a.txt", "hola\n");
		await writeFindings([binFinding("a.txt")]);
		let n = 0;
		const rescan: SanitizeOptions["rescan"] = async () => ({
			hallazgos: [binFinding(`nuevo-${n++}.bin`)],
			gitleaksVersion: "8.30.1",
		});
		const d = decisor(() => ({ accion: "falso-positivo", motivo: FP }));
		const err = await sanitize(opts({ decisor: d, rescan })).catch((e) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle).toMatchObject({ abiertos: 1 });
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
		expect((await readState(raiz)).etapas.sanitize.estado).toBe("bloqueada");
	});

	it("SAN-003 un abierto que desaparece del árbol por un Change pasa a resuelto", async () => {
		const f: Finding = {
			...binFinding("x"),
			tipo: "estructura",
			regla: "n8n-pindata",
			archivo: "wf.json",
			linea: 3,
		};
		await put(work, "wf.json", '{"pinData":1}\n');
		await writeFindings([f]);
		const res = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "abortar" })),
				rescan: async () => ({ hallazgos: [], gitleaksVersion: "8.30.1" }),
				adapter: {
					sanitize: async () => [
						{
							tipo: "editar",
							ruta: "wf.json",
							desde: 0,
							hasta: 14,
							texto: "{}\n",
						},
					],
				},
			}),
		);
		expect(res.abiertos).toBe(0);
		expect((await readFindings())[0]?.estado).toBe("resuelto");
		expect(sha(await readFile(join(work, "wf.json")))).toBe(sha("{}\n"));
	});
});

describe("sanitize · con los detectores reales del escáner", () => {
	/** Same drafts as scan(): secrets and PII, ids by the shared formula. */
	function motorReal(): SanitizeOptions["rescan"] {
		return async () => {
			const hallazgos: Finding[] = [];
			for (const rel of await files(work)) {
				const text = (await readFile(join(work, rel))).toString("utf8");
				for (const m of detectSecrets(text)) {
					hallazgos.push({
						...mkFinding(rel, "x", "x"),
						id: findingId({
							motor: "mct",
							regla: m.rule,
							archivo: rel,
							linea: m.line,
							value: m.value,
						}),
						regla: m.rule,
						linea: m.line,
						columna: m.column,
						fragmento: "ghp_****",
					});
				}
				for (const m of detectPii(text)) {
					hallazgos.push({
						...mkFinding(rel, "x", "x"),
						id: findingId({
							motor: "mct",
							regla: m.regla,
							archivo: rel,
							linea: m.linea,
							value: text.slice(m.inicio, m.fin),
						}),
						regla: m.regla,
						tipo: "pii",
						linea: m.linea,
						columna: m.columna,
						fragmento: m.fragmento,
					});
				}
			}
			return { hallazgos, gitleaksVersion: "8.30.1" };
		};
	}

	it("SAN-001 ubica con CRLF y multibyte los hallazgos reales de secretos y PII y no corrompe el resto", async () => {
		const token = makeSecrets().find((x) => x.kind === "github-token");
		const correo = ["ana.pruebas", "@", "ejemplo", ".com"].join("");
		const text = `// ñandú 😀 línea\r\nconst t = "${token?.value}"; // 日本語\r\ncontacto: ${correo}\r\nfin\r\n`;
		await put(work, "src/app.ts", text);
		await writeFindings([]);
		const res = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan: motorReal(),
			}),
		);
		const out = await readFile(join(work, "src/app.ts"), "utf8");
		expect(out).not.toContain(token?.value ?? "?");
		expect(out).not.toContain(correo);
		expect(out).toContain("// ñandú 😀 línea\r\n");
		expect(out).toContain('"; // 日本語\r\ncontacto: ');
		expect(out.endsWith("\r\nfin\r\n")).toBe(true);
		expect(res.abiertos).toBe(0);
		expect(res.aprobacion).not.toBeNull();
	});
});

describe("sanitize · casos límite", () => {
	it("SAN-001 un archivo que no es UTF-8 válido no se edita (puedeReemplazar false)", async () => {
		const bytes = Buffer.concat([
			Buffer.from(`k="${SECRET}"\n`),
			Buffer.from([0xff, 0xfe, 0x41, 0x0a]),
		]);
		await put(work, "raro.txt", bytes);
		const f = mkFinding("raro.txt", `k="${SECRET}"\n`, SECRET);
		await writeFindings([f]);
		const d = decisor(() => ({ accion: "falso-positivo", motivo: FP }));
		await sanitize(opts({ decisor: d, rescan: fixedRescan([f]) }));
		expect(d.ctxs[0]).toMatchObject({ puedeReemplazar: false });
		expect((await readFile(join(work, "raro.txt"))).equals(bytes)).toBe(true);
	});

	it("SAN-001 respeta CRLF al agregar a un .env.example existente sin salto final", async () => {
		const t = `k="${SECRET}"\r\n`;
		await put(work, "a.ts", t);
		await put(work, ".env.example", "FOO=\r\nBAR=");
		await writeFindings([mkFinding("a.ts", t, SECRET)]);
		await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar", nombre: "NUEVA" })),
			}),
		);
		expect(await readFile(join(work, ".env.example"), "utf8")).toBe(
			"FOO=\r\nBAR=\r\nNUEVA=\r\n",
		);
	});

	it("SAN-001 un findings.json ausente o corrupto sale con WORKSPACE_INVALIDO", async () => {
		const d = decisor(() => ({ accion: "abortar" }));
		await expect(sanitize(opts({ decisor: d }))).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
		});
		await writeFile(join(raiz, "findings.json"), "{ no json");
		await expect(sanitize(opts({ decisor: d }))).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
		});
		await stat(join(raiz, "lock")).then(
			() => expect.unreachable("lock should be released"),
			() => undefined,
		);
	});

	it("SAN-001 un hallazgo con fragmento sin enmascarar en findings.json se rechaza", async () => {
		const f = { ...binFinding("a.bin"), fragmento: "demasiado-largo" };
		await writeFindings([f]);
		await expect(
			sanitize(opts({ decisor: decisor(() => ({ accion: "abortar" })) })),
		).rejects.toMatchObject({ codigo: "WORKSPACE_INVALIDO" });
	});
});

describe("sanitize · revisión T19 (doble motor, aislados)", () => {
	const V = ["Zm9v", "YmFy", "Y2x2", "a2V5", "dmFs", "dWUx", "MjM0", "NTY3"]
		.concat(["ODkw", "QUJD", "REVG", "R0hJ", "SktM"])
		.join("")
		.concat("==");

	it("SAN-001 un hallazgo gitleaks con Match completo y uno mct sobre el token reemplazan solo el valor, también con autoPlaceholders", async () => {
		const match = `API_KEY="${SECRET}"`;
		const text = `${match}\nfin\n`;
		await put(work, "cfg.env.ts", text);
		const g: Finding = {
			...mkFinding("cfg.env.ts", text, match, "work", "generic-api-key"),
			motor: "gitleaks",
			id: findingId({
				motor: "gitleaks",
				regla: "generic-api-key",
				archivo: "cfg.env.ts",
				linea: 1,
				value: match,
			}),
		};
		const m = mkFinding("cfg.env.ts", text, SECRET, "work", "generic-api-key");
		await writeFindings([g, m]);
		const rescan: SanitizeOptions["rescan"] = async () => {
			const t = await readFile(join(work, "cfg.env.ts"), "utf8");
			return {
				hallazgos: t.includes(SECRET) ? [g, m].map((f) => ({ ...f })) : [],
				gitleaksVersion: "8.30.1",
			};
		};
		const res = await sanitize(
			opts({
				autoPlaceholders: true,
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan,
			}),
		);
		const out = await readFile(join(work, "cfg.env.ts"), "utf8");
		expect(out).toBe(`API_KEY="${ph("GENERIC_API_KEY")}"\nfin\n`);
		expect(res.abiertos).toBe(0);
		expect(res.decididos.resuelto).toBe(2);
	});

	it("SEG-001 una línea de quarantine de solo base64 con relleno no se copia a .env.example", async () => {
		await put(quarantine, ".env.backup", `A=1\n${V}\nfin\n`);
		const q: Finding = {
			...mkFinding(
				".env.backup",
				`A=1\n${V}\n`,
				V,
				"quarantine",
				"github-token",
			),
		};
		await writeFindings([q]);
		await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "abortar" }) as Decision),
				rescan: fixedRescan([q]),
			}),
		);
		const env = await readFile(join(work, ".env.example"), "utf8").catch(
			() => "",
		);
		expect(env).not.toContain(V);
		expect(env).not.toContain(V.slice(0, 8));
	});
});

describe("sanitize · arreglos de revisión T19 (valor, claves y solapes)", () => {
	const gl = (
		archivo: string,
		text: string,
		match: string,
		regla: string,
	): Finding => ({
		...mkFinding(archivo, text, match, "work", regla),
		motor: "gitleaks",
		id: findingId({
			motor: "gitleaks",
			regla,
			archivo,
			linea: text.slice(0, text.indexOf(match)).split("\n").length,
			value: match,
		}),
	});
	const run = async (
		archivo: string,
		hallazgos: Finding[],
		marcador: string,
	) => {
		await writeFindings(hallazgos);
		await sanitize(
			opts({
				autoPlaceholders: true,
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan: async () => {
					const t = await readFile(join(work, archivo), "utf8");
					return {
						hallazgos: t.includes(marcador)
							? hallazgos.map((f) => ({ ...f }))
							: [],
						gitleaksVersion: "8.30.1",
					};
				},
			}),
		);
		return readFile(join(work, archivo), "utf8");
	};

	it("SAN-001 gitleaks con clave más larga que el valor reemplaza el valor, no el nombre", async () => {
		const valor = ["qX7p", "Lm2n", "Rt9v"].join("");
		const match = `billing_service_internal_api_key_value = "${valor}"`;
		const text = `const ${match};\n`;
		await put(work, "a.ts", text);
		const out = await run(
			"a.ts",
			[gl("a.ts", text, match, "generic-api-key")],
			valor,
		);
		expect(out).not.toContain(valor);
		expect(out).toContain("billing_service_internal_api_key_value");
	});

	it("SAN-001 gitleaks separa clave y valor con cada operador, incluso con '=' o ':' dentro del valor", {
		timeout: 60000,
	}, async () => {
		const pref = ["Qw3E", "rTy6", "Ui9O", "pAs1"].join("");
		const sec = ["Zm9v", "YmFy", "Y2x2", "a2V5"].join("");
		const ops = [",", " > ", " || ", " := ", " ?= ", " => ", ": ", "=", " <= "];
		for (const op of ops) {
			for (const valor of [`${pref}=${sec}`, `${pref}:${sec}==`]) {
				const match = `api_token${op}${valor}`;
				const text = `${match}
fin
`;
				await put(work, "o.ts", text);
				const out = await run(
					"o.ts",
					[gl("o.ts", text, match, "generic-api-key")],
					sec,
				);
				expect(out).not.toContain(pref);
				expect(out).not.toContain(sec);
				expect(out).toContain("api_token");
				expect(out).toMatch(/\$\{GENERIC_API_KEY\w*\}/);
			}
		}
	});

	it("SAN-001 gitleaks con clave y valor entre comillas separados por coma reemplaza el valor entero", async () => {
		const pref = ["Qw3E", "rTy6", "Ui9O", "pAs1"].join("");
		const sec = ["Zm9v", "YmFy", "Y2x2", "a2V5"].join("");
		const match = `"api_token", "${pref}=${sec}"`;
		const text = `${match}
`;
		await put(work, "q.ts", text);
		const out = await run(
			"q.ts",
			[gl("q.ts", text, match, "generic-api-key")],
			sec,
		);
		expect(out).not.toContain(pref);
		expect(out).not.toContain(sec);
	});

	it("SAN-001 un Match cuya parte izquierda parece cuerpo de token se reemplaza completo, con el rescan como respaldo", async () => {
		const nombre = ["Qw3E", "rTy6", "Ui9O", "pAs1", "_key"].join("");
		const sec = ["Zm9v", "YmFy", "Y2x2", "a2V5"].join("");
		const match = `${nombre}=${sec}`;
		const text = `${match}
`;
		await put(work, "n.ts", text);
		const out = await run(
			"n.ts",
			[gl("n.ts", text, match, "heroku-api-key")],
			nombre,
		);
		expect(out).not.toContain(nombre);
		expect(out).not.toContain(sec);
	});

	it("SAN-001 un nombre con forma de token partido por separadores se reemplaza completo", async () => {
		const nombre = ["Qw3E", "rTy6", "Ui9O", "pAs1"].join("_") + "_key";
		const sec = ["Zm9v", "YmFy", "Y2x2", "a2V5"].join("");
		const match = `${nombre}=${sec}`;
		const text = `${match}
`;
		await put(work, "m.ts", text);
		const out = await run(
			"m.ts",
			[gl("m.ts", text, match, "heroku-api-key")],
			nombre,
		);
		expect(out).not.toContain("Qw3E");
		expect(out).not.toContain(sec);
	});

	it("SAN-001 un Match sin nombre de clave a la izquierda se reemplaza completo", async () => {
		const id = ["1234", "56789"].join("");
		const sec = ["AAHd", "kQw3", "ErTy", "6UiO"].join("");
		const match = `${id}:${sec}`;
		const text = `${match}
`;
		await put(work, "t.ts", text);
		const out = await run(
			"t.ts",
			[gl("t.ts", text, match, "telegram-bot-api-token")],
			sec,
		);
		expect(out).not.toContain(id);
		expect(out).not.toContain(sec);
	});

	it("SAN-001 el mismo token dos veces en una línea se reemplaza en ambos sitios y la corrida firma", async () => {
		const tok = ["Zm9v", "YmFy", "Y2x2", "a2V5", "dmFs"].join("");
		const text = `curl -H "k: ${tok}" "https://x?t=${tok}"\nfin\n`;
		await put(work, "c.sh", text);
		await writeFindings([mkFinding("c.sh", text, tok)]);
		const res = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan: fakeRescan([tok]),
			}),
		);
		const out = await readFile(join(work, "c.sh"), "utf8");
		expect(out).not.toContain(tok);
		expect(out.split(ph("GENERIC_TOKEN")).length - 1).toBe(2);
		expect(res.abiertos).toBe(0);
		expect(res.aprobacion?.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
	});

	it("SAN-001 tres spans A, B y C donde C toca a A y B se unen en una sola edición", async () => {
		const a = ["Zm9v", "YmFy", "Y2x2"].join("");
		const b = ["a2V5", "dmFs", "dWUx"].join("");
		const text = `${a},${b}\nfin\n`;
		await put(work, "u.ts", text);
		const fa = mkFinding("u.ts", text, a, "work", "generic-token");
		const fb = mkFinding("u.ts", text, b, "work", "other-token");
		const fc = gl("u.ts", text, `${a},${b}`, "provider-token");
		// Order A, B, C: C arrives after two disjoint spans.
		const out = await run("u.ts", [fa, fb, fc], a);
		expect(out).not.toContain(a);
		expect(out).not.toContain(b);
		expect(out.endsWith("\nfin\n")).toBe(true);
	});

	it("SEG-001 un token sin clave con '=' interno o relleno se reemplaza completo (hashicorp, sentry, jwt)", async () => {
		const casos: Array<[string, string, string]> = [
			[
				"hashicorp-tf-api-token",
				[
					"Qw3Erty6Ui9Opa",
					".atlasv1.",
					"Zx8Cv7Bn6Mm5Ll4Kk3Jj2Hh1Gg0Ff",
					"=",
					"d9S8a7",
				].join(""),
				"Qw3Erty6Ui9Opa",
			],
			[
				"sentry-org-token",
				["sntrys_", "eyJpYXQiOjE2", "=_", "Zm9vYmFyYmF6cXV4"].join(""),
				"eyJpYXQiOjE2",
			],
			[
				"jwt-base64",
				["ZXlKaGJHY2lP", "aUpJVXpJMU5p", "SjkuZXlKemRX", "SWlPaUl4Ig"].join(
					"",
				) + "==",
				"ZXlKaGJHY2lP",
			],
		];
		for (const [regla, token, marca] of casos) {
			const text = `x ${token}\nfin\n`;
			await put(work, "p.ts", text);
			const out = await run("p.ts", [gl("p.ts", text, token, regla)], marca);
			expect(out).not.toContain(marca);
			expect(out).not.toContain("==");
			expect(out).toMatch(/^x \$\{[A-Z0-9_]+\}\nfin\n$/);
		}
	});

	it("SAN-003 si tras editar el valor sigue en el archivo no se marca resuelto y falla cerrado", async () => {
		const sec = ["Zm9v", "YmFy", "Y2x2", "a2V5"].join("");
		const match = `api_token = "${sec}"`;
		const text = `${match}
other = ${sec}
`;
		await put(work, "r.ts", text);
		const f = gl("r.ts", text, match, "generic-api-key");
		await writeFindings([f]);
		await expect(
			sanitize(
				opts({
					autoPlaceholders: true,
					decisor: decisor(() => ({ accion: "reemplazar" })),
					rescan: async () => ({
						hallazgos: [{ ...f }],
						gitleaksVersion: "8.30.1",
					}),
				}),
			),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
		expect(await readFile(join(work, "r.ts"), "utf8")).toBe(text);
	});

	it("SAN-003 una clave privada se reemplaza entera, cabecera y cuerpo", async () => {
		const b = ["-----", "BEGIN RSA PRIVATE", " KEY-----"].join("");
		const e = ["-----", "END RSA PRIVATE", " KEY-----"].join("");
		const l1 = ["MIIEowIBAAKCAQEA", "x7/Qw3Er5Ty6Ui"].join("");
		const l2 = ["Op0Pa1Sd2Fg3Hj4K", "l5Zx6Cv7Bn8Mq/w"].join("");
		const text = `x\n${b}\n${l1}\n${l2}\n${e}\nfin\n`;
		await put(work, "k.pem.ts", text);
		for (const motor of ["mct", "gitleaks"] as const) {
			await put(work, "k.pem.ts", text);
			const f =
				motor === "mct"
					? mkFinding("k.pem.ts", text, b, "work", "private-key")
					: gl("k.pem.ts", text, `${b}\n${l1}\n${l2}\n${e}`, "private-key");
			const out = await run("k.pem.ts", [f], l1);
			expect(out).not.toContain(l1);
			expect(out).not.toContain(l2);
			expect(out).not.toContain("BEGIN");
			expect(out.endsWith("\nfin\n")).toBe(true);
		}
	});

	it("SAN-001 un término de diccionario dentro de un token no deja cola del token", async () => {
		const tok = ["ghp_", "a1B2c3D4e5", "XXXX", "F6g7H8i9J0k1L2m3N4o5"].join("");
		const text = `v=${tok}\n`;
		await put(work, "d.ts", text);
		const outer = mkFinding("d.ts", text, tok, "work", "github-token");
		const inner = mkFinding("d.ts", text, "XXXX", "work", "dict-match");
		const out = await run("d.ts", [outer, inner], "XXXX");
		expect(out).not.toContain("F6g7H8i9");
		expect(out).not.toContain("a1B2c3D4");
	});
});
