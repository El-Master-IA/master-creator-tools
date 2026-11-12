import { createHash } from "node:crypto";
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@mct/contract/types";
import { findingId, leerClave } from "@mct/scanner/finding-id";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	esCandidato,
	esRutaDeTest,
	esValorDePrueba,
	huellaLista,
	MOTIVO_AUTO,
} from "../src/auto-fixtures.js";
import {
	autoFixturesLista,
	type Decisor,
	type SanitizeOptions,
	sanitize,
} from "../src/sanitize.js";
import { createWorkspace } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
// Every value is assembled from fragments (T05): no literal secret or PII lives here.
const CORREO_PRUEBA = ["usuario", "@", "example", ".com"].join("");
const CORREO_REAL = ["ana.gomez", "@", "clientes", ".co"].join("");
const TARJETA = ["4242", "4242", "4242", "4242"].join("");
const TOKEN_RELLENO = ["gh", "p_", "x".repeat(36)].join("");
const TOKEN_REAL = [
	"gh",
	"p_",
	"A1b2C3d4E5f6G7h8I9j0",
	"K1l2M3n4O5p6Q7r8S9t0",
].join("");
const TOKEN_TEST_EN_MEDIO = [
	"gh",
	"p_",
	"A1b2C3d4",
	"test",
	"E5f6G7h8I9j0K1l2",
].join("");
const URL_CON_CLAVE = [
	"postgres",
	"://",
	"u",
	":",
	"s3cr3t-Pw9xK2",
	"@",
	"localhost",
	"/db",
].join("");
const TERMINO = ["Cliente", "Reservado", "SA"].join("");
const GITLEAKS_RELLENO = ["k", "y".repeat(30)].join("");

let base: string;
let raiz: string;
let work: string;
let CLAVE: Uint8Array;

interface Sembrado {
	valor: string;
	regla: string;
	tipo: Finding["tipo"];
	severidad: Finding["severidad"];
	motor?: Finding["motor"];
}

const SEMBRADOS: Sembrado[] = [
	{ valor: CORREO_PRUEBA, regla: "pii-email", tipo: "pii", severidad: "alto" },
	{ valor: CORREO_REAL, regla: "pii-email", tipo: "pii", severidad: "alto" },
	{ valor: TARJETA, regla: "pii-card", tipo: "pii", severidad: "alto" },
	{
		valor: TOKEN_RELLENO,
		regla: "generic-token",
		tipo: "secreto",
		severidad: "critico",
	},
	{
		valor: TOKEN_REAL,
		regla: "github-pat",
		tipo: "secreto",
		severidad: "critico",
	},
	{
		valor: TOKEN_TEST_EN_MEDIO,
		regla: "github-pat",
		tipo: "secreto",
		severidad: "critico",
	},
	{
		valor: URL_CON_CLAVE,
		regla: "node-url-credenciales",
		tipo: "secreto",
		severidad: "critico",
	},
	{ valor: TERMINO, regla: "dict-match", tipo: "pii", severidad: "alto" },
	{
		valor: GITLEAKS_RELLENO,
		regla: "generic-api-key",
		tipo: "secreto",
		severidad: "critico",
		motor: "gitleaks",
	},
];

async function put(rel: string, content: string | Buffer) {
	const full = join(work, ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, content);
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

const idDe = (
	motor: string,
	regla: string,
	archivo: string,
	linea: number,
	valor: string,
) => findingId({ motor, regla, archivo, linea, value: valor }, CLAVE);

function rescan(): SanitizeOptions["rescan"] {
	return async () => {
		const hallazgos: Finding[] = [];
		for (const rel of await files(work)) {
			const buf = await readFile(join(work, rel));
			if (buf.includes(0)) {
				hallazgos.push({
					id: idDe("mct", "binary-unknown", rel, 0, "bin"),
					motor: "mct",
					regla: "binary-unknown",
					tipo: "binario",
					zona: "work",
					archivo: rel,
					linea: 0,
					columna: 0,
					fragmento: "****",
					severidad: "alto",
					estado: "abierto",
				});
				continue;
			}
			const lineas = buf.toString("utf8").split("\n");
			for (const [n, linea] of lineas.entries()) {
				for (const s of SEMBRADOS) {
					const col = linea.indexOf(s.valor);
					if (col < 0) continue;
					const motor = s.motor ?? "mct";
					hallazgos.push({
						id: idDe(motor, s.regla, rel, n + 1, s.valor),
						motor,
						regla: s.regla,
						tipo: s.tipo,
						zona: "work",
						archivo: rel,
						linea: n + 1,
						columna: col + 1,
						fragmento: "****",
						severidad: s.severidad,
						estado: "abierto",
					});
				}
			}
		}
		if (await readFile(join(raiz, "extra.flag"), "utf8").catch(() => "")) {
			hallazgos.push({
				id: idDe("mct", "credenciales-registro", "tests/.npmrc", 1, "x"),
				motor: "mct",
				regla: "credenciales-registro",
				tipo: "estructura",
				zona: "work",
				archivo: "tests/.npmrc",
				linea: 1,
				columna: 1,
				fragmento: "****",
				severidad: "critico",
				estado: "abierto",
			});
		}
		return { hallazgos, gitleaksVersion: "8.30.1" };
	};
}

const nadie: Decisor = {
	decidir: async () => {
		throw new Error("no debe preguntar");
	},
	confirmar: async () => false,
};

function opts(over: Partial<SanitizeOptions> = {}): SanitizeOptions {
	return {
		raiz,
		tty: false,
		mctVersion: "0.0.0",
		now: () => T0,
		usuario: () => "tester",
		decisor: nadie,
		rescan: rescan(),
		...over,
	};
}

async function escanear(): Promise<void> {
	const r = await rescan()({});
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({
			schemaVersion: 2,
			mctVersion: "0.0.0",
			gitleaksVersion: "8.30.1",
			generadoEn: T0,
			hallazgos: r.hallazgos,
		}),
	);
}

const leerFindings = async (): Promise<Finding[]> =>
	JSON.parse(await readFile(join(raiz, "findings.json"), "utf8")).hallazgos;

async function sembrar(): Promise<void> {
	await put(
		"tests/datos.py",
		`a = "${CORREO_PRUEBA}"\nb = "${TARJETA}"\nc = "${TOKEN_RELLENO}"\n`,
	);
	await put(
		"tests/reales.py",
		`r = "${TOKEN_REAL}"\nm = "${TOKEN_TEST_EN_MEDIO}"\nu = "${URL_CON_CLAVE}"\nd = "${TERMINO}"\n`,
	);
	await put("tests/gl.py", `k = "${GITLEAKS_RELLENO}"\n`);
	await put(
		"src/app.py",
		`contacto = "${CORREO_PRUEBA}"\nreal = "${CORREO_REAL}"\n`,
	);
	await put("tests/blob.bin", Buffer.from([0, 1, 2]));
	await writeFile(join(raiz, "extra.flag"), "1");
	await escanear();
}

const IDS_CANDIDATOS = (hs: Finding[]) =>
	hs
		.filter((h) => h.archivo === "tests/datos.py")
		.map((h) => h.id)
		.sort();

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-san014-"));
	raiz = join(base, ".mct");
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: base },
		adapter: "node",
		now: () => T0,
	});
	CLAVE = await leerClave(raiz);
	work = join(raiz, "work");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("patrones cerrados de dato de prueba (SAN-014)", () => {
	it("SAN-014 la lista cerrada de rutas de test", () => {
		for (const ok of [
			"test/a.js",
			"src/tests/a.js",
			"__tests__/a.js",
			"spec/a.rb",
			"x/fixtures/a.json",
			"testdata/a.txt",
			"src/a.test.ts",
			"src/a.spec.js",
			"pkg/test_api.py",
			"pkg/api_test.py",
			"pkg/conftest.py",
		]) {
			expect(esRutaDeTest(ok), ok).toBe(true);
		}
		for (const no of [
			"src/app.py",
			"src/contest/a.py",
			"testing/a.py",
			"latest.py",
			"[ruta:abc]",
			"src/test.py",
		]) {
			expect(esRutaDeTest(no), no).toBe(false);
		}
	});

	it("SAN-014 tarjetas, correos, telefonos y hosts de prueba", () => {
		expect(esValorDePrueba("pii", TARJETA)).toBe(true);
		expect(esValorDePrueba("pii", "1111 1111 1111 1111")).toBe(true);
		expect(esValorDePrueba("pii", "1234567890123456")).toBe(true);
		expect(esValorDePrueba("pii", "4539148803436467")).toBe(false);
		expect(esValorDePrueba("pii", CORREO_PRUEBA)).toBe(true);
		expect(esValorDePrueba("pii", ["a", "@", "mail.test"].join(""))).toBe(true);
		expect(esValorDePrueba("pii", CORREO_REAL)).toBe(false);
		expect(esValorDePrueba("pii", "(212) 555-0123")).toBe(true);
		expect(esValorDePrueba("pii", "3105559876")).toBe(false);
		// SAN-014: only NANP (optional leading 1 + 3 digits + 55501xx); a mobile with country code (57 + 3xx + 55501xx) is not test data.
		const movil = ["57", "300", "55501", "23"].join("");
		expect(esValorDePrueba("pii", movil)).toBe(false);
		expect(esValorDePrueba("pii", ["1", "212", "55501", "23"].join(""))).toBe(
			true,
		);
		expect(esValorDePrueba("pii", "http://localhost:3000/x")).toBe(true);
		expect(esValorDePrueba("pii", "https://api.example.com/v1")).toBe(false);
		expect(esValorDePrueba("pii", "https://example.com/v1")).toBe(true);
		expect(esValorDePrueba("pii", "db.internal.local")).toBe(true);
	});

	it("SAN-014 para secretos el patron cubre el valor completo", () => {
		expect(esValorDePrueba("secreto", TOKEN_RELLENO)).toBe(true);
		expect(
			esValorDePrueba(
				"secreto",
				["sk", "_", "test", "_", "x".repeat(24)].join(""),
			),
		).toBe(true);
		expect(esValorDePrueba("secreto", "A".repeat(32))).toBe(true);
		expect(esValorDePrueba("secreto", TOKEN_REAL)).toBe(false);
		expect(esValorDePrueba("secreto", TOKEN_TEST_EN_MEDIO)).toBe(false);
		expect(
			esValorDePrueba(
				"secreto",
				["gh", "p_", "x".repeat(20), "Q9r8S7t6"].join(""),
			),
		).toBe(false);
	});

	it("SAN-014 un valor con credenciales en userinfo nunca es dato de prueba", () => {
		expect(esValorDePrueba("secreto", URL_CON_CLAVE)).toBe(false);
		expect(
			esValorDePrueba(
				"secreto",
				["redis", "://", "localhost", ":6379"].join(""),
			),
		).toBe(true);
		expect(
			esValorDePrueba(
				"secreto",
				["redis", "://", "u", "@", "localhost"].join(""),
			),
		).toBe(false);
	});

	it("SAN-014 esCandidato excluye diccionario, gitleaks, quarantine, binario y critico no secreto", () => {
		const base: Finding = {
			id: "a".repeat(64),
			motor: "mct",
			regla: "pii-email",
			tipo: "pii",
			zona: "work",
			archivo: "tests/a.py",
			linea: 1,
			columna: 1,
			fragmento: "****",
			severidad: "alto",
			estado: "abierto",
		};
		expect(esCandidato(base, CORREO_PRUEBA)).toBe(true);
		expect(esCandidato({ ...base, regla: "dict-match" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato({ ...base, motor: "gitleaks" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato({ ...base, zona: "quarantine" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato({ ...base, tipo: "binario" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato({ ...base, severidad: "critico" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato({ ...base, archivo: "src/a.py" }, CORREO_PRUEBA)).toBe(
			false,
		);
		expect(esCandidato(base, null)).toBe(false);
	});

	it("SAN-014 el sha256 es el de los id ordenados unidos con salto de linea", () => {
		const ids = ["b".repeat(64), "a".repeat(64)];
		expect(huellaLista(ids)).toBe(
			createHash("sha256")
				.update(`${"a".repeat(64)}\n${"b".repeat(64)}`)
				.digest("hex"),
		);
	});
});

describe("sanitize --auto-fixtures (SAN-014)", () => {
	it("SAN-014 el dry-run lista solo los datos de prueba reales y no cambia nada", async () => {
		await sembrar();
		const antes = await readFile(join(raiz, "findings.json"), "utf8");
		const arbol = await Promise.all(
			(await files(work)).map((f) => readFile(join(work, f))),
		);
		const lista = await autoFixturesLista(opts({ autoFixtures: {} }));
		const hs = await leerFindings();
		expect(lista.candidatos.map((c) => c.id).sort()).toEqual(
			IDS_CANDIDATOS(hs),
		);
		expect(lista.candidatos).toHaveLength(3);
		expect(Object.keys(lista.candidatos[0] as object).sort()).toEqual([
			"archivo",
			"id",
			"linea",
			"regla",
			"tipo",
		]);
		expect(lista.sha256).toBe(huellaLista(lista.candidatos.map((c) => c.id)));
		expect(await readFile(join(raiz, "findings.json"), "utf8")).toBe(antes);
		const despues = await Promise.all(
			(await files(work)).map((f) => readFile(join(work, f))),
		);
		expect(despues).toEqual(arbol);
	});

	it("SAN-014 un token real, uno con test en medio y una URL con clave en tests/ siguen abiertos", async () => {
		await sembrar();
		const lista = await autoFixturesLista(opts({ autoFixtures: {} }));
		const err = await sanitize(
			opts({ autoFixtures: { confirmo: lista.sha256 } }),
		).catch((e) => e);
		expect(err).toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
		const hs = await leerFindings();
		const abiertos = hs.filter((h) => h.estado === "abierto");
		for (const regla of [
			"github-pat",
			"node-url-credenciales",
			"credenciales-registro",
			"binary-unknown",
			"generic-api-key",
			"dict-match",
		]) {
			expect(
				abiertos.some((h) => h.regla === regla),
				regla,
			).toBe(true);
		}
		// the same email outside a test path stays open
		expect(abiertos.some((h) => h.archivo === "src/app.py")).toBe(true);
		expect(abiertos.some((h) => h.archivo === "tests/datos.py")).toBe(false);
	});

	it("SAN-014 con --confirmo correcto marca falso-positivo con el motivo fijo, via auto-fixtures", async () => {
		await sembrar();
		const lista = await autoFixturesLista(opts({ autoFixtures: {} }));
		await sanitize(opts({ autoFixtures: { confirmo: lista.sha256 } })).catch(
			() => undefined,
		);
		const marcados = (await leerFindings()).filter(
			(h) => h.estado === "falso-positivo",
		);
		expect(marcados.map((h) => h.id).sort()).toEqual(
			lista.candidatos.map((c) => c.id).sort(),
		);
		for (const h of marcados) {
			expect(h).toMatchObject({
				motivo: MOTIVO_AUTO,
				via: "auto-fixtures",
				decidio: "tester",
			});
		}
	});

	it("SAN-014 si el sha256 no coincide sale con VALIDACION sin aplicar ninguna", async () => {
		await sembrar();
		const antes = await readFile(join(raiz, "findings.json"), "utf8");
		await expect(
			sanitize(opts({ autoFixtures: { confirmo: "0".repeat(64) } })),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
		expect(await readFile(join(raiz, "findings.json"), "utf8")).toBe(antes);
		await expect(
			sanitize(opts({ autoFixtures: { confirmo: "no-es-sha" } })),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-014 sin TTY y sin --confirmo no aplica nada", async () => {
		await sembrar();
		const antes = await readFile(join(raiz, "findings.json"), "utf8");
		await expect(sanitize(opts({ autoFixtures: {} }))).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(await readFile(join(raiz, "findings.json"), "utf8")).toBe(antes);
	});

	it("SAN-014 con TTY muestra la lista y solo aplica con un si", async () => {
		await sembrar();
		let vista = 0;
		const no = await sanitize(
			opts({
				tty: true,
				decisor: {
					decidir: async () => ({ accion: "abortar" }),
					confirmar: async () => false,
				},
				autoFixtures: {
					confirmar: async (l) => {
						vista = l.candidatos.length;
						return false;
					},
				},
			}),
		).catch((e) => e);
		expect(vista).toBe(3);
		expect(no).toMatchObject({ codigo: "CANCELADO" });
		expect((await leerFindings()).some((h) => h.via === "auto-fixtures")).toBe(
			false,
		);
	});

	it("SAN-014 repetir con la misma lista es idempotente y approval guarda autoFixturesSha256", async () => {
		await put("tests/datos.py", `a = "${CORREO_PRUEBA}"\nb = "${TARJETA}"\n`);
		await escanear();
		const lista = await autoFixturesLista(opts({ autoFixtures: {} }));
		const r1 = await sanitize(
			opts({ autoFixtures: { confirmo: lista.sha256 } }),
		);
		expect(r1.abiertos).toBe(0);
		expect(r1.porVia.autoFixtures).toBe(2);
		const f1 = await readFile(join(raiz, "findings.json"), "utf8");
		const r2 = await sanitize(
			opts({ autoFixtures: { confirmo: lista.sha256 } }),
		);
		expect(r2.abiertos).toBe(0);
		expect(await readFile(join(raiz, "findings.json"), "utf8")).toBe(f1);
		const aprobacion = JSON.parse(
			await readFile(join(raiz, "approval.json"), "utf8"),
		);
		expect(aprobacion.autoFixturesSha256).toEqual([lista.sha256]);
		expect(aprobacion.decisionesSha256).toEqual([]);
	});
});

describe("SAN-014 relleno estricto para secretos", () => {
	// Values assembled from fragments: no literal secret in the repo (T05).
	const pref = ["sk", "_", "live", "_"].join("");
	it("SAN-014 un prefijo de proveedor con relleno de 8+ es dato de prueba", () => {
		expect(esValorDePrueba("secreto", `${pref}${"x".repeat(24)}`)).toBe(true);
		expect(
			esValorDePrueba(
				"secreto",
				`${["AK", "IA"].join("")}${"EXAMPLE".repeat(2)}`,
			),
		).toBe(true);
	});
	it("SAN-014 segmentos arbitrarios, dígitos o relleno corto no son dato de prueba", () => {
		expect(
			esValorDePrueba("secreto", ["my", "_app", "_test_", "1234"].join("")),
		).toBe(false);
		expect(
			esValorDePrueba("secreto", "8".repeat(3) + "1".repeat(3) + "9".repeat(4)),
		).toBe(false);
		expect(esValorDePrueba("secreto", `${pref}xxxx`)).toBe(false);
		expect(
			esValorDePrueba("secreto", ["ab", "c_d", "ef-", "test"].join("")),
		).toBe(false);
	});
});
