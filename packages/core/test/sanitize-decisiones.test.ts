import { createHash } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@mct/contract/types";
import { findingId, leerClave } from "@mct/scanner/finding-id";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type Decisor,
	type SanitizeOptions,
	sanitize,
} from "../src/sanitize.js";
import { createWorkspace } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
// Fixtures are assembled from fragments (T05): no literal secret or PII lives here.
const SECRET = ["tok", "en-", "a1b2c3d4e5f6a7b8c9d0"].join("");
const SECRET_SHORT = ["pw", "-", "m4n5b6v7"].join("");
const EMAIL = ["ana.gomez", "@", "clientes", ".co"].join("");
const QUAR = ["quar", "-value-", "55aa66bb77"].join("");
const TERM = ["Cliente", " Reservado", " SA"].join("");
const PH = ["$", "{API_TOKEN}"].join("");
const FP = "Es un dato de ejemplo del manual";

let base: string;
let dest: string;
let raiz: string;
let work: string;
let quarantine: string;
let CLAVE: Uint8Array;

interface Sembrado {
	valor: string;
	regla: string;
	tipo: Finding["tipo"];
	severidad: Finding["severidad"];
}

const SEMBRADOS: Sembrado[] = [
	{
		valor: SECRET,
		regla: "generic-token",
		tipo: "secreto",
		severidad: "critico",
	},
	{
		valor: SECRET_SHORT,
		regla: "generic-token",
		tipo: "secreto",
		severidad: "critico",
	},
	{ valor: EMAIL, regla: "pii-email", tipo: "pii", severidad: "alto" },
	{
		valor: QUAR,
		regla: "generic-token",
		tipo: "secreto",
		severidad: "critico",
	},
];

async function put(root: string, rel: string, content: string | Buffer) {
	const full = join(root, ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, content);
}

function lineCol(text: string, index: number): [number, number] {
	const before = text.slice(0, index);
	return [
		before.split("\n").length,
		index - (before.lastIndexOf("\n") + 1) + 1,
	];
}

async function files(dir: string, rel = ""): Promise<string[]> {
	const { readdir } = await import("node:fs/promises");
	const out: string[] = [];
	for (const e of await readdir(join(dir, rel), { withFileTypes: true })) {
		const r = rel === "" ? e.name : `${rel}/${e.name}`;
		if (e.isDirectory()) out.push(...(await files(dir, r)));
		else out.push(r);
	}
	return out;
}

function rescan(): SanitizeOptions["rescan"] {
	return async () => {
		const hallazgos: Finding[] = [];
		for (const [dir, zona] of [
			[work, "work"],
			[quarantine, "quarantine"],
		] as const) {
			for (const rel of await files(dir)) {
				const buf = await readFile(join(dir, rel));
				if (buf.includes(0)) {
					if (zona === "work") hallazgos.push(binario(rel));
					continue;
				}
				const text = buf.toString("utf8");
				for (const s of SEMBRADOS) {
					let at = text.indexOf(s.valor);
					while (at >= 0) {
						const [linea, columna] = lineCol(text, at);
						hallazgos.push({
							id: findingId(
								{
									motor: "mct",
									regla: s.regla,
									archivo: rel,
									linea,
									value: s.valor,
								},
								CLAVE,
							),
							motor: "mct",
							regla: s.regla,
							tipo: s.tipo,
							zona,
							archivo: rel,
							linea,
							columna,
							fragmento: "****",
							severidad: s.severidad,
							estado: zona === "quarantine" ? "aislado" : "abierto",
						});
						at = text.indexOf(s.valor, at + s.valor.length);
					}
				}
			}
		}
		return { hallazgos, gitleaksVersion: "8.30.1" };
	};
}

function binario(archivo: string): Finding {
	return {
		id: findingId(
			{
				motor: "mct",
				regla: "binary-unknown",
				archivo,
				linea: 0,
				value: "bin",
			},
			CLAVE,
		),
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

/** Scans the tree once and stores findings.json, as the scan stage would. */
async function escanear(): Promise<Finding[]> {
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
	return r.hallazgos;
}

const idDe = (hs: Finding[], valorRegla: string, archivo: string) =>
	(hs.find((h) => h.regla === valorRegla && h.archivo === archivo) as Finding)
		.id;

async function escribirDecisiones(
	decisiones: unknown[],
	extra: Record<string, unknown> = {},
	nombre = "decisiones.json",
): Promise<string> {
	const ruta = join(dest, nombre);
	await writeFile(
		ruta,
		JSON.stringify({ schemaVersion: 1, decisiones, ...extra }),
		{ mode: 0o600 },
	);
	await chmod(ruta, 0o600);
	return ruta;
}

const leerFindings = async (): Promise<Finding[]> =>
	JSON.parse(await readFile(join(raiz, "findings.json"), "utf8")).hallazgos;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-san012-"));
	dest = join(base, "dest");
	raiz = join(dest, ".mct");
	await mkdir(dest, { recursive: true });
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: dest },
		adapter: "node",
		now: () => T0,
	});
	CLAVE = await leerClave(raiz);
	work = join(raiz, "work");
	quarantine = join(raiz, "quarantine");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

async function sembrarBasico(): Promise<Finding[]> {
	await put(work, "src/a.ts", `export const k = "${SECRET}";\n`);
	await put(work, "docs/x.md", `contacto: ${EMAIL}\n`);
	return escanear();
}

describe("sanitize --decisiones · aplicar (SAN-012)", () => {
	it("SAN-012 reemplazar sobre un secreto critico aplica, registra via archivo y guarda decisionesSha256", async () => {
		const hs = await sembrarBasico();
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "generic-token", "src/a.ts"),
				accion: "reemplazar",
				nombre: "API_TOKEN",
			},
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: FP,
			},
		]);
		const res = await sanitize(opts({ decisiones: ruta }));
		expect(res.abiertos).toBe(0);
		expect(res.porVia).toEqual({ tty: 0, archivo: 2, autoFixtures: 0 });
		expect(await readFile(join(work, "src/a.ts"), "utf8")).toBe(
			`export const k = "${PH}";\n`,
		);
		const guardados = await leerFindings();
		const fp = guardados.find((h) => h.regla === "pii-email") as Finding;
		expect(fp).toMatchObject({
			estado: "falso-positivo",
			via: "archivo",
			decidio: "tester",
			motivo: FP,
		});
		expect(guardados.find((h) => h.regla === "generic-token")).toMatchObject({
			estado: "resuelto",
			via: "archivo",
		});
		const aprobacion = JSON.parse(
			await readFile(join(raiz, "approval.json"), "utf8"),
		);
		const sha = createHash("sha256")
			.update(await readFile(ruta))
			.digest("hex");
		expect(aprobacion.decisionesSha256).toEqual([sha]);
		expect(aprobacion.autoFixturesSha256).toEqual([]);
	});

	it("SAN-012 reemplazar sobre un binario elimina el archivo", async () => {
		await put(work, "blob.bin", Buffer.from([0, 1, 2, 3]));
		const hs = await escanear();
		const ruta = await escribirDecisiones([
			{ id: (hs[0] as Finding).id, accion: "reemplazar" },
		]);
		await sanitize(opts({ decisiones: ruta }));
		await expect(stat(join(work, "blob.bin"))).rejects.toThrow();
	});

	it("SAN-012 idempotencia: volver a correr con el mismo archivo no cambia findings.json ni duplica el sha", async () => {
		const hs = await sembrarBasico();
		const ruta = await escribirDecisiones([
			{ id: idDe(hs, "generic-token", "src/a.ts"), accion: "reemplazar" },
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: FP,
			},
		]);
		await sanitize(opts({ decisiones: ruta }));
		const f1 = await readFile(join(raiz, "findings.json"), "utf8");
		const w1 = await readFile(join(work, "src/a.ts"), "utf8");
		const res = await sanitize(opts({ decisiones: ruta }));
		expect(res.abiertos).toBe(0);
		// A replaced finding is gone from the tree, so the re-scan reads it as obsoleto
		// (D-045); every other decision is byte-identical.
		const antes = JSON.parse(f1).hallazgos as Finding[];
		const despues = await leerFindings();
		expect(despues.map((h) => h.id)).toEqual(antes.map((h) => h.id));
		for (const [i, h] of despues.entries()) {
			const previo = antes[i] as Finding;
			if (previo.estado === "resuelto") expect(h.estado).toBe("obsoleto");
			else expect(h).toEqual(previo);
		}
		expect(await readFile(join(work, "src/a.ts"), "utf8")).toBe(w1);
		const aprobacion = JSON.parse(
			await readFile(join(raiz, "approval.json"), "utf8"),
		);
		expect(aprobacion.decisionesSha256).toHaveLength(1);
	});
});

describe("sanitize --decisiones · todo o nada (SAN-012)", () => {
	async function estado() {
		return {
			findings: await readFile(join(raiz, "findings.json"), "utf8"),
			a: await readFile(join(work, "src/a.ts"), "utf8"),
		};
	}

	async function rechazada(ruta: string): Promise<void> {
		const antes = await estado();
		await expect(sanitize(opts({ decisiones: ruta }))).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
		expect(await estado()).toEqual(antes);
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
	}

	it("SAN-012 falso-positivo de un secreto (incluso alto) sale con VALIDACION sin aplicar ninguna", async () => {
		const hs = await sembrarBasico();
		// A valid entry first: it must not be applied either.
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: FP,
			},
			{
				id: idDe(hs, "generic-token", "src/a.ts"),
				accion: "falso-positivo",
				motivo: FP,
			},
		]);
		await rechazada(ruta);
	});

	it("SAN-012 falso-positivo de un critico que no es secreto sale con VALIDACION", async () => {
		await put(work, "docs/x.md", `contacto: ${EMAIL}\n`);
		await put(work, "src/a.ts", "x\n");
		SEMBRADOS.push({
			valor: EMAIL,
			regla: "pii-critica",
			tipo: "pii",
			severidad: "critico",
		});
		try {
			const hs = await escanear();
			const ruta = await escribirDecisiones([
				{
					id: idDe(hs, "pii-critica", "docs/x.md"),
					accion: "falso-positivo",
					motivo: FP,
				},
			]);
			await rechazada(ruta);
		} finally {
			SEMBRADOS.pop();
		}
	});

	it("SAN-012 falso-positivo de un binario (binary-unknown) sale con VALIDACION; findings.json no cambia", async () => {
		await put(work, "src/a.ts", "x\n");
		await writeFile(join(work, "blob.bin"), Buffer.from([0, 1, 2, 3]));
		const hs = await escanear();
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "binary-unknown", "blob.bin"),
				accion: "falso-positivo",
				motivo: FP,
			},
		]);
		await rechazada(ruta);
	});

	it("SAN-012 falso-positivo de estructura n8n-pindata/n8n-staticdata o de severidad alta sale con VALIDACION", async () => {
		await put(work, "docs/x.md", `contacto: ${EMAIL}\n`);
		await put(work, "src/a.ts", "x\n");
		for (const [regla, severidad] of [
			["n8n-pindata", "medio"],
			["n8n-staticdata", "medio"],
			["otra-estructura", "alto"],
		] as const) {
			SEMBRADOS.push({ valor: EMAIL, regla, tipo: "estructura", severidad });
			try {
				const hs = await escanear();
				const ruta = await escribirDecisiones([
					{
						id: idDe(hs, regla, "docs/x.md"),
						accion: "falso-positivo",
						motivo: FP,
					},
				]);
				await rechazada(ruta);
			} finally {
				SEMBRADOS.pop();
			}
		}
	});

	it("SAN-012 aceptar no se admite en el archivo", async () => {
		const hs = await sembrarBasico();
		const ruta = await escribirDecisiones([
			{ id: idDe(hs, "pii-email", "docs/x.md"), accion: "aceptar", motivo: FP },
		]);
		await rechazada(ruta);
	});

	it("SAN-012 un id que no es de ningun hallazgo sale con VALIDACION", async () => {
		await sembrarBasico();
		const ruta = await escribirDecisiones([
			{ id: "a".repeat(64), accion: "reemplazar" },
		]);
		await rechazada(ruta);
	});

	it("SAN-012 un hallazgo aislado no se puede decidir", async () => {
		await sembrarBasico();
		await put(quarantine, ".env", `TOKEN=${QUAR}\n`);
		const hs = await escanear();
		const aislado = hs.find((h) => h.estado === "aislado") as Finding;
		const ruta = await escribirDecisiones([
			{ id: aislado.id, accion: "reemplazar" },
		]);
		await rechazada(ruta);
	});

	it("SAN-012 una entrada que choca con otra decision del mismo id sale con VALIDACION", async () => {
		const hs = await sembrarBasico();
		const id = idDe(hs, "pii-email", "docs/x.md");
		const ruta = await escribirDecisiones([
			{ id, accion: "reemplazar" },
			{ id, accion: "falso-positivo", motivo: FP },
		]);
		await rechazada(ruta);
	});

	it("SAN-012 un hallazgo ya decidido con otra accion sale con VALIDACION", async () => {
		const hs = await sembrarBasico();
		const id = idDe(hs, "pii-email", "docs/x.md");
		await sanitize(
			opts({
				decisiones: await escribirDecisiones([
					{ id, accion: "falso-positivo", motivo: FP },
				]),
			}),
		).catch(() => undefined);
		// Still open secret so the gate is closed and findings.json keeps the decision.
		const ruta = await escribirDecisiones([{ id, accion: "reemplazar" }]);
		await expect(sanitize(opts({ decisiones: ruta }))).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
	});

	it("SAN-012 un motivo con un valor de quarantine/ sale con VALIDACION sin repetirlo", async () => {
		const hs = await sembrarBasico();
		await put(quarantine, ".env", `TOKEN=${QUAR}\n`);
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: `es el mismo que ${QUAR.toUpperCase()} del entorno`,
			},
		]);
		const err = await sanitize(opts({ decisiones: ruta })).catch((e) => e);
		expect(err).toMatchObject({ codigo: "VALIDACION" });
		expect(JSON.stringify(err.detalle ?? {}) + err.message).not.toContain(QUAR);
	});

	it("SAN-012 un motivo con un termino del diccionario (mayusculas) sale con VALIDACION", async () => {
		const hs = await sembrarBasico();
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: `pertenece a ${TERM.toUpperCase()} y es de prueba`,
			},
		]);
		await expect(
			sanitize(opts({ decisiones: ruta, terminos: [TERM] })),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it.each([
		["no es JSON", "{no json"],
		[
			"schemaVersion distinto de 1",
			JSON.stringify({ schemaVersion: 2, decisiones: [] }),
		],
		[
			"clave desconocida arriba",
			JSON.stringify({ schemaVersion: 1, decisiones: [], revisadoPor: "x" }),
		],
		[
			"clave desconocida en una entrada",
			JSON.stringify({
				schemaVersion: 1,
				decisiones: [{ id: "a".repeat(64), accion: "reemplazar", extra: 1 }],
			}),
		],
		[
			"nombre invalido",
			JSON.stringify({
				schemaVersion: 1,
				decisiones: [
					{ id: "a".repeat(64), accion: "reemplazar", nombre: "minuscula" },
				],
			}),
		],
		[
			"motivo corto",
			JSON.stringify({
				schemaVersion: 1,
				decisiones: [
					{ id: "a".repeat(64), accion: "falso-positivo", motivo: "corto" },
				],
			}),
		],
		[
			"decisiones no es lista",
			JSON.stringify({ schemaVersion: 1, decisiones: {} }),
		],
	])(
		"SAN-012 archivo inválido (%s) sale con VALIDACION sin cambios",
		async (_n, contenido) => {
			await sembrarBasico();
			const ruta = join(dest, "decisiones.json");
			await writeFile(ruta, contenido, { mode: 0o600 });
			await chmod(ruta, 0o600);
			await rechazada(ruta);
		},
	);

	it("SAN-012 archivo inexistente, carpeta o de 1 MB o mas salen con VALIDACION", async () => {
		await sembrarBasico();
		await rechazada(join(dest, "no-existe.json"));
		await mkdir(join(dest, "carpeta.json"));
		await rechazada(join(dest, "carpeta.json"));
		const grande = join(dest, "grande.json");
		await writeFile(grande, Buffer.alloc(1_100_000, 32), { mode: 0o600 });
		await chmod(grande, 0o600);
		await rechazada(grande);
	});

	it("SAN-012 un symlink sale con VALIDACION", async () => {
		await sembrarBasico();
		const real = await escribirDecisiones([], {}, "real.json");
		const enlace = join(dest, "enlace.json");
		try {
			await symlink(real, enlace);
		} catch {
			return; // no privilege to create links here
		}
		await rechazada(enlace);
	});
});

describe("sanitize sin TTY (SAN-004)", () => {
	it("SAN-004 queda algo abierto: PUERTA_BLOQUEADA con abiertos y hallazgosAbiertos, conserva lo aplicado y repetir es idempotente", async () => {
		const hs = await sembrarBasico();
		const ruta = await escribirDecisiones([
			{
				id: idDe(hs, "pii-email", "docs/x.md"),
				accion: "falso-positivo",
				motivo: FP,
			},
		]);
		const err = await sanitize(opts({ decisiones: ruta })).catch((e) => e);
		expect(err).toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
		expect(err.detalle.abiertos).toBe(1);
		expect(err.detalle.hallazgosAbiertos).toHaveLength(1);
		expect(err.detalle.hallazgosAbiertos[0]).toMatchObject({
			regla: "generic-token",
			tipo: "secreto",
			archivo: "src/a.ts",
		});
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
		const f1 = await readFile(join(raiz, "findings.json"), "utf8");
		expect(
			(await leerFindings()).find((h) => h.regla === "pii-email"),
		).toMatchObject({
			estado: "falso-positivo",
			via: "archivo",
		});
		await expect(sanitize(opts({ decisiones: ruta }))).rejects.toMatchObject({
			codigo: "PUERTA_BLOQUEADA",
		});
		expect(await readFile(join(raiz, "findings.json"), "utf8")).toBe(f1);
	});

	it("SAN-004 sin hallazgos y sin TTY firma la aprobacion con las listas vacias", async () => {
		await put(work, "src/a.ts", "export {};\n");
		await escanear();
		const res = await sanitize(opts());
		expect(res.aprobacion).not.toBeNull();
		const aprobacion = JSON.parse(
			await readFile(join(raiz, "approval.json"), "utf8"),
		);
		expect(aprobacion.decisionesSha256).toEqual([]);
		expect(aprobacion.autoFixturesSha256).toEqual([]);
	});

	it("SAN-004 el decisor nunca se llama sin TTY", async () => {
		await sembrarBasico();
		await expect(sanitize(opts())).rejects.toMatchObject({
			codigo: "PUERTA_BLOQUEADA",
		});
	});
});
