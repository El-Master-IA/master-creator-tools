import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@mct/contract/types";
import { hallazgosAbiertos } from "@mct/core/sanitize";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { findingId, leerClave } from "../../scanner/src/finding-id.js";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps, type Prompter } from "../src/commands/flow.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

// Fixture values are assembled from fragments (T05): no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const TOKEN_16 = ["tok", "en-", "a1b2c3d4e5"].join("");
const EMAIL = ["ana.gomez", "@", "clientes", ".co"].join("");
const TERMINO = ["Cliente", " Reservado", " SA"].join("");
const ENV_VALOR = ["env-se", "cret-9f8e", "7d6c5b4a"].join("");

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

const sinPrompts: Prompter = {
	select: async () => null as never,
	text: async () => null,
	confirm: async () => true,
};

let base: string;
let origen: string;
let dest: string;
let home: string;
let restore: () => void;

function makeIo(tty = false) {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: "es_CO.UTF-8" },
		stdinIsTTY: tty,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

const ws = () => join(dest, ".mct");

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-cli-abiertos-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	home = join(base, "home");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(join(home, ".mct"), { recursive: true });
	await writeFile(join(home, ".mct", "sensible.txt"), `${TERMINO}\n`, {
		mode: 0o600,
	});
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(
		join(origen, "src", "index.js"),
		`const token = "${TOKEN}";\n`,
	);
	await writeFile(
		join(origen, "src", "notas.txt"),
		`contacto: ${EMAIL}\n${TERMINO}\n`,
	);
	await writeFile(join(origen, ".env"), `API_TOKEN=${ENV_VALOR}\n`);
	restore = overrideFlowDeps({
		home,
		prompter: sinPrompts,
		gitleaks: {
			binary: process.execPath,
			installDir: join(base, "bin"),
			run: okRunner,
		},
	});
	expect(await runCli(["init", origen, "--dest", dest], makeIo().io)).toBe(0);
});

afterEach(async () => {
	restore();
	await rm(base, { recursive: true, force: true });
});

interface Abierto {
	id: string;
	regla: string;
	tipo: string;
	severidad: string;
	archivo: string;
	linea: number;
	fragmento?: string;
}

function parse<T>(out: string[]): T {
	return JSON.parse(out.join("")) as T;
}

describe("hallazgosAbiertos en --json (SAN-013)", () => {
	it("SAN-013 scan --json con hallazgos sale 10 y trae hallazgosAbiertos en error.detalle", async () => {
		const { io, out } = makeIo();
		expect(await runCli(["--json", "scan", "--workspace", ws()], io)).toBe(10);
		const body = parse<{
			error: {
				codigo: string;
				detalle: { abiertos: number; hallazgosAbiertos: Abierto[] };
			};
		}>(out);
		expect(body.error.codigo).toBe("PUERTA_BLOQUEADA");
		const lista = body.error.detalle.hallazgosAbiertos;
		expect(typeof body.error.detalle.abiertos).toBe("number");
		expect(lista).toHaveLength(body.error.detalle.abiertos);
		for (const h of lista) {
			expect(
				Object.keys(h).every((k) =>
					[
						"id",
						"regla",
						"tipo",
						"severidad",
						"archivo",
						"linea",
						"fragmento",
					].includes(k),
				),
			).toBe(true);
		}
	});

	it("SAN-013 el secreto lleva fragmento enmascarado; PII y diccionario no llevan fragmento ni el valor", async () => {
		const { io, out } = makeIo();
		await runCli(["--json", "scan", "--workspace", ws()], io);
		const texto = out.join("");
		const lista = parse<{
			error: { detalle: { hallazgosAbiertos: Abierto[] } };
		}>(out).error.detalle.hallazgosAbiertos;
		const secreto = lista.find(
			(h) => h.tipo === "secreto" && h.archivo === "src/index.js",
		) as Abierto;
		expect(secreto.fragmento).toBe("ghp_****");
		const pii = lista.filter((h) => h.tipo === "pii");
		expect(pii.length).toBeGreaterThanOrEqual(2);
		for (const h of pii) expect(h).not.toHaveProperty("fragmento");
		expect(lista.some((h) => h.regla === "dict-match")).toBe(true);
		for (const prohibido of [TOKEN, EMAIL, TERMINO, ENV_VALOR]) {
			expect(texto).not.toContain(prohibido);
		}
	});

	it("SAN-013 los hallazgos aislados (quarantine) no salen", async () => {
		const { io, out } = makeIo();
		await runCli(["--json", "scan", "--workspace", ws()], io);
		const lista = parse<{
			error: { detalle: { abiertos: number; hallazgosAbiertos: Abierto[] } };
		}>(out).error.detalle.hallazgosAbiertos;
		expect(lista.some((h) => h.archivo === ".env")).toBe(false);
	});

	it("SAN-013 sanitize --json sin TTY lleva detalle.abiertos (numero) y detalle.hallazgosAbiertos", async () => {
		await runCli(["scan", "--workspace", ws()], makeIo().io);
		const { io, out } = makeIo();
		expect(await runCli(["--json", "sanitize", "--workspace", ws()], io)).toBe(
			10,
		);
		const body = parse<{
			error: {
				codigo: string;
				detalle: { abiertos: number; hallazgosAbiertos: Abierto[] };
			};
		}>(out);
		expect(body.error.codigo).toBe("PUERTA_BLOQUEADA");
		expect(typeof body.error.detalle.abiertos).toBe("number");
		expect(body.error.detalle.hallazgosAbiertos).toHaveLength(
			body.error.detalle.abiertos,
		);
	});
});

describe("fragmento segun el largo del valor (SAN-013)", () => {
	it("SAN-013 un secreto de 16 caracteres sale como **** y uno largo con 4 reales", async () => {
		const raiz = ws();
		const clave = await leerClave(raiz);
		const largo = ["Zq", "8vN3", "mK7pR2", "tY5wX9", "bC4dF6", "hJ1"].join("");
		const texto = `a = "${TOKEN_16}"\nb = "${largo}"\n`;
		await writeFile(join(raiz, "work", "src", "claves.js"), texto);
		const mk = (valor: string, linea: number): Finding => ({
			id: findingId(
				{
					motor: "mct",
					regla: "generic-token",
					archivo: "src/claves.js",
					linea,
					value: valor,
				},
				clave,
			),
			motor: "mct",
			regla: "generic-token",
			tipo: "secreto",
			zona: "work",
			archivo: "src/claves.js",
			linea,
			columna: (texto.split("\n")[linea - 1]?.indexOf(valor) as number) + 1,
			fragmento: "****",
			severidad: "critico",
			estado: "abierto",
		});
		const aislado: Finding = {
			...mk(TOKEN_16, 1),
			archivo: ".env",
			zona: "quarantine",
			estado: "aislado",
			id: "b".repeat(64),
		};
		const lista = await hallazgosAbiertos(raiz, [
			mk(TOKEN_16, 1),
			mk(largo, 2),
			aislado,
		]);
		expect(TOKEN_16).toHaveLength(16);
		expect(largo.length).toBeGreaterThan(16);
		expect(lista).toHaveLength(2);
		expect(lista[0]?.fragmento).toBe("****");
		expect(lista[1]?.fragmento).toBe(`${largo.slice(0, 4)}****`);
	});
});
