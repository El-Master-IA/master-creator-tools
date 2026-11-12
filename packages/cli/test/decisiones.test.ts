import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps, type Prompter } from "../src/commands/flow.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

// Fixture values are assembled from fragments (T05): no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const EMAIL = ["ana.gomez", "@", "clientes", ".co"].join("");
const PH = ["$", "{API_TOKEN}"].join("");
const MOTIVO = "Es un dato de ejemplo del manual de usuario";

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

let asked = 0;
const spy: Prompter = {
	select: async () => {
		asked++;
		return null as never;
	},
	text: async () => {
		asked++;
		return null;
	},
	confirm: async () => {
		asked++;
		return true;
	},
};

let base: string;
let origen: string;
let dest: string;
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

interface Abierto {
	id: string;
	regla: string;
	tipo: string;
	archivo: string;
}

async function abiertos(): Promise<Abierto[]> {
	const { io, out } = makeIo();
	await runCli(["--json", "scan", "--workspace", ws()], io);
	return JSON.parse(out.join("")).error.detalle.hallazgosAbiertos;
}

async function escribir(decisiones: unknown[]): Promise<string> {
	const ruta = join(dest, "decisiones.json");
	await writeFile(ruta, JSON.stringify({ schemaVersion: 1, decisiones }), {
		mode: 0o600,
	});
	await chmod(ruta, 0o600);
	return ruta;
}

const hallazgos = async (): Promise<unknown[]> =>
	JSON.parse(await readFile(join(ws(), "findings.json"), "utf8")).hallazgos;

beforeEach(async () => {
	asked = 0;
	base = await mkdtemp(join(tmpdir(), "mct-cli-dec-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	const home = join(base, "home");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(home, { recursive: true });
	await mkdir(dest, { recursive: true });
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(
		join(origen, "src", "index.js"),
		`const token = "${TOKEN}";\n`,
	);
	await writeFile(join(origen, "src", "notas.txt"), `contacto: ${EMAIL}\n`);
	restore = overrideFlowDeps({
		home,
		prompter: spy,
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

describe("sanitize --decisiones sin TTY (SAN-004, SAN-012)", () => {
	it("SAN-012 el archivo cubre todo: aprueba sin preguntar, via archivo y decisionesSha256", async () => {
		const lista = await abiertos();
		const token = lista.find((h) => h.tipo === "secreto") as Abierto;
		const ruta = await escribir([
			{ id: token.id, accion: "reemplazar", nombre: "API_TOKEN" },
			...lista
				.filter((h) => h.tipo === "pii")
				.map((h) => ({ id: h.id, accion: "falso-positivo", motivo: MOTIVO })),
		]);
		const { io, out } = makeIo();
		const code = await runCli(
			["--json", "sanitize", "--workspace", ws(), "--decisiones", ruta],
			io,
		);
		expect(code).toBe(0);
		const body = JSON.parse(out.join(""));
		expect(body.abiertos).toBe(0);
		expect(body.hallazgosAbiertos).toEqual([]);
		expect(body.porVia.archivo).toBeGreaterThanOrEqual(2);
		expect(body.aprobacion.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
		expect(asked).toBe(0);
		expect(await readFile(join(ws(), "work", "src", "index.js"), "utf8")).toBe(
			`const token = "${PH}";\n`,
		);
		const aprobacion = JSON.parse(
			await readFile(join(ws(), "approval.json"), "utf8"),
		);
		expect(aprobacion.decisionesSha256).toHaveLength(1);
	});

	it("SAN-004 si el archivo no cubre todo: exit 10, decisiones conservadas y segunda corrida igual", async () => {
		const lista = await abiertos();
		const pii = lista.filter((h) => h.tipo === "pii");
		const ruta = await escribir(
			pii.map((h) => ({ id: h.id, accion: "falso-positivo", motivo: MOTIVO })),
		);
		const correr = async () => {
			const { io, out } = makeIo();
			const code = await runCli(
				["--json", "sanitize", "--workspace", ws(), "--decisiones", ruta],
				io,
			);
			return { code, body: JSON.parse(out.join("")) };
		};
		const a = await correr();
		expect(a.code).toBe(10);
		expect(a.body.error.codigo).toBe("PUERTA_BLOQUEADA");
		expect(a.body.error.detalle.abiertos).toBe(1);
		expect(a.body.error.detalle.hallazgosAbiertos).toHaveLength(1);
		await expect(stat(join(ws(), "approval.json"))).rejects.toThrow();
		const tras1 = await hallazgos();
		expect(
			(tras1 as { estado: string; via?: string }[]).filter(
				(h) => h.estado === "falso-positivo" && h.via === "archivo",
			),
		).toHaveLength(pii.length);
		const b = await correr();
		expect(b.code).toBe(10);
		expect(await hallazgos()).toEqual(tras1);
		expect(asked).toBe(0);
	});

	it("SAN-012 un falso positivo de un secreto por archivo sale con VALIDACION y no cambia nada", async () => {
		const lista = await abiertos();
		const token = lista.find((h) => h.tipo === "secreto") as Abierto;
		const antes = await readFile(join(ws(), "findings.json"), "utf8");
		const ruta = await escribir([
			{ id: token.id, accion: "falso-positivo", motivo: MOTIVO },
		]);
		const { io, out } = makeIo();
		const code = await runCli(
			["--json", "sanitize", "--workspace", ws(), "--decisiones", ruta],
			io,
		);
		expect(code).toBe(2);
		expect(JSON.parse(out.join("")).error.codigo).toBe("VALIDACION");
		expect(await readFile(join(ws(), "findings.json"), "utf8")).toBe(antes);
	});

	it("SAN-015 un decisiones.json dentro del origen o con otro nombre dentro de .mct sale con VALIDACION", async () => {
		await abiertos();
		const ruta = join(ws(), "work", "decisiones.json");
		await writeFile(
			ruta,
			JSON.stringify({ schemaVersion: 1, decisiones: [] }),
			{
				mode: 0o600,
			},
		);
		const { io, out } = makeIo();
		const code = await runCli(
			["--json", "sanitize", "--workspace", ws(), "--decisiones", ruta],
			io,
		);
		expect(code).toBe(2);
		expect(JSON.parse(out.join("")).error.codigo).toBe("VALIDACION");
	});

	it("SAN-012 --confirmo y --dry-run sin --auto-fixtures salen con VALIDACION", async () => {
		await abiertos();
		for (const extra of [["--confirmo", "a".repeat(64)], ["--dry-run"]]) {
			const { io } = makeIo();
			expect(
				await runCli(["sanitize", "--workspace", ws(), ...extra], io),
			).toBe(2);
		}
	});
});

describe("--type ampliado y flags de run (DET-001, RUN-001)", () => {
	it("DET-001 init rechaza un --type desconocido y acepta los cinco adaptadores", async () => {
		const { io } = makeIo();
		expect(
			await runCli(
				["init", origen, "--dest", join(base, "x"), "--type", "ruby"],
				io,
			),
		).toBe(2);
		const g = makeIo();
		expect(
			await runCli(
				["init", origen, "--dest", join(base, "g"), "--type", "generico"],
				g.io,
			),
		).toBe(0);
	});

	it("RUN-001 run --auto-fixtures sin --confirmo y --confirmo sin --auto-fixtures salen con VALIDACION", async () => {
		for (const extra of [["--auto-fixtures"], ["--confirmo", "a".repeat(64)]]) {
			const { io } = makeIo();
			expect(
				await runCli(["run", origen, "--dest", join(base, "r"), ...extra], io),
			).toBe(2);
		}
	});

	it("RUN-001 run acepta --decisiones y --type python en la ayuda", async () => {
		const { io, out } = makeIo();
		await runCli(["run", "--help"], io);
		const texto = out.join("");
		expect(texto).toContain("--decisiones");
		expect(texto).toContain("--auto-fixtures");
		expect(texto).toContain("--confirmo");
		expect(texto).toContain("python");
	});
});
