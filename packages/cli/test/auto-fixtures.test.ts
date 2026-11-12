import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
const CORREO_PRUEBA = ["usuario", "@", "example", ".com"].join("");
const CORREO_REAL = ["ana.gomez", "@", "clientes", ".co"].join("");
const TARJETA = ["4242", "4242", "4242", "4242"].join("");

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

let asked: string[] = [];
let respuesta = true;
const spy: Prompter = {
	select: async () => {
		asked.push("select");
		return null as never;
	},
	text: async () => {
		asked.push("text");
		return null;
	},
	confirm: async (o) => {
		asked.push(o.message);
		return respuesta;
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

async function dryRun() {
	const { io, out } = makeIo();
	const code = await runCli(
		["--json", "sanitize", "--workspace", ws(), "--auto-fixtures", "--dry-run"],
		io,
	);
	return { code, body: JSON.parse(out.join("")) };
}

const findings = async (): Promise<
	{ estado: string; via?: string; archivo: string; tipo: string }[]
> => JSON.parse(await readFile(join(ws(), "findings.json"), "utf8")).hallazgos;

beforeEach(async () => {
	asked = [];
	respuesta = true;
	base = await mkdtemp(join(tmpdir(), "mct-cli-auto-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	const home = join(base, "home");
	await mkdir(join(origen, "tests"), { recursive: true });
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(home, { recursive: true });
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(
		join(origen, "tests", "datos.js"),
		`const a = "${CORREO_PRUEBA}";\nconst t = "${TARJETA}";\nconst real = "${TOKEN}";\n`,
	);
	await writeFile(
		join(origen, "src", "app.js"),
		`const c = "${CORREO_REAL}";\n`,
	);
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
	await runCli(["scan", "--workspace", ws()], makeIo().io);
});

afterEach(async () => {
	restore();
	await rm(base, { recursive: true, force: true });
});

describe("sanitize --auto-fixtures (SAN-014)", () => {
	it("SAN-014 --dry-run --json devuelve candidatos y sha256 y no cambia nada", async () => {
		const antes = await readFile(join(ws(), "findings.json"), "utf8");
		const { code, body } = await dryRun();
		expect(code).toBe(0);
		expect(body.sha256).toMatch(/^[0-9a-f]{64}$/);
		expect(body.candidatos.length).toBeGreaterThanOrEqual(1);
		for (const c of body.candidatos) {
			expect(Object.keys(c).sort()).toEqual([
				"archivo",
				"id",
				"linea",
				"regla",
				"tipo",
			]);
			expect(c.archivo).toBe("tests/datos.js");
		}
		expect(JSON.stringify(body)).not.toContain(CORREO_PRUEBA);
		expect(await readFile(join(ws(), "findings.json"), "utf8")).toBe(antes);
		expect(asked).toEqual([]);
	});

	it("SAN-014 sin TTY y sin --confirmo no aplica nada (exit 2)", async () => {
		const antes = await readFile(join(ws(), "findings.json"), "utf8");
		const { io } = makeIo();
		expect(
			await runCli(["sanitize", "--workspace", ws(), "--auto-fixtures"], io),
		).toBe(2);
		expect(await readFile(join(ws(), "findings.json"), "utf8")).toBe(antes);
		expect(asked).toEqual([]);
	});

	it("SAN-014 con --confirmo aplica solo la lista; el token real y el correo fuera de tests siguen abiertos", async () => {
		const { body } = await dryRun();
		const { io, out } = makeIo();
		const code = await runCli(
			[
				"--json",
				"sanitize",
				"--workspace",
				ws(),
				"--auto-fixtures",
				"--confirmo",
				body.sha256,
			],
			io,
		);
		expect(code).toBe(10);
		const err = JSON.parse(out.join("")).error;
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		const abiertos = err.detalle.hallazgosAbiertos as {
			tipo: string;
			archivo: string;
		}[];
		expect(
			abiertos.some(
				(h) => h.tipo === "secreto" && h.archivo === "tests/datos.js",
			),
		).toBe(true);
		expect(abiertos.some((h) => h.archivo === "src/app.js")).toBe(true);
		expect(
			abiertos.some((h) => h.archivo === "tests/datos.js" && h.tipo === "pii"),
		).toBe(false);
		const marcados = (await findings()).filter(
			(h) => h.via === "auto-fixtures",
		);
		expect(marcados).toHaveLength(body.candidatos.length);
		expect(marcados.every((h) => h.estado === "falso-positivo")).toBe(true);
		expect(asked).toEqual([]);
	});

	it("SAN-014 con un --confirmo que no coincide sale con VALIDACION (exit 2)", async () => {
		const antes = await readFile(join(ws(), "findings.json"), "utf8");
		const { io } = makeIo();
		expect(
			await runCli(
				[
					"sanitize",
					"--workspace",
					ws(),
					"--auto-fixtures",
					"--confirmo",
					"0".repeat(64),
				],
				io,
			),
		).toBe(2);
		expect(await readFile(join(ws(), "findings.json"), "utf8")).toBe(antes);
	});

	it("SAN-014 con TTY muestra la lista y pregunta; un no no aplica nada", async () => {
		respuesta = false;
		const { io } = makeIo(true);
		await runCli(["sanitize", "--workspace", ws(), "--auto-fixtures"], io);
		expect(asked.some((m) => m.includes("tests/datos.js"))).toBe(true);
		expect((await findings()).some((h) => h.via === "auto-fixtures")).toBe(
			false,
		);
	});
});
