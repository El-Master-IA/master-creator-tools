import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps, type Prompter } from "../src/commands/flow.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

// Fixture values are assembled from fragments: no literal secret lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

let base: string;
let origen: string;
let dest: string;
let restore: () => void;
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

function makeIo(tty: boolean, lang = "es_CO.UTF-8") {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: lang },
		stdinIsTTY: tty,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

beforeEach(async () => {
	asked = 0;
	base = await mkdtemp(join(tmpdir(), "mct-cli-notty-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	const home = join(base, "home");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(home, { recursive: true });
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(
		join(origen, "src", "index.js"),
		`const token = "${TOKEN}";\n`,
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
});

afterEach(async () => {
	restore();
	await rm(base, { recursive: true, force: true });
});

describe("SAN-004 sin terminal", () => {
	it("SAN-004 CUANDO no hay TTY EL SISTEMA DEBE negarse a aprobar con PUERTA_BLOQUEADA", async () => {
		const ws = join(dest, ".mct");
		expect(
			await runCli(["init", origen, "--dest", dest], makeIo(false).io),
		).toBe(0);
		expect(await runCli(["scan", "--workspace", ws], makeIo(false).io)).toBe(
			10,
		);
		const { io, out, err } = makeIo(false);
		const code = await runCli(["--json", "sanitize", "--workspace", ws], io);
		expect(code).toBe(10);
		const body = JSON.parse(out.join("")) as { error: { codigo: string } };
		expect(body.error.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.join("")).toContain("terminal");
		expect(asked).toBe(0);
		await expect(access(join(ws, "approval.json"))).rejects.toThrow();
	});

	it("SAN-004 CUANDO no hay TTY EL SISTEMA DEBE explicarlo tambien en ingles", async () => {
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo(false).io);
		await runCli(["scan", "--workspace", ws], makeIo(false).io);
		const { io, err } = makeIo(false, "en_US.UTF-8");
		const code = await runCli(["sanitize", "--workspace", ws], io);
		expect(code).toBe(10);
		expect(err.join("")).toContain("interactive terminal");
	});

	it("SAN-004 CUANDO no hay TTY y quedan abiertos EL SISTEMA DEBE dar abiertos (numero) y hallazgosAbiertos y explicar las vias no interactivas", async () => {
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo(false).io);
		await runCli(["scan", "--workspace", ws], makeIo(false).io);
		const { io, out, err } = makeIo(false);
		expect(await runCli(["--json", "sanitize", "--workspace", ws], io)).toBe(
			10,
		);
		const body = JSON.parse(out.join("")) as {
			error: {
				detalle: { abiertos: number; hallazgosAbiertos: { archivo: string }[] };
			};
		};
		expect(typeof body.error.detalle.abiertos).toBe("number");
		expect(body.error.detalle.hallazgosAbiertos).toHaveLength(
			body.error.detalle.abiertos,
		);
		expect(err.join("")).toContain("--decisiones");
		expect(err.join("")).toContain("--auto-fixtures");
		expect(asked).toBe(0);
		await expect(access(join(ws, "approval.json"))).rejects.toThrow();
	});

	it("SAN-004 CUANDO no hay TTY y no hay hallazgos EL SISTEMA DEBE firmar la aprobacion sin preguntar", async () => {
		await writeFile(join(origen, "src", "index.js"), "module.exports = 1;\n");
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo(false).io);
		expect(await runCli(["scan", "--workspace", ws], makeIo(false).io)).toBe(0);
		expect(
			await runCli(["sanitize", "--workspace", ws], makeIo(false).io),
		).toBe(0);
		await access(join(ws, "approval.json"));
		expect(asked).toBe(0);
	});

	it("CLI-008 CUANDO init --force corre sin TTY EL SISTEMA DEBE salir con CANCELADO sin tocar el workspace", async () => {
		const ws = join(dest, ".mct");
		expect(
			await runCli(["init", origen, "--dest", dest], makeIo(false).io),
		).toBe(0);
		const code = await runCli(
			["init", origen, "--dest", dest, "--force"],
			makeIo(false).io,
		);
		expect(code).toBe(20);
		await access(join(ws, "state.json"));
		expect(asked).toBe(0);
	});

	it("CLI-008 CUANDO init --force tiene TTY EL SISTEMA DEBE confirmar antes de recrear", async () => {
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo(false).io);
		const code = await runCli(
			["init", origen, "--dest", dest, "--force"],
			makeIo(true).io,
		);
		expect(code).toBe(0);
		expect(asked).toBe(1);
		await access(join(ws, "state.json"));
	});
});
