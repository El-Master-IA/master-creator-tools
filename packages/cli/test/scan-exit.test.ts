import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readState } from "@mct/core/workspace";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps } from "../src/commands/flow.js";
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

const brokenRunner: Runner = async () => ({
	code: 2,
	signal: null,
	stdout: "",
	timedOut: false,
});

let base: string;
let dest: string;
let restore: () => void;

function makeIo() {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: "es_CO.UTF-8" },
		stdinIsTTY: false,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

async function fixture(name: string, index: string): Promise<string> {
	const dir = join(base, name);
	await mkdir(join(dir, "src"), { recursive: true });
	await writeFile(
		join(dir, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(join(dir, "src", "index.js"), index);
	return dir;
}

function useRunner(run: Runner): void {
	restore();
	restore = overrideFlowDeps({
		home: join(base, "home"),
		gitleaks: {
			binary: process.execPath,
			installDir: join(base, "bin"),
			run,
		},
	});
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-cli-scan-"));
	dest = join(base, "dest");
	await mkdir(join(base, "home"), { recursive: true });
	restore = overrideFlowDeps({});
	useRunner(okRunner);
});

afterEach(async () => {
	restore();
	await rm(base, { recursive: true, force: true });
});

describe("SCAN-010 salida de scan", () => {
	it("SCAN-010 CUANDO scan termina con abiertos EL SISTEMA DEBE salir con 10", async () => {
		const origen = await fixture("o1", `const token = "${TOKEN}";\n`);
		const ws = join(dest, ".mct");
		expect(await runCli(["init", origen, "--dest", dest], makeIo().io)).toBe(0);
		const { io, out } = makeIo();
		const code = await runCli(["--json", "scan", "--workspace", ws], io);
		expect(code).toBe(10);
		const body = JSON.parse(out.join("")) as {
			error: { codigo: string; detalle: { abiertos: number } };
		};
		expect(body.error.codigo).toBe("PUERTA_BLOQUEADA");
		expect(body.error.detalle.abiertos).toBeGreaterThan(0);
		expect(out.join("")).not.toContain(TOKEN);
	});

	it("SCAN-010 CUANDO scan termina con 0 abiertos EL SISTEMA DEBE salir con 0 y sugerir licenses", async () => {
		const origen = await fixture("o2", "module.exports = 1;\n");
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo().io);
		const { io, out, err } = makeIo();
		const code = await runCli(["--json", "scan", "--workspace", ws], io);
		expect(code).toBe(0);
		const body = JSON.parse(out.join("")) as {
			hallazgos: { abiertos: number };
			gitleaksVersion: string;
		};
		expect(body.hallazgos.abiertos).toBe(0);
		expect(body.gitleaksVersion).toBe("8.30.1");
		expect(err.join("")).toContain("mct licenses");
	});

	it("SCAN-010 CUANDO el motor falla EL SISTEMA DEBE fallar cerrado con MOTOR_NO_DISPONIBLE y no con 0 hallazgos", async () => {
		const origen = await fixture("o3", "module.exports = 1;\n");
		const ws = join(dest, ".mct");
		await runCli(["init", origen, "--dest", dest], makeIo().io);
		useRunner(brokenRunner);
		const code = await runCli(["scan", "--workspace", ws], makeIo().io);
		expect(code).toBe(12);
	});

	it("SCAN-010 CUANDO no hay workspace EL SISTEMA DEBE salir con WORKSPACE_INVALIDO", async () => {
		const code = await runCli(
			["scan", "--workspace", join(base, "nada", ".mct")],
			makeIo().io,
		);
		expect(code).toBe(4);
	});

	it("CLI-001 CUANDO init recibe un origen que no existe EL SISTEMA DEBE salir con ORIGEN_NO_ENCONTRADO", async () => {
		const code = await runCli(
			["init", join(base, "no-existe"), "--dest", dest],
			makeIo().io,
		);
		expect(code).toBe(3);
	});

	it("SAN-006 CUANDO llega Ctrl+C durante scan EL SISTEMA DEBE salir con 130 y dejar el workspace como estaba", async () => {
		const origen = await fixture(
			"o4",
			`const token = "${TOKEN}";
`,
		);
		const ws = join(dest, ".mct");
		expect(await runCli(["init", origen, "--dest", dest], makeIo().io)).toBe(0);
		const controller = new AbortController();
		useRunner(async (c, args, opts) => {
			if (!args.includes("version")) controller.abort();
			return okRunner(c, args, opts);
		});
		const code = await runCli(
			["scan", "--workspace", ws],
			makeIo().io,
			[],
			controller.signal,
		);
		expect(code).toBe(130);
		expect((await readState(ws)).etapas.scan?.estado).toBe("pendiente");
		await expect(access(join(ws, "report.html"))).rejects.toThrow();
		await expect(access(join(ws, "lock"))).rejects.toThrow();
		await expect(access(join(ws, "findings.json"))).rejects.toThrow();
	});

	it("SAN-006 CUANDO llega Ctrl+C antes de init EL SISTEMA DEBE salir con 130 sin crear el workspace", async () => {
		const origen = await fixture("o5", "module.exports = 1;\n");
		const controller = new AbortController();
		controller.abort();
		const code = await runCli(
			["init", origen, "--dest", dest],
			makeIo().io,
			[],
			controller.signal,
		);
		expect(code).toBe(130);
		await expect(access(join(dest, ".mct"))).rejects.toThrow();
	});
});
