import { MctError } from "@mct/contract/errors";
import type { Command } from "commander";
import { describe, expect, it } from "vitest";
import { type Register, runCli } from "../src/main.js";
import { contextOf, type Io } from "../src/output.js";

function makeIo(env: Record<string, string | undefined> = {}) {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env,
		stdinIsTTY: false,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

// Token-shaped fixtures are assembled from fragments (never literal).
const tokenOf = (ch: string) => `${"gh"}${"p_"}${ch.repeat(30)}`;

const fake: Register = (program: Command) => {
	program.command("ok").action(() => {
		contextOf(program).result({ workspace: "w", archivos: 3 }, "hecho");
	});
	program.command("gate").action(() => {
		contextOf(program).result({ abiertos: 2 }, "hay hallazgos", 10);
	});
	program.command("bad").action(() => {
		throw new MctError("PUERTA_BLOQUEADA", "Hay 3 hallazgos sin resolver", {
			accion: "Corre: mct sanitize",
			etapa: "package",
			detalle: { abiertos: 3 },
		});
	});
	program.command("boom").action(() => {
		throw new Error(`secreto ${tokenOf("a")}`);
	});
	program.command("big").action(() => {
		contextOf(program).result({ n: 1n });
	});
};

describe("CLI-005 salida --json", () => {
	it("CLI-005 exito: stdout solo el JSON del resultado y exit 0", async () => {
		const { io, out, err } = makeIo();
		const code = await runCli(["--json", "ok"], io, [fake]);
		expect(code).toBe(0);
		expect(out).toHaveLength(1);
		expect(JSON.parse(out.join(""))).toEqual({ workspace: "w", archivos: 3 });
		expect(err.join("")).toContain("hecho");
	});

	it("CLI-005 el flag --json tambien vale despues del subcomando", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["ok", "--json"], io, [fake]);
		expect(code).toBe(0);
		expect(JSON.parse(out.join(""))).toEqual({ workspace: "w", archivos: 3 });
	});

	it("CLI-005 sin --json stdout queda vacio y lo humano va a stderr", async () => {
		const { io, out, err } = makeIo();
		const code = await runCli(["ok"], io, [fake]);
		expect(code).toBe(0);
		expect(out).toEqual([]);
		expect(err.join("")).toContain("hecho");
	});

	it("CLI-005 resultado con exit distinto de 0 conserva su JSON", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "gate"], io, [fake]);
		expect(code).toBe(10);
		expect(JSON.parse(out.join(""))).toEqual({ abiertos: 2 });
	});

	it("CLI-005 error: stdout solo el JSON de error y exit de su codigo", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "bad"], io, [fake]);
		expect(code).toBe(10);
		expect(out).toHaveLength(1);
		expect(JSON.parse(out.join(""))).toEqual({
			error: {
				codigo: "PUERTA_BLOQUEADA",
				mensaje: "Hay 3 hallazgos sin resolver",
				accion: "Corre: mct sanitize",
				etapa: "package",
				detalle: { abiertos: 3 },
			},
		});
	});

	it("CLI-005 error no controlado sale como INTERNO sin filtrar su mensaje", async () => {
		const { io, out, err } = makeIo();
		const code = await runCli(["--json", "boom"], io, [fake]);
		expect(code).toBe(70);
		const body = JSON.parse(out.join("")) as { error: { codigo: string } };
		expect(body.error.codigo).toBe("INTERNO");
		expect(out.join("") + err.join("")).not.toContain("a".repeat(30));
	});

	it("CLI-005 resultado no serializable falla cerrado con INTERNO", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "big"], io, [fake]);
		expect(code).toBe(70);
		expect(out).toHaveLength(1);
		expect(JSON.parse(out.join(""))).toHaveProperty("error.codigo", "INTERNO");
	});

	it("CLI-005 opcion invalida con --json: VALIDACION en JSON, exit 2", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "--nope"], io, [fake]);
		expect(code).toBe(2);
		expect(out).toHaveLength(1);
		expect(JSON.parse(out.join(""))).toHaveProperty(
			"error.codigo",
			"VALIDACION",
		);
	});

	it("CLI-005 subcomando desconocido con --json: VALIDACION en JSON", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "nada"], io, [fake]);
		expect(code).toBe(2);
		expect(JSON.parse(out.join(""))).toHaveProperty(
			"error.codigo",
			"VALIDACION",
		);
	});

	it("CLI-005 --lang invalido es VALIDACION", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--json", "--lang", "fr", "ok"], io, [fake]);
		expect(code).toBe(2);
		expect(JSON.parse(out.join(""))).toHaveProperty(
			"error.codigo",
			"VALIDACION",
		);
	});

	it("CLI-005 un token en un argumento no sale en el error", async () => {
		const { io, out, err } = makeIo();
		await runCli(["--json", tokenOf("b")], io, [fake]);
		expect(out.join("") + err.join("")).not.toContain("b".repeat(30));
	});

	it("CLI-005 sin color con NO_COLOR, --no-color o stderr sin TTY", async () => {
		const cases: [string[], Record<string, string>, boolean][] = [
			[["bad"], { NO_COLOR: "1" }, true],
			[["--no-color", "bad"], {}, true],
			[["bad"], {}, false],
		];
		for (const [argv, env, tty] of cases) {
			const { io, err } = makeIo(env);
			io.stderrIsTTY = tty;
			await runCli(argv, io, [fake]);
			// biome-ignore lint/suspicious/noControlCharactersInRegex: busca secuencias ANSI
			expect(err.join("")).not.toMatch(/\u001b\[/);
		}
	});
});
