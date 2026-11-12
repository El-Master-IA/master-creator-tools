import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { GITLEAKS_VERSION } from "@mct/contract/pins";
import { describe, expect, it } from "vitest";
import { createDoctor } from "../src/commands/doctor.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

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

const lines = (chunks: string[]) => chunks.join("").trimEnd().split("\n");

describe("CLI-007 primera ejecucion", () => {
	it("CLI-007 sin argumentos muestra 5 lineas que sugieren doctor e init", async () => {
		const { io, out, err } = makeIo({ LANG: "es_CO.UTF-8" });
		const code = await runCli([], io);
		expect(code).toBe(0);
		expect(out).toEqual([]);
		const l = lines(err);
		expect(l).toHaveLength(5);
		expect(l[1]).toContain(
			"init → scan → sanitize → licenses → package → verify → publish",
		);
		expect(l[3]).toContain("mct doctor");
		expect(l[4]).toContain(
			"mct init <carpeta | https://github.com/owner/repo | flujo.json>",
		);
	});

	it("CLI-007 con --lang en el resumen sale en ingles, tambien 5 lineas", async () => {
		const { io, err } = makeIo();
		const code = await runCli(["--lang", "en"], io);
		expect(code).toBe(0);
		const l = lines(err);
		expect(l).toHaveLength(5);
		expect(l[2]).toContain("Nothing is published");
		expect(l[3]).toContain("mct doctor");
		expect(l[4]).toContain("mct init <folder");
	});

	it("CLI-007 el idioma por defecto sale de LANG", async () => {
		const { io, err } = makeIo({ LANG: "en_US.UTF-8" });
		await runCli([], io);
		expect(lines(err)[2]).toContain("Nothing is published");
	});

	it("CLI-007 --version imprime la version y sale con 0", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--version"], io);
		expect(code).toBe(0);
		expect(out.join("").trim()).toMatch(/^\d+\.\d+\.\d+/);
	});

	it("CLI-007 --help sale con 0 y lista los flags globales", async () => {
		const { io, out } = makeIo();
		const code = await runCli(["--help"], io);
		expect(code).toBe(0);
		expect(out.join("")).toContain("--json");
		expect(out.join("")).toContain("--workspace");
		expect(out.join("")).not.toContain("--yes");
	});
});

// Token-shaped fixtures are assembled from fragments (never literal).
const TOKEN = `${"gh"}${"p_"}${"Q7".repeat(15)}`;

type Runner = NonNullable<Parameters<typeof createDoctor>[0]>["run"] & {};

const okRun: Runner = async (file) => {
	const name = file.replace(/\\/g, "/").split("/").pop() ?? "";
	return {
		code: 0,
		signal: null,
		stdout: name.startsWith("gitleaks") ? `${GITLEAKS_VERSION}\n` : "",
		timedOut: false,
	};
};
const missingRun: Runner = async () => ({
	code: null,
	signal: null,
	stdout: "",
	timedOut: false,
	error: Object.assign(new Error("x"), { code: "ENOENT" }),
});

async function doctor(
	args: string[],
	deps: Parameters<typeof createDoctor>[0],
	env: Record<string, string | undefined> = {},
) {
	const home = await mkdtemp(join(tmpdir(), "mct-t24-"));
	try {
		const { io, out, err } = makeIo({ LANG: "es_CO.UTF-8", ...env });
		const code = await runCli(
			["--workspace", join(home, ".mct"), "doctor", ...args],
			io,
			[
				createDoctor({
					home,
					resolveExe: async (n) => `/usr/bin/${n}`,
					...deps,
				}),
			],
		);
		return { code, out, err, text: err.join("") };
	} finally {
		await rm(home, { recursive: true, force: true });
	}
}

describe("CLI-007 doctor termina con el siguiente comando", () => {
	it("CLI-007 todo bien: exit 0 y sugiere mct init", async () => {
		const r = await doctor([], { run: okRun }, { GITHUB_TOKEN: TOKEN });
		expect(r.code).toBe(0);
		expect(lines(r.err).at(-1)).toBe("Siguiente: mct init <origen>");
	});

	it("CLI-007 con fallas sale 0 y el siguiente es la accion que las arregla", async () => {
		const r = await doctor([], { run: missingRun });
		expect(r.code).toBe(0);
		expect(lines(r.err).at(-1)).toContain("mct doctor --install-gitleaks");
	});

	it("CLI-007 con mct.config.json invalido doctor sale 0 con 5 chequeos y Siguiente", async () => {
		const home = await mkdtemp(join(tmpdir(), "mct-t24-"));
		try {
			await writeFile(join(home, "mct.config.json"), "{ roto", "utf8");
			const { io, out, err } = makeIo({ LANG: "es_CO.UTF-8" });
			const code = await runCli(
				["--workspace", join(home, ".mct"), "--json", "doctor"],
				io,
				[
					createDoctor({
						home,
						run: okRun,
						resolveExe: async (n) => `/usr/bin/${n}`,
					}),
				],
			);
			expect(code).toBe(0);
			const parsed = JSON.parse(out.join(""));
			expect(parsed.checks).toHaveLength(5);
			expect(parsed.siguiente).toBeTruthy();
			expect(err.join("")).not.toContain("roto");
		} finally {
			await rm(home, { recursive: true, force: true });
		}
	});

	it("CLI-007 en ingles el siguiente sale en ingles", async () => {
		const r = await doctor(["--lang", "en"], { run: okRun });
		expect(lines(r.err).at(-1)).toBe("Next: mct init <source>");
	});

	it("CLI-007 con token dice presente y no lo muestra en texto ni en JSON", async () => {
		const human = await doctor([], { run: okRun }, { GITHUB_TOKEN: TOKEN });
		expect(human.text).toContain("presente");
		expect(human.text).not.toContain(TOKEN);
		const json = await doctor(["--json"], { run: okRun }, { GH_TOKEN: TOKEN });
		expect(json.out.join("")).not.toContain(TOKEN);
		expect(json.text).not.toContain(TOKEN);
		const parsed = JSON.parse(json.out.join(""));
		expect(parsed.checks).toHaveLength(5);
		expect(parsed.siguiente).toBe("mct init <origen>");
	});

	it("SEC-001 sensible.txt con permisos abiertos avisa con la accion", async () => {
		const r = await doctor([], {
			run: okRun,
			perms: {
				platform: "linux",
				stat: async () => ({ mode: 0o100644 }),
			},
		});
		expect(r.text).toContain("AVISO");
		expect(r.text).toContain("chmod 600");
		expect(lines(r.err).at(-1)).toContain("chmod 600");
	});

	it("CLI-007 si falla --install-gitleaks sale con 12 y no se vuelve a decir nada falso", async () => {
		const r = await doctor(["--install-gitleaks"], {
			run: missingRun,
			install: async () => {
				throw new MctError("MOTOR_NO_DISPONIBLE", "descarga fallida");
			},
		});
		expect(r.code).toBe(12);
		expect(r.text).toContain("MOTOR_NO_DISPONIBLE");
		expect(r.text).not.toContain("Siguiente: mct init");
	});

	it("CLI-007 con --json y fallo de instalacion stdout lleva el error con exit 12", async () => {
		const r = await doctor(["--json", "--install-gitleaks"], {
			run: missingRun,
			install: async () => {
				throw new Error("sin red");
			},
		});
		expect(r.code).toBe(12);
		expect(JSON.parse(r.out.join("")).error.codigo).toBe("MOTOR_NO_DISPONIBLE");
	});
});
