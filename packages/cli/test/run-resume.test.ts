import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Etapa } from "@mct/contract/types";
import { hashTree } from "@mct/core/hash";
import {
	createWorkspace,
	ETAPAS,
	readState,
	writeState,
} from "@mct/core/workspace";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps } from "../src/commands/flow.js";
import {
	normalizeRef,
	runPipeline,
	type StageRunner,
} from "../src/commands/run.js";
import { runCli } from "../src/main.js";
import { type CliContext, createContext, type Io } from "../src/output.js";

let tmp: string;
let origen: string;
let raiz: string;

beforeEach(async () => {
	tmp = await mkdtemp(join(tmpdir(), "mct-run-"));
	origen = join(tmp, "src");
	await mkdir(origen);
	await writeFile(join(origen, "a.txt"), "hola");
	raiz = join(tmp, "dest", ".mct");
});

afterEach(async () => {
	await rm(tmp, { recursive: true, force: true });
});

function makeCtx(workspace: string): CliContext {
	const io: Io = {
		out: () => {},
		err: () => {},
		env: {},
		stdinIsTTY: false,
		stderrIsTTY: false,
	};
	const program = new Command().option("--workspace <dir>");
	program.parse(["--workspace", workspace], { from: "user" });
	return createContext(program, io, {
		json: false,
		noColor: true,
		verbose: false,
		lang: "es",
	});
}

async function seed(ref: string, ok: readonly Etapa[]): Promise<void> {
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref },
		adapter: "node",
	});
	const state = await readState(raiz);
	for (const e of ok) {
		state.etapas[e] = { estado: "ok", ts: state.etapas[e].ts };
	}
	await writeState(raiz, state);
}

/** Fake stages: each one marks itself ok in state.json, like the real commands. */
function fakeStages(calls: string[], blockAt?: Etapa): StageRunner {
	return async (etapa, argv) => {
		calls.push(argv.join(" "));
		if (etapa === blockAt) return 10;
		if (etapa === "init") {
			await createWorkspace(raiz, {
				mctVersion: "0.0.0",
				origen: { tipo: "carpeta", ref: origen },
				adapter: "node",
			});
			return 0;
		}
		if (etapa !== "publish" || !argv.includes("--dry-run")) {
			const state = await readState(raiz);
			state.etapas[etapa] = { estado: "ok", ts: state.etapas[etapa].ts };
			await writeState(raiz, state);
		}
		return 0;
	};
}

describe("RUN-001 mct run", () => {
	it("RUN-001 reanuda desde la primera etapa no ok sin repetir init", async () => {
		await seed(origen, ["init", "scan", "sanitize"]);
		const calls: string[] = [];
		const result = await runPipeline(makeCtx(raiz), {
			origen,
			repo: "o/n",
			runStage: fakeStages(calls),
		});
		expect(calls.map((c) => c.split(" ")[0])).toEqual([
			"licenses",
			"package",
			"verify",
			"publish",
		]);
		expect(result.reanudadaDesde).toBe("licenses");
		expect(result.etapas.licenses).toBe("ok");
		expect(result.detenidaEn).toBeUndefined();
	});

	it("RUN-001 un scan bloqueado por hallazgos se repite tras sanitize y debe quedar ok", async () => {
		await seed(origen, ["init"]);
		const calls: string[] = [];
		const base = fakeStages(calls);
		let scans = 0;
		const result = await runPipeline(makeCtx(raiz), {
			origen,
			runStage: async (etapa, argv) => {
				if (etapa === "scan" && scans++ === 0) {
					calls.push(argv.join(" "));
					throw new MctError("PUERTA_BLOQUEADA", "hallazgos", {
						etapa: "scan",
						detalle: { abiertos: 2 },
					});
				}
				return base(etapa, argv);
			},
		});
		expect(calls.map((c) => c.split(" ")[0])).toEqual([
			"scan",
			"sanitize",
			"scan",
			"licenses",
			"package",
			"verify",
		]);
		expect(result.etapas.scan).toBe("ok");
		expect(result.detenidaEn).toBe("publish");
	});

	it("RUN-001 si el re-scan tras sanitize no queda ok EL SISTEMA DEBE detenerse en scan", async () => {
		await seed(origen, ["init"]);
		const base = fakeStages([]);
		const error = await runPipeline(makeCtx(raiz), {
			origen,
			runStage: async (etapa, argv) => {
				if (etapa === "scan") {
					throw new MctError("PUERTA_BLOQUEADA", "hallazgos", {
						etapa: "scan",
						detalle: { abiertos: 1 },
					});
				}
				return base(etapa, argv);
			},
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(MctError);
		expect((error as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect((error as MctError).etapa).toBe("scan");
	});

	it("RUN-001 al reanudar con sanitize ok y scan bloqueado EL SISTEMA DEBE repetir sanitize y el re-scan antes de seguir", async () => {
		await seed(origen, ["init", "sanitize"]);
		const calls: string[] = [];
		const base = fakeStages(calls);
		let scans = 0;
		await runPipeline(makeCtx(raiz), {
			origen,
			runStage: async (etapa, argv) => {
				if (etapa === "scan" && scans++ === 0) {
					calls.push(argv.join(" "));
					throw new MctError("PUERTA_BLOQUEADA", "hallazgos", {
						etapa: "scan",
						detalle: { abiertos: 1 },
					});
				}
				return base(etapa, argv);
			},
		});
		expect(calls.map((c) => c.split(" ")[0]).slice(0, 4)).toEqual([
			"scan",
			"sanitize",
			"scan",
			"licenses",
		]);
	});

	it("RUN-001 si el re-scan sale distinto de 0 EL SISTEMA DEBE detenerse en scan", async () => {
		await seed(origen, ["init"]);
		const base = fakeStages([]);
		let scans = 0;
		const error = await runPipeline(makeCtx(raiz), {
			origen,
			runStage: async (etapa, argv) => {
				if (etapa === "scan") {
					if (scans++ === 0) {
						throw new MctError("PUERTA_BLOQUEADA", "hallazgos", {
							etapa: "scan",
							detalle: { abiertos: 1 },
						});
					}
					return 1;
				}
				return base(etapa, argv);
			},
		}).catch((e: unknown) => e);
		expect((error as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect((error as MctError).etapa).toBe("scan");
	});

	it("RUN-001 sin workspace corre todas las etapas desde init", async () => {
		const calls: string[] = [];
		const result = await runPipeline(makeCtx(raiz), {
			origen,
			dest: join(tmp, "dest"),
			runStage: fakeStages(calls),
		});
		expect(calls[0]).toContain("init");
		expect(calls[0]).toContain(join(tmp, "dest"));
		expect(result.reanudadaDesde).toBeUndefined();
		expect(Object.keys(result.etapas)).toEqual([...ETAPAS]);
	});

	it("RUN-001 un workspace de otro origen sale con VALIDACION sin tocarlo", async () => {
		await seed(join(tmp, "otro"), ["init", "scan"]);
		const antes = await hashTree(raiz);
		const stateAntes = await readFile(join(raiz, "state.json"), "utf8");
		const calls: string[] = [];
		const error = await runPipeline(makeCtx(raiz), {
			origen,
			runStage: fakeStages(calls),
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(MctError);
		expect((error as MctError).codigo).toBe("VALIDACION");
		expect(calls).toEqual([]);
		expect(await hashTree(raiz)).toBe(antes);
		expect(await readFile(join(raiz, "state.json"), "utf8")).toBe(stateAntes);
	});

	it("RUN-001 sin --repo se detiene antes de publish con exit 0", async () => {
		const calls: string[] = [];
		const result = await runPipeline(makeCtx(raiz), {
			origen,
			dest: join(tmp, "dest"),
			runStage: fakeStages(calls),
		});
		expect(result.detenidaEn).toBe("publish");
		expect(calls.some((c) => c.startsWith("publish"))).toBe(false);
		expect(result.etapas.verify).toBe("ok");
	});

	it("RUN-001 se detiene en la puerta que queda cerrada", async () => {
		const calls: string[] = [];
		const error = await runPipeline(makeCtx(raiz), {
			origen,
			dest: join(tmp, "dest"),
			repo: "o/n",
			runStage: fakeStages(calls, "licenses"),
		}).catch((e: unknown) => e);
		expect((error as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect((error as MctError).exit).toBe(10);
		expect(calls.map((c) => c.split(" ")[0])).toEqual([
			"init",
			"scan",
			"sanitize",
			"licenses",
		]);
	});

	it("RUN-001 --dry-run pasa publish --dry-run y exige --repo", async () => {
		const calls: string[] = [];
		await runPipeline(makeCtx(raiz), {
			origen,
			dest: join(tmp, "dest"),
			repo: "o/n",
			dryRun: true,
			runStage: fakeStages(calls),
		});
		expect(calls.at(-1)).toBe("publish --repo o/n --dry-run");
		const error = await runPipeline(makeCtx(raiz), {
			origen,
			dryRun: true,
			runStage: fakeStages([]),
		}).catch((e: unknown) => e);
		expect((error as MctError).codigo).toBe("VALIDACION");
	});
});

describe("RUN-001 mct run por la CLI", () => {
	it("RUN-001 sin --repo, run --json devuelve 0 con detenidaEn publish", async () => {
		await seed(origen, [
			"init",
			"scan",
			"sanitize",
			"licenses",
			"package",
			"verify",
		]);
		const out: string[] = [];
		const io: Io = {
			out: (t) => out.push(t),
			err: () => {},
			env: {},
			stdinIsTTY: false,
			stderrIsTTY: false,
		};
		const code = await runCli(
			["run", origen, "--workspace", raiz, "--json"],
			io,
		);
		expect(code).toBe(0);
		const json = JSON.parse(out.join("")) as {
			detenidaEn?: string;
			etapas: Record<string, string>;
		};
		expect(json.detenidaEn).toBe("publish");
		expect(json.etapas.verify).toBe("ok");
	});

	it("RUN-001 normalizeRef iguala URLs de GitHub con .git, barra final y mayusculas", () => {
		const base = "https://github.com/owner/repo";
		expect(normalizeRef(`${base}.git`)).toBe(normalizeRef(base));
		expect(normalizeRef(`${base}/`)).toBe(normalizeRef(base));
		expect(normalizeRef("HTTPS://GitHub.com/Owner/Repo")).toBe(
			normalizeRef(base),
		);
		expect(normalizeRef(`${base}-otro`)).not.toBe(normalizeRef(base));
	});

	it("RUN-001 un exit 0 con state sin ok falla cerrado", async () => {
		const ctx = makeCtx(raiz);
		await seed(origen, ["init"]);
		const error = await runPipeline(ctx, {
			origen,
			runStage: async () => 0,
		}).catch((e: unknown) => e);
		expect((error as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect((error as MctError).detalle).toMatchObject({ exit: 0 });
	});

	it("RUN-001 con la senal abortada sale con INTERRUMPIDO sin correr etapas", async () => {
		const controller = new AbortController();
		controller.abort();
		const io: Io = {
			out: () => {},
			err: () => {},
			env: {},
			stdinIsTTY: false,
			stderrIsTTY: false,
		};
		const program = new Command().option("--workspace <dir>");
		program.parse(["--workspace", raiz], { from: "user" });
		const ctx = createContext(
			program,
			io,
			{ json: false, noColor: true, verbose: false, lang: "es" },
			controller.signal,
		);
		const calls: string[] = [];
		const error = await runPipeline(ctx, {
			origen,
			runStage: fakeStages(calls),
		}).catch((e: unknown) => e);
		expect((error as MctError).codigo).toBe("INTERRUMPIDO");
		expect(calls).toEqual([]);
	});
});

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

describe("RUN-001 decisor inyectado", () => {
	it("RUN-001 sin TTY llega a sanitize con el decisor inyectado y lo restaura aunque la etapa falle", async () => {
		await mkdir(join(origen, "src"), { recursive: true });
		await writeFile(
			join(origen, "package.json"),
			JSON.stringify({ name: "fx", version: "1.0.0" }),
		);
		await writeFile(
			join(origen, "src", "index.js"),
			`const token = "${TOKEN}";\nmodule.exports = token;\n`,
		);
		const home = join(tmp, "home");
		await mkdir(home, { recursive: true });
		const restoreDeps = overrideFlowDeps({
			home,
			gitleaks: {
				binary: process.execPath,
				installDir: join(tmp, "bin"),
				run: okRunner,
			},
		});
		try {
			const seen: string[] = [];
			const error = await runPipeline(makeCtx(raiz), {
				origen,
				dest: join(tmp, "dest"),
				decisor: {
					async decidir(h) {
						seen.push(h.id);
						return { accion: "abortar" };
					},
					async confirmar() {
						return false;
					},
				},
			}).catch((e: unknown) => e);
			// The decisor was asked (no TTY, no prompts) and its abort made the stage throw.
			expect(seen.length).toBeGreaterThan(0);
			expect(error).toBeInstanceOf(MctError);
			expect((error as MctError).etapa ?? "sanitize").toBe("sanitize");

			// Restored: a plain `mct sanitize` without TTY is blocked again, decisor untouched.
			const before = seen.length;
			const err: string[] = [];
			const code = await runCli(["sanitize", "--workspace", raiz], {
				out: () => {},
				err: (t) => err.push(t),
				env: {},
				stdinIsTTY: false,
				stderrIsTTY: false,
			});
			expect(code).toBe(10);
			expect(seen.length).toBe(before);
		} finally {
			restoreDeps();
		}
	});
});
