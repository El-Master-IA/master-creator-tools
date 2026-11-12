import { cp, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { overridePublishDeps } from "../packages/cli/src/commands/publish.js";
import { runPipeline } from "../packages/cli/src/commands/run.js";
import {
	type CliContext,
	createContext,
	type Io,
} from "../packages/cli/src/output.js";
import { MctError } from "../packages/contract/src/errors.js";
import type { Finding } from "../packages/contract/src/types.js";
import type { Decision, Decisor } from "../packages/core/src/sanitize.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const REPO = "El-Master-IA/master-creator-tools";
/** Only fixtures live here: their secrets and PII are assembled from fragments. */
const TEST_FILE = /^packages\/[^/]+\/test\//;

let tmp = "";
let restore: (() => void) | undefined;

beforeEach(async () => {
	tmp = await mkdtemp(join(tmpdir(), "mct-dogfood-"));
});
afterEach(async () => {
	restore?.();
	restore = undefined;
	await rm(tmp, { recursive: true, force: true });
});

function makeCtx(workspace: string, env: Io["env"]): CliContext {
	const io: Io = {
		out: () => {},
		err: (text) => {
			process.stderr.write(`${text}
`);
		},
		env,
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

describe("DOG-001 dogfooding", () => {
	it("DOG-001 mct run . --repo <owner>/master-creator-tools --dry-run pasa todas las puertas", async () => {
		const dest = join(tmp, "dest");
		const raiz = join(dest, ".mct");
		// The config lives next to the workspace, never inside the origin copy.
		await mkdir(dest, { recursive: true });
		await cp(join(REPO_ROOT, "mct.config.json"), join(dest, "mct.config.json"));

		// GitHub is simulated: no credential, no network.
		let writes = 0;
		restore = overridePublishDeps({
			createClient: async () => ({
				tokenSource: "GITHUB_TOKEN",
				rateRemaining: undefined,
				// PUB-006: the dry run only reads. The repo does not exist yet (404);
				// any other call is a write and fails the test.
				request: async (route: string) => {
					if (route === "GET /repos/{owner}/{repo}") {
						throw new MctError("INTERNO", "Not Found", {
							etapa: "publish",
							detalle: { estado: 404 },
						});
					}
					writes++;
					throw new Error(`dry-run must not call GitHub: ${route}`);
				},
				checkPermissions: async () => undefined,
			}),
		});

		const marcados: { archivo: string; motivo: string }[] = [];
		const ajenos: Finding[] = [];
		const decisor: Decisor = {
			async decidir(h): Promise<Decision> {
				if (TEST_FILE.test(h.archivo)) {
					const motivo =
						"Fixture de test armado por fragmentos, no es un dato real";
					marcados.push({ archivo: h.archivo, motivo });
					return { accion: "falso-positivo", motivo };
				}
				ajenos.push(h);
				return { accion: "abortar" };
			},
			async confirmar() {
				return false;
			},
		};

		const ctx = makeCtx(raiz, { ...process.env });
		let result: Awaited<ReturnType<typeof runPipeline>> | undefined;
		try {
			result = await runPipeline(ctx, {
				origen: REPO_ROOT,
				dest,
				repo: REPO,
				dryRun: true,
				decisor,
			});
		} catch (error) {
			const etapa =
				error instanceof MctError
					? (error.etapa ?? (error.detalle as { etapa?: string })?.etapa)
					: undefined;
			const fuera = ajenos.map((f) => `${f.archivo}:${f.linea} ${f.regla}`);
			throw new Error(
				`DOG-001: la etapa ${etapa ?? "desconocida"} falló: ${
					error instanceof Error ? error.message : String(error)
				}${
					error instanceof MctError
						? ` ${JSON.stringify(error.detalle ?? {})}`
						: ""
				}${fuera.length > 0 ? ` | hallazgos fuera de tests: ${fuera.join(", ")}` : ""}`,
				{ cause: error },
			);
		}

		expect(ajenos).toEqual([]);
		expect(writes).toBe(0);
		expect(result.detenidaEn).toBeUndefined();
		for (const etapa of Object.keys(result.etapas) as Array<
			keyof typeof result.etapas
		>) {
			if (etapa === "publish") continue;
			expect(result.etapas[etapa], `etapa ${etapa}`).toBe("ok");
		}
		// The origin is never touched: the workspace lives outside it.
		expect(raiz.startsWith(REPO_ROOT)).toBe(false);
		await readFile(join(raiz, "state.json"), "utf8");
		process.stdout.write(
			`dogfood: ${marcados.length} falsos positivos marcados en ${[
				...new Set(
					marcados.map((m) => m.archivo.split("/").slice(0, 2).join("/")),
				),
			].join(", ")}\n`,
		);
	}, 1_200_000);

	it("DOG-001 una puerta que falla hace fallar el test mostrando la etapa", async () => {
		const dest = join(tmp, "dest2");
		const ctx = makeCtx(join(dest, ".mct"), { ...process.env });
		const error = await runPipeline(ctx, {
			origen: join(tmp, "no-existe"),
			dest,
			repo: REPO,
			dryRun: true,
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(MctError);
		expect((error as MctError).etapa).toBe("init");
	});
});
