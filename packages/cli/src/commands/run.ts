import { existsSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Etapa, State } from "@mct/contract/types";
import type { Decisor } from "@mct/core/sanitize";
import { ETAPAS, readState } from "@mct/core/workspace";
import { Command } from "commander";
import {
	type CliContext,
	contextOf,
	createContext,
	type Lang,
} from "../output.js";
import { register as flow, setFlowDecisor } from "./flow.js";
import { register as licenses } from "./licenses.js";
import { register as pack } from "./package.js";
import { register as publish } from "./publish.js";
import { register as verify } from "./verify.js";

const TEXT = {
	es: {
		desc: "encadena init → scan → sanitize → licenses → package → verify → publish",
		dest: "carpeta que contendrá .mct/",
		type: "tipo de proyecto (n8n, node o auto)",
		repo: "repo de destino owner/nombre (sin él se detiene antes de publish)",
		dryRun: "corre publish --dry-run al final (necesita --repo)",
		tipoMal: "--type debe ser n8n, node o auto",
		dryRunSinRepo: "--dry-run necesita --repo <owner/nombre>",
		accionRepo: "Corre: mct run <origen> --repo <owner/nombre> --dry-run",
		otroOrigen:
			"El workspace existente se creó desde otro origen. No se tocó nada.",
		accionOtro:
			"Usa otro --dest, o corre mct clean / mct init --force si quieres recrearlo",
		bloqueada: (etapa: string) =>
			`La etapa ${etapa} terminó con la puerta cerrada.`,
		accionBloqueada: (etapa: string) => `Corre: mct ${etapa}`,
		detenida:
			"Listo hasta verify. Para publicar: mct publish --repo <owner/nombre>",
		fin: "Pipeline completo.",
		interrumpido: "Interrumpido por la persona (Ctrl+C)",
		reanuda: (etapa: string) => `Workspace válido: se reanuda desde ${etapa}.`,
		etapa: (etapa: string) => `Etapa ${etapa}`,
	},
	en: {
		desc: "chain init → scan → sanitize → licenses → package → verify → publish",
		dest: "folder that will hold .mct/",
		type: "project type (n8n, node or auto)",
		repo: "target repo owner/name (without it, stops before publish)",
		dryRun: "run publish --dry-run at the end (needs --repo)",
		tipoMal: "--type must be n8n, node or auto",
		dryRunSinRepo: "--dry-run needs --repo <owner/name>",
		accionRepo: "Run: mct run <source> --repo <owner/name> --dry-run",
		otroOrigen:
			"The existing workspace was created from another source. Nothing was touched.",
		accionOtro:
			"Use another --dest, or run mct clean / mct init --force to recreate it",
		bloqueada: (etapa: string) => `Stage ${etapa} ended with a closed gate.`,
		accionBloqueada: (etapa: string) => `Run: mct ${etapa}`,
		detenida: "Done up to verify. To publish: mct publish --repo <owner/name>",
		fin: "Pipeline complete.",
		interrumpido: "Interrupted (Ctrl+C)",
		reanuda: (etapa: string) => `Valid workspace: resuming from ${etapa}.`,
		etapa: (etapa: string) => `Stage ${etapa}`,
	},
} as const;

export type EtapaRun = "ok" | "bloqueada" | "pendiente";

/** Output of `mct run` (api.md). */
export interface RunResult {
	etapas: Record<Etapa, EtapaRun>;
	detenidaEn?: Etapa;
	reanudadaDesde?: Etapa;
}

/**
 * Runs one stage as the CLI command of the same name with `argv` (without the
 * global flags) and resolves with the exit code the stage asked for. Errors of
 * the stage propagate as thrown `MctError`.
 */
export type StageRunner = (etapa: Etapa, argv: string[]) => Promise<number>;

export interface RunOptions {
	/** Folder, `https://github.com/<owner>/<repo>` or n8n `.json`, as given to `init`. */
	origen: string;
	/** Folder that will hold `.mct/`; default: the parent of `ctx.workspace`. */
	dest?: string;
	type?: "n8n" | "node" | "auto";
	/** `owner/name`. Without it the pipeline stops before `publish` (exit 0). */
	repo?: string;
	/** Runs `publish --dry-run` at the end; requires `repo`. */
	dryRun?: boolean;
	/**
	 * Internal API only, never a flag: decides the findings of `sanitize` instead of
	 * the prompts, so the stage needs no TTY (used by the dogfooding, T38).
	 */
	decisor?: Decisor;
	/** Replaces how each stage runs (tests); default: {@link defaultStageRunner}. */
	runStage?: StageRunner;
}

/** Everything the stage commands need, but with the stage output hidden from stdout. */
export function defaultStageRunner(ctx: CliContext, raiz: string): StageRunner {
	return async (etapa, argv) => {
		const sub = new Command();
		sub
			.name("mct")
			.option("--workspace <dir>")
			.exitOverride()
			.configureOutput({ outputError: () => {} });
		for (const register of [flow, licenses, pack, verify, publish]) {
			register(sub);
		}
		// Stage results never reach stdout: `run` prints only its own result.
		// `--json` also means no TTY, as in every command.
		const io = {
			...ctx.io,
			out: () => {},
			stdinIsTTY: ctx.interactive && ctx.io.stdinIsTTY,
		};
		const stageCtx = createContext(
			sub,
			io,
			{
				json: false,
				noColor: !ctx.color,
				verbose: ctx.verbose,
				lang: ctx.lang,
			},
			ctx.signal,
		);
		ctx.info(TEXT[ctx.lang].etapa(etapa));
		await sub.parseAsync(["--workspace", raiz, ...argv], { from: "user" });
		return stageCtx.exitCode;
	};
}

function argvOf(
	etapa: Etapa,
	o: RunOptions,
	dest: string,
	repoDryRun: boolean,
): string[] {
	switch (etapa) {
		case "init":
			return ["init", o.origen, "--dest", dest, "--type", o.type ?? "auto"];
		case "publish":
			return [
				"publish",
				"--repo",
				o.repo ?? "",
				...(repoDryRun ? ["--dry-run"] : []),
			];
		default:
			return [etapa];
	}
}

export function normalizeRef(ref: string): string {
	return ref
		.trim()
		.replace(/\/+$/, "")
		.replace(/\.git$/, "")
		.toLowerCase();
}

/** The workspace comes from `origen` when the stored ref matches it (folder, n8n file or GitHub URL). */
function sameOrigin(state: State, origen: string): boolean {
	const ref = state.origen.ref;
	if (state.origen.tipo === "github") {
		return normalizeRef(ref) === normalizeRef(origen);
	}
	const abs = resolve(origen);
	const candidates = new Set([origen, abs]);
	try {
		candidates.add(realpathSync(abs));
	} catch {
		// The source may no longer exist; the plain forms still compare.
	}
	return candidates.has(ref) || candidates.has(resolve(ref));
}

async function readStates(raiz: string): Promise<Record<Etapa, EtapaRun>> {
	const state = await readState(raiz);
	const out = {} as Record<Etapa, EtapaRun>;
	for (const e of ETAPAS) out[e] = state.etapas[e].estado;
	return out;
}

/**
 * RUN-001. Chains the seven stages and stops at the first closed gate (the stage's
 * own `MctError` propagates). With a valid workspace made from the same `origen` it
 * resumes from the first stage that is not `ok` without repeating `init`; a
 * workspace from another origin fails with `VALIDACION` before anything is touched.
 * Without `repo` it stops before `publish` (exit 0, `detenidaEn: "publish"`).
 * There is no `--yes`: `publish` keeps its own confirmations.
 *
 * Used by `mct run` and, with `dryRun: true`, an injected `decisor` and a simulated
 * GitHub (`overridePublishDeps`), by the dogfooding (T38).
 */
export async function runPipeline(
	ctx: CliContext,
	o: RunOptions,
): Promise<RunResult> {
	const t = TEXT[ctx.lang as Lang];
	if (o.type !== undefined && !["n8n", "node", "auto"].includes(o.type)) {
		throw new MctError("VALIDACION", t.tipoMal);
	}
	const repo = o.repo === undefined || o.repo === "" ? undefined : o.repo;
	if (o.dryRun === true && repo === undefined) {
		throw new MctError("VALIDACION", t.dryRunSinRepo, {
			accion: t.accionRepo,
			etapa: "publish",
		});
	}
	const raiz =
		o.dest !== undefined ? resolve(o.dest, ".mct") : resolve(ctx.workspace);
	const dest = dirname(raiz);
	const runStage = o.runStage ?? defaultStageRunner(ctx, raiz);
	const options: RunOptions = { ...o, ...(repo !== undefined && { repo }) };

	const etapas = {} as Record<Etapa, EtapaRun>;
	let reanudadaDesde: Etapa | undefined;
	if (existsSync(raiz)) {
		const state = await readState(raiz);
		if (!sameOrigin(state, o.origen)) {
			throw new MctError("VALIDACION", t.otroOrigen, {
				accion: t.accionOtro,
				etapa: "init",
			});
		}
		Object.assign(etapas, await readStates(raiz));
		const first = ETAPAS.find((e) => etapas[e] !== "ok");
		if (first !== undefined) {
			reanudadaDesde = first;
			ctx.info(t.reanuda(first));
		}
	} else {
		for (const e of ETAPAS) etapas[e] = "pendiente";
	}

	const restore =
		o.decisor === undefined ? undefined : setFlowDecisor(o.decisor);
	try {
		for (const etapa of ETAPAS) {
			if (etapas[etapa] === "ok") continue;
			if (etapa === "publish" && repo === undefined) {
				ctx.info(t.detenida);
				return finish(etapas, "publish", reanudadaDesde);
			}
			if (ctx.signal.aborted) {
				throw new MctError("INTERRUMPIDO", t.interrumpido, { etapa });
			}
			let exit: number;
			try {
				exit = await runStage(
					etapa,
					argvOf(etapa, options, dest, o.dryRun === true),
				);
			} catch (error) {
				// Open findings are what `sanitize` (next stage) exists to resolve.
				if (!(etapa === "scan" && hasOpenFindings(error))) throw error;
				etapas.scan = "bloqueada";
				// On resume sanitize may already say ok: run it again so the re-scan
				// below always happens before any later stage.
				if (etapas.sanitize === "ok") etapas.sanitize = "pendiente";
				continue;
			}
			if (exit !== 0) {
				etapas[etapa] = "bloqueada";
				throw new MctError("PUERTA_BLOQUEADA", t.bloqueada(etapa), {
					accion: t.accionBloqueada(etapa),
					etapa,
					detalle: { etapas: { ...etapas }, exit },
				});
			}
			try {
				Object.assign(etapas, await readStates(raiz));
			} catch (error) {
				// A real publish may delete the workspace on request; nothing else may.
				if (etapa !== "publish" || o.dryRun === true || existsSync(raiz)) {
					throw error;
				}
				etapas.publish = "ok";
			}
			// Fail closed: exit 0 is not enough, state.json must say the stage is ok
			// (a publish --dry-run writes nothing, so it keeps its state).
			if (
				estadoDe(etapas, etapa) !== "ok" &&
				!(etapa === "publish" && o.dryRun === true)
			) {
				throw new MctError("PUERTA_BLOQUEADA", t.bloqueada(etapa), {
					accion: t.accionBloqueada(etapa),
					etapa,
					detalle: { etapas: { ...etapas }, exit },
				});
			}
			// A scan blocked by open findings is re-run once sanitize resolved them;
			// it must come back ok, or the pipeline stops there.
			if (etapa === "sanitize" && etapas.scan !== "ok") {
				const rescan = await runStage(
					"scan",
					argvOf("scan", options, dest, o.dryRun === true),
				);
				Object.assign(etapas, await readStates(raiz));
				if (rescan !== 0 || estadoDe(etapas, "scan") !== "ok") {
					etapas.scan = "bloqueada";
					throw new MctError("PUERTA_BLOQUEADA", t.bloqueada("scan"), {
						accion: t.accionBloqueada("scan"),
						etapa: "scan",
						detalle: { etapas: { ...etapas }, exit: rescan },
					});
				}
			}
		}
	} finally {
		restore?.();
	}
	ctx.info(t.fin);
	return finish(etapas, undefined, reanudadaDesde);
}

function estadoDe(etapas: Record<Etapa, EtapaRun>, etapa: Etapa): EtapaRun {
	return etapas[etapa];
}

function hasOpenFindings(error: unknown): boolean {
	if (!(error instanceof MctError) || error.codigo !== "PUERTA_BLOQUEADA") {
		return false;
	}
	const detalle = error.detalle as
		| { abiertos?: unknown; detalle?: { abiertos?: unknown } }
		| undefined;
	return typeof (detalle?.abiertos ?? detalle?.detalle?.abiertos) === "number";
}

function finish(
	etapas: Record<Etapa, EtapaRun>,
	detenidaEn: Etapa | undefined,
	reanudadaDesde: Etapa | undefined,
): RunResult {
	return {
		etapas,
		...(detenidaEn !== undefined && { detenidaEn }),
		...(reanudadaDesde !== undefined && { reanudadaDesde }),
	};
}

export function register(program: Command): void {
	program
		.command("run")
		.description(TEXT.es.desc)
		.argument(
			"<origen>",
			"folder, https://github.com/<owner>/<repo> or n8n .json",
		)
		.option("--dest <dir>", TEXT.es.dest)
		.option("--type <type>", TEXT.es.type)
		.option("--repo <owner/nombre>", TEXT.es.repo)
		.option("--dry-run", TEXT.es.dryRun)
		.action(
			async (
				origen: string,
				opts: { dest?: string; type?: string; repo?: string; dryRun?: boolean },
			) => {
				const ctx = contextOf(program);
				const result = await runPipeline(ctx, {
					origen,
					...(opts.dest !== undefined && { dest: opts.dest }),
					...(opts.type !== undefined && {
						type: opts.type as "n8n" | "node" | "auto",
					}),
					...(opts.repo !== undefined && { repo: opts.repo }),
					...(opts.dryRun === true && { dryRun: true }),
				});
				ctx.result(result);
			},
		);
}
