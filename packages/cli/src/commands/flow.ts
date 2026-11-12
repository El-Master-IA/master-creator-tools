import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { text as clackText, confirm, isCancel, select } from "@clack/prompts";
import { MctError } from "@mct/contract/errors";
import type { Adapter, Finding, Rule } from "@mct/contract/types";
import { adapterById } from "@mct/core/adapters";
import { hashTree } from "@mct/core/hash";
import { initFromSource } from "@mct/core/init";
import { defaultDictionaryPath } from "@mct/core/init-guards";
import {
	autoFixturesLista,
	type Decision,
	type Decisor,
	hallazgosAbiertos,
	type ListaAuto,
	type RescanResult,
	sanitize,
} from "@mct/core/sanitize";
import { stageScan } from "@mct/core/stage-scan";
import { readState, workspacePaths } from "@mct/core/workspace";
import type { Command } from "commander";
// The CLI package does not list the engines as dependencies; they are bundled
// from their sources (same approach as core, which owns the real scan stage).
import { findRegistryIssues } from "../../../adapter-node/src/index.js";
import {
	detectDictionary,
	loadDictionary,
} from "../../../scanner/src/dictionary.js";
import { defaultRunner, type Runner } from "../../../scanner/src/gitleaks.js";
import { detectPii } from "../../../scanner/src/pii.js";
import { type ScanGitleaksOptions, scan } from "../../../scanner/src/scan.js";
import { detectSecrets } from "../../../scanner/src/secrets.js";
import pkg from "../../package.json" with { type: "json" };
import { type CliContext, contextOf, type Lang } from "../output.js";

// ------------------------------------------------------------------ prompts

export interface SelectOption<T extends string> {
	value: T;
	label: string;
}

/** Prompt boundary: every method returns `null` when the person cancels (Esc / Ctrl+C). */
export interface Prompter {
	select<T extends string>(o: {
		message: string;
		options: SelectOption<T>[];
	}): Promise<T | null>;
	text(o: {
		message: string;
		initialValue?: string;
		validate?: (value: string) => string | undefined;
	}): Promise<string | null>;
	confirm(o: {
		message: string;
		initialValue: boolean;
	}): Promise<boolean | null>;
}

const clackPrompter: Prompter = {
	async select(o) {
		const answer = await select<string>({
			message: o.message,
			options: o.options.map((x) => ({ value: x.value, label: x.label })),
		});
		if (isCancel(answer)) return null;
		return answer as never;
	},
	async text(o) {
		const answer = await clackText({
			message: o.message,
			...(o.initialValue === undefined ? {} : { initialValue: o.initialValue }),
			...(o.validate === undefined
				? {}
				: { validate: (v) => o.validate?.(v ?? "") }),
		});
		if (isCancel(answer)) return null;
		return answer;
	},
	async confirm(o) {
		const answer = await confirm({
			message: o.message,
			initialValue: o.initialValue,
		});
		if (isCancel(answer)) return null;
		return answer === true;
	},
};

export interface FlowDeps {
	prompter: Prompter;
	/** Home with `~/.mct/` (dictionary, pinned gitleaks). Default: the user's home. */
	home?: string;
	/** Overrides for the gitleaks engine (tests inject a runner). */
	gitleaks: Partial<ScanGitleaksOptions>;
	/** Injected review decisor (only through `setFlowDecisor`); replaces the prompts. */
	decisor?: Decisor | undefined;
}

let deps: FlowDeps = { prompter: clackPrompter, gitleaks: {} };

/** Test hook: replaces the boundary (prompts, home, gitleaks); returns the restore function. */
export function overrideFlowDeps(partial: Partial<FlowDeps>): () => void {
	const previous = deps;
	deps = { prompter: clackPrompter, gitleaks: {}, ...partial };
	return () => {
		deps = previous;
	};
}

/**
 * Internal API for `mct run` (never a flag): sanitize uses this decisor instead of
 * the prompts and no longer needs a TTY. Returns the function that restores it.
 */
export function setFlowDecisor(decisor: Decisor | undefined): () => void {
	const previous = deps;
	deps = { ...deps, decisor };
	return () => {
		deps = previous;
	};
}

// -------------------------------------------------------------------- texts

const TEXT = {
	es: {
		initDesc: "copia el origen a un workspace de trabajo",
		scanDesc: "busca secretos, PII y términos del diccionario",
		sanitizeDesc: "revisa los hallazgos y firma la aprobación",
		destFlag: "carpeta que contendrá .mct/",
		typeFlag: "tipo de proyecto",
		forceFlag: "recrea el workspace (pide confirmación)",
		autoFlag: "aplica los reemplazos sugeridos (igual pide confirmar)",
		reopenFlag: "devuelve un hallazgo decidido a abierto",
		initOk: (adapter: string, conf: number, n: number) =>
			`Workspace listo · adaptador ${adapter} (confianza ${conf}) · ${n} archivos`,
		scanVacio: "0 hallazgos en ambos motores. Siguiente: mct licenses",
		scanCerrada: (n: number) =>
			`Puerta cerrada: ${n} hallazgos abiertos. Corre: mct sanitize`,
		sanVacio: (h: string) =>
			`No hay hallazgos que revisar. Aprobación firmada (sha256 …${h}). Siguiente: mct licenses`,
		sanOk: (h: string) =>
			`0 hallazgos abiertos · aprobación firmada (sha256 …${h}). Siguiente: mct licenses`,
		sanSinTty:
			"La revisión de hallazgos necesita una terminal interactiva, o un archivo con --decisiones o --auto-fixtures --confirmo. No se aprueba en automático.",
		sanSinTtyAccion: "Corre mct sanitize desde una terminal",
		decisionesFlag:
			"aplica decisiones desde un JSON (falso-positivo o reemplazar)",
		autoFixturesFlag:
			"marca como falso positivo los datos de prueba en rutas de test",
		dryRunFlag: "con --auto-fixtures: solo lista los candidatos y su sha256",
		confirmoFlag: "con --auto-fixtures: sha256 de la lista que ya viste",
		autoSolo: (f: string) => `${f} solo se usa junto con --auto-fixtures`,
		dryRunConfirmo:
			"--dry-run no se combina con --confirmo ni con --decisiones",
		autoPregunta: (n: number, grupos: string) =>
			`Encontré ${n} datos de prueba en rutas de test (${grupos}). ¿Marcarlos como falso positivo?`,
		autoAplicado: (n: number, h: string, q: number) =>
			`${n} hallazgos marcados como datos de prueba (auto-fixtures, sha256 …${h}). Quedan ${q} abiertos.`,
		decAplicadas: (n: number, h: string, q: number) =>
			`Apliqué ${n} decisiones de decisiones.json (sha256 …${h}). Quedan ${q} abiertos.`,
		autoListo: (n: number, h: string) =>
			`${n} candidatos de auto-fixtures (sha256 …${h}). Nada se aplicó. Para aplicar: mct sanitize --auto-fixtures --confirmo <sha256>`,
		destInvalido:
			"Sin --dest, --workspace debe terminar en .mct para saber dónde crear el workspace.",
		sync: (nombre: string, ruta: string) =>
			`El workspace quedaría en ${nombre} (${ruta}). Ahí la copia con datos de clientes se subiría a la nube. ¿Seguir igual? Para evitarlo usa: mct init <origen> --dest <carpeta local>`,
		force: (perdidas: string) =>
			`Esto borra el workspace actual: ${perdidas}. ¿Recrear desde cero?`,
		hallazgo: (h: Finding) =>
			`${h.archivo}:${h.linea} · ${h.regla} · ${h.severidad} · ${h.fragmento}`,
		queHacer: "¿Qué hacemos con este hallazgo?",
		reemplazar: "Reemplazar por placeholder",
		eliminar: "Eliminar el archivo",
		falso: "Falso positivo (pide motivo)",
		aceptar: "Aceptar el riesgo (pide motivo)",
		abortar: "Abortar la revisión",
		nombre: "Nombre del placeholder (MAYÚSCULAS_Y_GUION_BAJO)",
		nombreMal: "Usa mayúsculas, números y guion bajo; empieza con una letra.",
		motivo: "Motivo (mínimo 10 caracteres)",
		motivoMal: "El motivo debe tener al menos 10 caracteres.",
		auto: (n: number) =>
			`Se aplicarán ${n} reemplazos sugeridos. ¿Confirmas el resumen?`,
		lote: (regla: string, dir: string) =>
			`¿Usar la misma decisión y motivo para los demás hallazgos ${regla} en ${dir}/?`,
		enLote: "↳ misma decisión que el anterior (lote confirmado)",
	},
	en: {
		initDesc: "copy the source into a working workspace",
		scanDesc: "look for secrets, PII and dictionary terms",
		sanitizeDesc: "review the findings and sign the approval",
		destFlag: "folder that will hold .mct/",
		typeFlag: "project type",
		forceFlag: "recreate the workspace (asks for confirmation)",
		autoFlag: "apply the suggested replacements (still asks to confirm)",
		reopenFlag: "send a decided finding back to open",
		initOk: (adapter: string, conf: number, n: number) =>
			`Workspace ready · ${adapter} adapter (confidence ${conf}) · ${n} files`,
		scanVacio: "0 findings in both engines. Next: mct licenses",
		scanCerrada: (n: number) =>
			`Gate closed: ${n} open findings. Run: mct sanitize`,
		sanVacio: (h: string) =>
			`No findings to review. Approval signed (sha256 …${h}). Next: mct licenses`,
		sanOk: (h: string) =>
			`0 open findings · approval signed (sha256 …${h}). Next: mct licenses`,
		sanSinTty:
			"Finding review needs an interactive terminal, or a file with --decisiones or --auto-fixtures --confirmo. Nothing is auto-approved.",
		sanSinTtyAccion: "Run mct sanitize from a terminal",
		decisionesFlag: "apply decisions from a JSON (false-positive or replace)",
		autoFixturesFlag: "mark test data in test paths as false positives",
		dryRunFlag:
			"with --auto-fixtures: only list the candidates and their sha256",
		confirmoFlag: "with --auto-fixtures: sha256 of the list you already saw",
		autoSolo: (f: string) => `${f} is only used together with --auto-fixtures`,
		dryRunConfirmo:
			"--dry-run cannot be combined with --confirmo or --decisiones",
		autoPregunta: (n: number, grupos: string) =>
			`Found ${n} test values in test paths (${grupos}). Mark them as false positives?`,
		autoAplicado: (n: number, h: string, q: number) =>
			`${n} findings marked as test data (auto-fixtures, sha256 …${h}). ${q} still open.`,
		decAplicadas: (n: number, h: string, q: number) =>
			`Applied ${n} decisions from decisiones.json (sha256 …${h}). ${q} still open.`,
		autoListo: (n: number, h: string) =>
			`${n} auto-fixtures candidates (sha256 …${h}). Nothing was applied. To apply: mct sanitize --auto-fixtures --confirmo <sha256>`,
		destInvalido:
			"Without --dest, --workspace must end in .mct so the workspace location is known.",
		sync: (nombre: string, ruta: string) =>
			`The workspace would be inside ${nombre} (${ruta}). The copy with client data would be uploaded to the cloud. Continue anyway? To avoid it use: mct init <source> --dest <local folder>`,
		force: (perdidas: string) =>
			`This deletes the current workspace: ${perdidas}. Recreate from scratch?`,
		hallazgo: (h: Finding) =>
			`${h.archivo}:${h.linea} · ${h.regla} · ${h.severidad} · ${h.fragmento}`,
		queHacer: "What should we do with this finding?",
		reemplazar: "Replace with a placeholder",
		eliminar: "Delete the file",
		falso: "False positive (asks for a reason)",
		aceptar: "Accept the risk (asks for a reason)",
		abortar: "Abort the review",
		nombre: "Placeholder name (UPPER_CASE_WITH_UNDERSCORES)",
		nombreMal: "Use capitals, digits and underscore; start with a letter.",
		motivo: "Reason (at least 10 characters)",
		motivoMal: "The reason must have at least 10 characters.",
		auto: (n: number) =>
			`${n} suggested replacements will be applied. Do you confirm the summary?`,
		lote: (regla: string, dir: string) =>
			`Use the same decision and reason for the other ${regla} findings in ${dir}/?`,
		enLote: "↳ same decision as before (batch confirmed)",
	},
} as const;

/** `--type` values of `init` and `run` (DET-001). */
export const TIPOS = [
	"auto",
	"n8n",
	"node",
	"python",
	"estatico",
	"generico",
] as const;

const MOTIVO_MIN = 10;
const MOTIVO_MAX = 500;
const PLACEHOLDER = /^[A-Z][A-Z0-9_]{0,63}$/;

// ---------------------------------------------------------------- scan engine

function maskPath(salt: string): string {
	return `[ruta:${createHash("sha256").update(salt).digest("hex").slice(0, 12)}]`;
}

/**
 * Fresh scan of the current tree for the re-scan inside `sanitize` (no previous
 * findings: core reconciles). Same engines and masking as the scan stage; any
 * failure propagates (fail closed, never an empty result).
 */
function makeRescan(
	raiz: string,
	adapter: Adapter,
	home: string,
	lang: Lang,
): (ctx: { signal?: AbortSignal }) => Promise<RescanResult> {
	return async (rc) => {
		if (rc.signal?.aborted) throw interrumpido(lang);
		const ws = workspacePaths(raiz);
		const antes = await hashTree(ws.work);
		const terms = await loadDictionary(defaultDictionaryPath(home));
		const rules: readonly Rule[] = adapter.rules();
		const sensitive = (t: string): boolean =>
			t.length > 0 &&
			(detectDictionary(t, terms).length > 0 ||
				detectSecrets(t).length > 0 ||
				detectPii(t).length > 0 ||
				rules.some((r) => new RegExp(r.patron.source, r.patron.flags).test(t)));
		const registryIssues = await findRegistryIssues(ws);
		const result = await scan({
			work: ws.work,
			quarantine: ws.quarantine,
			rules,
			dictionary: terms,
			registryIssues,
			gitleaks: {
				installDir: join(home, ".mct", "bin"),
				tmpDir: join(raiz, "tmp"),
				...deps.gitleaks,
			},
		});
		if (rc.signal?.aborted) throw interrumpido(lang);
		// The approval must cover exactly the tree the engines saw (like stageScan).
		if ((await hashTree(ws.work)) !== antes) {
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"work/ cambió durante el re-scan; no se firma un árbol sin escanear",
				{ accion: "mct sanitize", etapa: "sanitize" },
			);
		}
		return {
			hallazgos: result.hallazgos.map((f) =>
				sensitive(f.archivo) ? { ...f, archivo: maskPath(f.id) } : f,
			),
			gitleaksVersion: result.gitleaksVersion,
		};
	};
}

// ------------------------------------------------------------------- decisor

async function askMotivo(
	ctx: CliContext,
	t: (typeof TEXT)[Lang],
): Promise<string | null> {
	for (;;) {
		const answer = await deps.prompter.text({
			message: t.motivo,
			validate: (v) =>
				v.trim().length >= MOTIVO_MIN && v.trim().length <= MOTIVO_MAX
					? undefined
					: t.motivoMal,
		});
		if (answer === null) return null;
		const motivo = answer.trim();
		if (motivo.length >= MOTIVO_MIN && motivo.length <= MOTIVO_MAX) {
			return motivo;
		}
		ctx.info(t.motivoMal);
	}
}

async function askNombre(
	ctx: CliContext,
	t: (typeof TEXT)[Lang],
	sugerido: string,
): Promise<string | null> {
	for (;;) {
		const answer = await deps.prompter.text({
			message: t.nombre,
			initialValue: sugerido,
			validate: (v) => (PLACEHOLDER.test(v.trim()) ? undefined : t.nombreMal),
		});
		if (answer === null) return null;
		const nombre = answer.trim();
		if (PLACEHOLDER.test(nombre)) return nombre;
		ctx.info(t.nombreMal);
	}
}

/**
 * core has no signal option for scan, so the CLI fails the stage before it
 * writes anything: the engine runner refuses to hand back a result once the
 * signal fired.
 */
function abortableRunner(base: Runner | undefined, ctx: CliContext): Runner {
	const run = base ?? defaultRunner;
	return async (command, args, options) => {
		if (ctx.signal.aborted) throw interrumpido(ctx.lang);
		const result = await run(command, args, options);
		if (ctx.signal.aborted) throw interrumpido(ctx.lang);
		return result;
	};
}

function initInterrumpido(lang: Lang): MctError {
	return new MctError(
		"INTERRUMPIDO",
		lang === "en"
			? "Init interrupted. Nothing was changed."
			: "Init interrumpido. No se cambió nada.",
	);
}

function interrumpido(lang: Lang): MctError {
	return new MctError(
		"INTERRUMPIDO",
		lang === "en"
			? "Review interrupted. The workspace is as it was before mct sanitize; no change was applied."
			: "Revisión interrumpida. El workspace quedó como antes de mct sanitize; no se aplicó ningún cambio.",
		{
			accion:
				lang === "en"
					? "Run mct sanitize again when ready."
					: "Repite mct sanitize cuando quieras.",
			etapa: "sanitize",
		},
	);
}

const ABORTAR: Decision = { accion: "abortar" };

/** SAN-011: a batch only spans one rule in one folder, and only after an explicit yes. */
function loteKey(h: Finding): string {
	return JSON.stringify([h.regla, dirname(h.archivo)]);
}

function makeDecisor(ctx: CliContext): Decisor {
	const t = TEXT[ctx.lang];
	const lotes = new Map<string, Decision>();
	return {
		async decidir(hallazgo, dc) {
			ctx.info(t.hallazgo(hallazgo));
			const enLote = lotes.get(loteKey(hallazgo));
			if (enLote !== undefined) {
				ctx.info(t.enLote);
				return enLote;
			}
			const options: SelectOption<
				"reemplazar" | "falso-positivo" | "aceptar" | "abortar"
			>[] = [];
			if (dc.puedeReemplazar) {
				options.push({
					value: "reemplazar",
					label: dc.eliminar ? t.eliminar : t.reemplazar,
				});
			}
			options.push(
				{ value: "falso-positivo", label: t.falso },
				{ value: "aceptar", label: t.aceptar },
				{ value: "abortar", label: t.abortar },
			);
			const eleccion = await deps.prompter.select({
				message: t.queHacer,
				options,
			});
			if (eleccion === null) throw interrumpido(ctx.lang);
			if (eleccion === "abortar") return ABORTAR;
			if (eleccion === "reemplazar") {
				if (dc.eliminar) return { accion: "reemplazar" };
				const nombre = await askNombre(ctx, t, dc.sugerido);
				if (nombre === null) throw interrumpido(ctx.lang);
				return { accion: "reemplazar", nombre };
			}
			const motivo = await askMotivo(ctx, t);
			if (motivo === null) throw interrumpido(ctx.lang);
			const decision: Decision = { accion: eleccion, motivo };
			const lote = await deps.prompter.confirm({
				message: t.lote(hallazgo.regla, dirname(hallazgo.archivo)),
				initialValue: false,
			});
			if (lote === null) throw interrumpido(ctx.lang);
			if (lote === true) lotes.set(loteKey(hallazgo), decision);
			return decision;
		},
		async confirmar(resumen) {
			const answer = await deps.prompter.confirm({
				message: t.auto(resumen.reemplazos.length),
				initialValue: false,
			});
			if (answer === null) throw interrumpido(ctx.lang);
			return answer === true;
		},
	};
}

// ------------------------------------------------------------------ commands

export function register(program: Command): void {
	program
		.command("init")
		.description(TEXT.es.initDesc)
		.argument(
			"<origen>",
			"folder, https://github.com/<owner>/<repo> or n8n .json",
		)
		.option("--dest <dir>", TEXT.es.destFlag)
		.option("--type <type>", TEXT.es.typeFlag, "auto")
		.option("--force", TEXT.es.forceFlag)
		.action(
			async (
				origen: string,
				opts: { dest?: string; type?: string; force?: boolean },
			) => {
				const ctx = contextOf(program);
				const t = TEXT[ctx.lang];
				if (
					opts.type === undefined ||
					!(TIPOS as readonly string[]).includes(opts.type)
				) {
					throw new MctError(
						"VALIDACION",
						"--type debe ser n8n, node, python, estatico, generico o auto",
					);
				}
				let dest = opts.dest;
				if (dest === undefined) {
					const ws = resolve(ctx.workspace);
					if (basename(ws) !== ".mct") {
						throw new MctError("VALIDACION", t.destInvalido);
					}
					dest = dirname(ws);
				}
				if (ctx.signal.aborted) throw interrumpido(ctx.lang);
				// Awaited even after Ctrl+C: core removes the partial workspace first.
				const result = await initFromSource({
					signal: ctx.signal,
					origen,
					dest,
					type: opts.type as (typeof TIPOS)[number],
					force: opts.force === true,
					isTTY: ctx.interactive,
					lang: ctx.lang,
					mctVersion: pkg.version,
					env: { ...process.env, ...ctx.io.env },
					...(deps.home === undefined ? {} : { home: deps.home }),
					confirmar: async (info) => {
						if (ctx.signal.aborted) throw interrumpido(ctx.lang);
						const answer = await deps.prompter.confirm({
							message: t.sync(info.nombre, info.ruta),
							initialValue: false,
						});
						if (answer === null) throw initInterrumpido(ctx.lang);
						return answer === true;
					},
					confirmarForce: async (info) => {
						if (ctx.signal.aborted) throw interrumpido(ctx.lang);
						const answer = await deps.prompter.confirm({
							message: t.force(info.perdidas.join(", ")),
							initialValue: false,
						});
						if (answer === null) throw initInterrumpido(ctx.lang);
						return answer === true;
					},
				});
				for (const aviso of result.avisos) {
					ctx.info(
						aviso.accion === undefined
							? aviso.mensaje
							: `${aviso.mensaje} ${aviso.accion}`,
					);
				}
				ctx.result(
					{
						workspace: result.workspace.raiz,
						adapter: result.adapter,
						confianza: Math.round(result.confianza * 100) / 100,
						archivos: result.archivos,
					},
					t.initOk(
						result.adapter,
						Math.round(result.confianza * 100) / 100,
						result.archivos,
					),
				);
			},
		);

	program
		.command("scan")
		.description(TEXT.es.scanDesc)
		.action(async () => {
			const ctx = contextOf(program);
			const t = TEXT[ctx.lang];
			const raiz = resolve(ctx.workspace);
			try {
				if (ctx.signal.aborted) throw interrumpido(ctx.lang);
				const r = await stageScan(raiz, {
					lang: ctx.lang,
					mctVersion: pkg.version,
					gitleaks: {
						...deps.gitleaks,
						run: abortableRunner(deps.gitleaks.run, ctx),
					},
					...(deps.home === undefined ? {} : { home: deps.home }),
				});
				ctx.result(
					{
						hallazgos: r.hallazgos,
						hallazgosAbiertos: [],
						analysis: r.analysis,
						gitleaksVersion: r.gitleaksVersion,
					},
					t.scanVacio,
				);
			} catch (error) {
				if (error instanceof MctError && error.codigo === "PUERTA_BLOQUEADA") {
					const n = Number(
						(error.detalle as { abiertos?: unknown } | undefined)?.abiertos,
					);
					// SAN-013: the open findings travel in error.detalle (never the aislados).
					const lista = await hallazgosAbiertos(raiz);
					throw new MctError(
						"PUERTA_BLOQUEADA",
						Number.isFinite(n) ? t.scanCerrada(n) : error.message,
						{
							accion: "mct sanitize",
							etapa: "scan",
							detalle: {
								...((error.detalle as Record<string, unknown> | undefined) ??
									{}),
								hallazgosAbiertos: lista,
							},
						},
					);
				}
				throw error;
			}
		});

	program
		.command("sanitize")
		.description(TEXT.es.sanitizeDesc)
		.option("--auto-placeholders", TEXT.es.autoFlag)
		.option("--reopen <id>", TEXT.es.reopenFlag)
		.option("--decisiones <archivo>", TEXT.es.decisionesFlag)
		.option("--auto-fixtures", TEXT.es.autoFixturesFlag)
		.option("--dry-run", TEXT.es.dryRunFlag)
		.option("--confirmo <sha256>", TEXT.es.confirmoFlag)
		.action(
			async (opts: {
				autoPlaceholders?: boolean;
				reopen?: string;
				decisiones?: string;
				autoFixtures?: boolean;
				dryRun?: boolean;
				confirmo?: string;
			}) => {
				const ctx = contextOf(program);
				const t = TEXT[ctx.lang];
				const raiz = resolve(ctx.workspace);
				if (opts.autoFixtures !== true) {
					if (opts.dryRun === true) {
						throw new MctError("VALIDACION", t.autoSolo("--dry-run"));
					}
					if (opts.confirmo !== undefined) {
						throw new MctError("VALIDACION", t.autoSolo("--confirmo"));
					}
				}
				if (
					opts.dryRun === true &&
					(opts.confirmo !== undefined || opts.decisiones !== undefined)
				) {
					throw new MctError("VALIDACION", t.dryRunConfirmo);
				}
				const state = await readState(raiz);
				const adapter = adapterById(state.adapter);
				if (adapter === undefined) {
					throw new MctError(
						"WORKSPACE_INVALIDO",
						"El adaptador del workspace no existe",
						{ accion: "mct init <origen> --force" },
					);
				}
				const home = deps.home ?? homedir();
				const tty = ctx.interactive || deps.decisor !== undefined;
				const base = {
					raiz,
					tty,
					signal: ctx.signal,
					decisor: deps.decisor ?? makeDecisor(ctx),
					rescan: makeRescan(raiz, adapter, home, ctx.lang),
					adapter,
					mctVersion: pkg.version,
					lang: ctx.lang,
					terminos: await loadDictionary(defaultDictionaryPath(home)),
				};
				if (opts.dryRun === true) {
					const lista = await autoFixturesLista({
						...base,
						autoFixtures: {},
					});
					ctx.result(
						{ candidatos: lista.candidatos, sha256: lista.sha256 },
						t.autoListo(lista.candidatos.length, lista.sha256.slice(-4)),
					);
					return;
				}
				let result: Awaited<ReturnType<typeof sanitize>>;
				try {
					result = await sanitize({
						...base,
						...(opts.autoPlaceholders === true && { autoPlaceholders: true }),
						...(opts.reopen === undefined ? {} : { reopen: opts.reopen }),
						...(opts.decisiones === undefined
							? {}
							: { decisiones: resolve(opts.decisiones) }),
						...(opts.autoFixtures === true && {
							autoFixtures: {
								...(opts.confirmo === undefined
									? {}
									: { confirmo: opts.confirmo }),
								confirmar: async (lista: ListaAuto) => {
									const answer = await deps.prompter.confirm({
										message: t.autoPregunta(
											lista.candidatos.length,
											resumenAuto(lista),
										),
										initialValue: false,
									});
									if (answer === null) throw interrumpido(ctx.lang);
									return answer === true;
								},
							},
						}),
					});
				} catch (error) {
					// SAN-004: without a terminal the gate stays closed; say what would open it.
					if (
						error instanceof MctError &&
						error.codigo === "PUERTA_BLOQUEADA" &&
						!tty
					) {
						throw new MctError("PUERTA_BLOQUEADA", t.sanSinTty, {
							accion: t.sanSinTtyAccion,
							etapa: "sanitize",
							...(error.detalle === undefined
								? {}
								: { detalle: error.detalle }),
						});
					}
					throw error;
				}
				const hash = result.aprobacion?.arbolSha256.slice(-4) ?? "";
				const decididos =
					result.decididos.resuelto +
					result.decididos.falsoPositivo +
					result.decididos.aceptado;
				if (opts.autoFixtures === true && result.porVia.autoFixtures > 0) {
					ctx.info(
						t.autoAplicado(
							result.porVia.autoFixtures,
							(opts.confirmo ?? "").slice(-4),
							result.abiertos,
						),
					);
				}
				if (opts.decisiones !== undefined && result.porVia.archivo > 0) {
					const sha = await readFile(opts.decisiones)
						.then((b) => createHash("sha256").update(b).digest("hex"))
						.catch(() => "");
					ctx.info(
						t.decAplicadas(
							result.porVia.archivo,
							sha.slice(-4),
							result.abiertos,
						),
					);
				}
				ctx.result(result, decididos === 0 ? t.sanVacio(hash) : t.sanOk(hash));
			},
		);
}

/** "tests/x.py: 8 pii-email · ..." (rule and path only, never a value). */
function resumenAuto(lista: ListaAuto): string {
	const cuenta = new Map<string, number>();
	for (const c of lista.candidatos) {
		const k = `${c.archivo}: ${c.regla}`;
		cuenta.set(k, (cuenta.get(k) ?? 0) + 1);
	}
	return [...cuenta].map(([k, n]) => `${k} x${n}`).join(" · ");
}
