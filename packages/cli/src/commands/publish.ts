import { resolve } from "node:path";
import { confirm, isCancel, text } from "@clack/prompts";
import { MctError } from "@mct/contract/errors";
import { type CleanResult, cleanWorkspace } from "@mct/core/clean";
import { createGithubClient, type GithubClient } from "@mct/core/github";
import {
	type PublishOptions,
	type PublishResult,
	publish,
} from "@mct/core/publish";
import type { Command } from "commander";
import { type CliContext, contextOf, type Lang } from "../output.js";

// ------------------------------------------------------------------ deps

/** Prompt boundary: both methods return `null` when the person cancels (Esc / Ctrl+C). */
export interface PublishPrompter {
	text(o: { message: string }): Promise<string | null>;
	confirm(o: {
		message: string;
		initialValue: boolean;
	}): Promise<boolean | null>;
}

export interface PublishDeps {
	prompter: PublishPrompter;
	createClient: (o: {
		lang: Lang;
		env: Record<string, string | undefined>;
	}) => Promise<GithubClient>;
	publish: (o: PublishOptions) => Promise<PublishResult>;
	clean: (o: {
		raiz: string;
		force: true;
		isTTY: true;
		lang: Lang;
	}) => Promise<CleanResult>;
}

const clackPrompter: PublishPrompter = {
	async text(o) {
		const answer = await text({ message: o.message });
		// Enter on an empty prompt can yield undefined: that is a mismatch, not a crash.
		return isCancel(answer) ? null : (answer ?? "");
	},
	async confirm(o) {
		const answer = await confirm({
			message: o.message,
			initialValue: o.initialValue,
		});
		return isCancel(answer) ? null : answer;
	},
};

const DEFAULT_DEPS: PublishDeps = {
	prompter: clackPrompter,
	createClient: (o) => createGithubClient(o),
	publish,
	clean: (o) => cleanWorkspace(o),
};

let deps: PublishDeps = DEFAULT_DEPS;

/** Tests swap the prompts and GitHub; returns the function that restores the defaults. */
export function overridePublishDeps(partial: Partial<PublishDeps>): () => void {
	const previous = deps;
	deps = { ...DEFAULT_DEPS, ...partial };
	return () => {
		deps = previous;
	};
}

// ------------------------------------------------------------------ text

const TEXT = {
	es: {
		desc: "publica dist/ en un repo nuevo de GitHub (privado primero, con confirmaciones)",
		repo: "repo de destino owner/nombre",
		privado: "deja el repo privado (no pide hacerlo público)",
		dryRun: "hace todas las comprobaciones sin escribir en GitHub",
		resume: "retoma un publish que este workspace dejó a medias",
		sinRepo: "Falta --repo <owner/nombre>",
		accionRepo: "Corre: mct publish --repo <owner/nombre>",
		sinTty:
			"publish necesita una terminal interactiva para confirmar. No se publicó nada.",
		accionTty: "Corre mct publish en una terminal, o usa --dry-run",
		cancelado: "No se publicó nada.",
		accionCancel: "Vuelve a correr mct publish cuando quieras publicar",
		noCoincide: (repo: string) =>
			`El nombre escrito no es ${repo}. No se publicó nada.`,
		resumen: (url: string, privado: boolean) =>
			`Puertas pasadas. Se creará ${url} privado con un único commit desde dist/` +
			(privado
				? "; quedará privado (--private)."
				: "; después del escaneo remoto se pedirá hacerlo público."),
		confirmar: (repo: string) =>
			`Escribe el nombre del repo para confirmar (${repo})`,
		publico: "¿Hacerlo público ahora?",
		borrar: (ws: string) =>
			`¿Borrar el workspace ${ws} con la copia de trabajo?`,
		borrado: (ws: string, n: number) =>
			`Workspace borrado: ${ws} (${n} archivos)`,
		conservado: (ws: string) => `El workspace sigue en ${ws}`,
		dryRunHecho: (url: string) =>
			`--dry-run: todas las comprobaciones pasaron. No se escribió nada en GitHub (${url}).`,
		hecho: (r: PublishResult) =>
			r.visibilidad === "publico"
				? `Público · release ${r.tag} · ${r.url}`
				: `Privado · release ${r.tag} · ${r.url}`,
		interrumpido: "Interrumpido por la persona (Ctrl+C)",
	},
	en: {
		desc: "publish dist/ to a new GitHub repo (private first, with confirmations)",
		repo: "target repo owner/name",
		privado: "keep the repo private (does not ask to make it public)",
		dryRun: "run every check without writing to GitHub",
		resume: "resume a publish this workspace left half done",
		sinRepo: "Missing --repo <owner/name>",
		accionRepo: "Run: mct publish --repo <owner/name>",
		sinTty:
			"publish needs an interactive terminal to confirm. Nothing was published.",
		accionTty: "Run mct publish in a terminal, or use --dry-run",
		cancelado: "Nothing was published.",
		accionCancel: "Run mct publish again when you want to publish",
		noCoincide: (repo: string) =>
			`The typed name is not ${repo}. Nothing was published.`,
		resumen: (url: string, privado: boolean) =>
			`Gates passed. ${url} will be created private with a single commit from dist/` +
			(privado
				? "; it will stay private (--private)."
				: "; after the remote scan you will be asked to make it public."),
		confirmar: (repo: string) => `Type the repo name to confirm (${repo})`,
		publico: "Make it public now?",
		borrar: (ws: string) => `Delete the ${ws} workspace with the working copy?`,
		borrado: (ws: string, n: number) => `Workspace deleted: ${ws} (${n} files)`,
		conservado: (ws: string) => `The workspace is still at ${ws}`,
		dryRunHecho: (url: string) =>
			`--dry-run: every check passed. Nothing was written to GitHub (${url}).`,
		hecho: (r: PublishResult) =>
			r.visibilidad === "publico"
				? `Public · release ${r.tag} · ${r.url}`
				: `Private · release ${r.tag} · ${r.url}`,
		interrumpido: "Interrupted (Ctrl+C)",
	},
} as const;

type Text = (typeof TEXT)[Lang];

function cancelado(t: Text, mensaje: string = t.cancelado): MctError {
	return new MctError("CANCELADO", mensaje, {
		etapa: "publish",
		accion: t.accionCancel,
	});
}

function stopIfAborted(ctx: CliContext, t: Text): void {
	if (ctx.signal.aborted) {
		throw new MctError("INTERRUMPIDO", t.interrumpido, { etapa: "publish" });
	}
}

// ------------------------------------------------------------------ command

interface PublishFlags {
	repo?: string;
	private?: boolean;
	dryRun?: boolean;
	resume?: boolean;
}

/**
 * PUB-002, CLI-008. There is no `--yes`: a real publish always needs a TTY, the exact
 * `owner/name` typed by the person, a second confirmation before going public, and ends
 * asking whether to delete the workspace (No by default). `--dry-run` needs no TTY.
 */
export function register(program: Command): void {
	program
		.command("publish")
		.description(TEXT.es.desc)
		.option("--repo <owner/nombre>", TEXT.es.repo)
		.option("--private", TEXT.es.privado)
		.option("--dry-run", TEXT.es.dryRun)
		.option("--resume", TEXT.es.resume)
		.action(async (flags: PublishFlags) => {
			const ctx = contextOf(program);
			const t = TEXT[ctx.lang];
			const repo = flags.repo;
			if (repo === undefined || repo === "") {
				throw new MctError("VALIDACION", t.sinRepo, {
					etapa: "publish",
					accion: t.accionRepo,
				});
			}
			const dryRun = flags.dryRun === true;
			const privado = flags.private === true;
			// No TTY (or --json) means nobody can type the name: nothing is called.
			if (!dryRun && !ctx.interactive) {
				throw new MctError("CANCELADO", t.sinTty, {
					etapa: "publish",
					accion: t.accionTty,
				});
			}
			stopIfAborted(ctx, t);
			const raiz = resolve(ctx.workspace);
			const env = { ...process.env, ...ctx.io.env };
			const client = await deps.createClient({ lang: ctx.lang, env });
			const base: PublishOptions = {
				raiz,
				repo,
				client,
				lang: ctx.lang,
				env,
				...(privado && { privado: true }),
				...(flags.resume === true && { resume: true }),
				// The dry run below never reaches this step.
				confirmarPublico: async () => false,
			};

			// Every check (gates, hashes, token permissions, repo absent) runs before asking.
			const checked = await deps.publish({ ...base, dryRun: true });
			if (dryRun) {
				ctx.result(checked, t.dryRunHecho(checked.url));
				return;
			}
			ctx.info(t.resumen(checked.url, privado));

			stopIfAborted(ctx, t);
			const typed = await deps.prompter.text({ message: t.confirmar(repo) });
			if (typed === null) throw cancelado(t);
			if (typed !== repo) throw cancelado(t, t.noCoincide(repo));

			stopIfAborted(ctx, t);
			const result = await deps.publish({
				...base,
				confirmarPublico: async () => {
					stopIfAborted(ctx, t);
					const answer = await deps.prompter.confirm({
						message: t.publico,
						initialValue: false,
					});
					return answer === true;
				},
			});
			ctx.info(t.hecho(result));

			stopIfAborted(ctx, t);
			// CLI-008: deleting the workspace is opt-in; Esc and Enter both keep it.
			const borrar = await deps.prompter.confirm({
				message: t.borrar(ctx.workspace),
				initialValue: false,
			});
			if (borrar === true) {
				const limpio = await deps.clean({
					raiz,
					force: true,
					isTTY: true,
					lang: ctx.lang,
				});
				ctx.info(t.borrado(limpio.borrado, limpio.archivos));
			} else {
				ctx.info(t.conservado(ctx.workspace));
			}
			ctx.result(
				{ url: result.url, visibilidad: result.visibilidad, tag: result.tag },
				undefined,
			);
		});
}
