import { resolve } from "node:path";
import { cancel, confirm, isCancel } from "@clack/prompts";
import { cleanWorkspace } from "@mct/core/clean";
import type { Command } from "commander";
import { type CliContext, contextOf } from "../output.js";

const TEXT = {
	es: {
		desc: "borra el workspace completo, incluida la cuarentena",
		force: "borra sin pedir confirmación (para scripts)",
		pregunta: (ruta: string, n: number) =>
			`Se borrará ${ruta} con ${n} archivos (incluida quarantine/). ¿Continuar?`,
		hecho: (ruta: string, n: number) => `Borrado ${ruta} (${n} archivos)`,
		cancelado: "Cancelado",
	},
	en: {
		desc: "delete the whole workspace, quarantine included",
		force: "delete without asking (for scripts)",
		pregunta: (ruta: string, n: number) =>
			`This will delete ${ruta} with ${n} files (including quarantine/). Continue?`,
		hecho: (ruta: string, n: number) => `Deleted ${ruta} (${n} files)`,
		cancelado: "Cancelled",
	},
} as const;

export function register(program: Command): void {
	program
		.command("clean")
		.description(TEXT.es.desc)
		.option("--force", TEXT.es.force)
		.action(async (opts: { force?: boolean }) => {
			const ctx: CliContext = contextOf(program);
			const t = TEXT[ctx.lang];
			const isTTY = ctx.io.stdinIsTTY && !ctx.json;
			const result = await cleanWorkspace({
				raiz: resolve(ctx.workspace),
				force: opts.force === true,
				isTTY,
				lang: ctx.lang,
				confirmar: async (info) => {
					const answer = await confirm({
						message: t.pregunta(info.ruta, info.archivos),
						initialValue: false,
					});
					if (isCancel(answer)) {
						cancel(t.cancelado);
						return false;
					}
					return answer === true;
				},
			});
			ctx.result(result, t.hecho(result.borrado, result.archivos));
		});
}
