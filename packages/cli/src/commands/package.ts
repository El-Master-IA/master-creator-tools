import { dirname, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import { loadConfig } from "@mct/core/config";
import { stagePackage } from "@mct/core/package";
import type { Command } from "commander";
import { type CliContext, contextOf } from "../output.js";

const TEXT = {
	es: {
		desc: "genera dist/ desde work/, lo generaliza y lo re-escanea",
		holder: "titular del copyright de LICENSE",
		year: "año del copyright (cuatro dígitos)",
		sinTitular:
			"Falta el titular del copyright. Usa --holder o define holder en mct.config.json",
		anioInvalido: "El año debe tener cuatro dígitos",
		hecho: (dist: string, n: number) =>
			`dist/ listo en ${dist} (${n} archivos)`,
	},
	en: {
		desc: "build dist/ from work/, generalize it and re-scan it",
		holder: "copyright holder for LICENSE",
		year: "copyright year (four digits)",
		sinTitular:
			"The copyright holder is missing. Use --holder or set holder in mct.config.json",
		anioInvalido: "The year must have four digits",
		hecho: (dist: string, n: number) => `dist/ ready at ${dist} (${n} files)`,
	},
} as const;

function parseYear(raw: string, mensaje: string): number {
	if (!/^\d{4}$/.test(raw)) throw new MctError("VALIDACION", mensaje);
	return Number.parseInt(raw, 10);
}

export function register(program: Command): void {
	program
		.command("package")
		.description(TEXT.es.desc)
		.option("--holder <nombre>", TEXT.es.holder)
		.option("--year <aaaa>", TEXT.es.year)
		.action(async (opts: { holder?: string; year?: string }) => {
			const ctx: CliContext = contextOf(program);
			const t = TEXT[ctx.lang];
			const raiz = resolve(ctx.workspace);
			// The config lives next to the workspace, not inside it (datos.md).
			const config = await loadConfig(dirname(raiz));
			const holder = opts.holder ?? config.holder;
			if (holder === undefined || holder.trim() === "") {
				throw new MctError("VALIDACION", t.sinTitular);
			}
			const year =
				opts.year !== undefined
					? parseYear(opts.year, t.anioInvalido)
					: (config.year ?? new Date().getFullYear());
			const result = await stagePackage(raiz, {
				holder,
				year,
				...(config.readme !== undefined && { readme: config.readme }),
			});
			ctx.result(result, t.hecho(result.dist, result.archivos));
		});
}
