import { dirname, resolve } from "node:path";
import { loadConfig } from "@mct/core/config";
import { resolveDocker } from "@mct/core/docker";
import { stageVerify } from "@mct/core/verify";
import type { Command } from "commander";
import { type CliContext, contextOf } from "../output.js";

const TEXT = {
	es: {
		desc: "instala y arranca dist/ en un contenedor limpio y sin red",
		remote: "usa este alias de ~/.ssh/config como host de Docker",
		local: "usa solo Docker local",
		hecho: (destino: string, tipo: string, ms: number) =>
			`verify pasó en ${destino} (${tipo}, ${Math.round(ms / 1000)} s)`,
	},
	en: {
		desc: "install and start dist/ in a clean container without network",
		remote: "use this alias from ~/.ssh/config as the Docker host",
		local: "use local Docker only",
		hecho: (destino: string, tipo: string, ms: number) =>
			`verify passed on ${destino} (${tipo}, ${Math.round(ms / 1000)} s)`,
	},
} as const;

export function register(program: Command): void {
	program
		.command("verify")
		.description(TEXT.es.desc)
		.option("--remote <alias>", TEXT.es.remote)
		.option("--local", TEXT.es.local)
		.action(async (opts: { remote?: string; local?: boolean }) => {
			const ctx: CliContext = contextOf(program);
			const t = TEXT[ctx.lang];
			const raiz = resolve(ctx.workspace);
			// The config lives next to the workspace, not inside it (datos.md).
			const config = await loadConfig(dirname(raiz));
			const target = await resolveDocker({
				lang: ctx.lang,
				...(opts.remote !== undefined && { remote: opts.remote }),
				...(opts.local === true && { local: true }),
				...(config.verify?.remoto !== undefined && {
					configRemote: config.verify.remoto,
				}),
			});
			const result = await stageVerify(raiz, {
				target,
				lang: ctx.lang,
				signal: ctx.signal,
				...(config.verify?.timeoutMin !== undefined && {
					configTimeoutMin: config.verify.timeoutMin,
				}),
			});
			ctx.result(
				result,
				t.hecho(result.destino, result.healthcheck.tipo, result.healthcheck.ms),
			);
		});
}
