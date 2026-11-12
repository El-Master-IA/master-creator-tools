import { dirname, resolve } from "node:path";
import { loadConfig } from "@mct/core/config";
import { resolveDocker } from "@mct/core/docker";
import { stageVerify, type VerifyResult } from "@mct/core/verify";
import type { Command } from "commander";
import { type CliContext, contextOf, type Lang } from "../output.js";

const TEXT = {
	es: {
		desc: "instala y arranca dist/ en un contenedor limpio y sin red",
		remote: "usa este alias de ~/.ssh/config como host de Docker",
		local: "usa solo Docker local",
		hecho: (destino: string, tipo: string, ms: number) =>
			`verify pasó en ${destino} (${tipo}, ${Math.round(ms / 1000)} s)`,
		omitido: "verify quedó omitido: no se arrancó ningún contenedor",
		aviso: "Aviso",
	},
	en: {
		desc: "install and start dist/ in a clean container without network",
		remote: "use this alias from ~/.ssh/config as the Docker host",
		local: "use local Docker only",
		hecho: (destino: string, tipo: string, ms: number) =>
			`verify passed on ${destino} (${tipo}, ${Math.round(ms / 1000)} s)`,
		omitido: "verify was skipped: no container was started",
		aviso: "Warning",
	},
} as const;

/** EXPERIENCE.md › textos de aviso del verify. */
const AVISOS: Record<string, Record<Lang, string>> = {
	"verify.omitido": {
		es: "Este proyecto no se probó en un contenedor",
		en: "This project was not tested in a container",
	},
	"verify.poetrySinLock": {
		es: "poetry.lock no se respeta en verify",
		en: "poetry.lock is not honored in verify",
	},
	"verify.pipCheck": {
		es: "pip check falló; en modo compilar no bloquea",
		en: "pip check failed; in compile mode it does not block",
	},
};

/** The text of a notice key; an unknown key is shown as it is. */
export function avisoText(key: string, lang: Lang): string {
	return AVISOS[key]?.[lang] ?? key;
}

/** The terminal summary of a passed verify, with one line per notice. */
export function humanSummary(result: VerifyResult, lang: Lang): string {
	const t = TEXT[lang];
	const head =
		result.healthcheck.tipo === "omitido"
			? t.omitido
			: t.hecho(result.destino, result.healthcheck.tipo, result.healthcheck.ms);
	return [
		head,
		...result.avisos.map((a) => `${t.aviso}: ${avisoText(a, lang)}`),
	].join("\n");
}

export function register(program: Command): void {
	program
		.command("verify")
		.description(TEXT.es.desc)
		.option("--remote <alias>", TEXT.es.remote)
		.option("--local", TEXT.es.local)
		.action(async (opts: { remote?: string; local?: boolean }) => {
			const ctx: CliContext = contextOf(program);
			const raiz = resolve(ctx.workspace);
			// The config lives next to the workspace, not inside it (datos.md).
			const config = await loadConfig(dirname(raiz));
			const result = await stageVerify(raiz, {
				// A thunk: an adapter without verify (VER-007) never asks for Docker.
				target: () =>
					resolveDocker({
						lang: ctx.lang,
						...(opts.remote !== undefined && { remote: opts.remote }),
						...(opts.local === true && { local: true }),
						...(config.verify?.remoto !== undefined && {
							configRemote: config.verify.remoto,
						}),
					}),
				lang: ctx.lang,
				signal: ctx.signal,
				...(config.verify?.timeoutMin !== undefined && {
					configTimeoutMin: config.verify.timeoutMin,
				}),
				...(config.verify?.modo !== undefined && {
					configModo: config.verify.modo,
				}),
				...(config.verify?.ignorar !== undefined && {
					configIgnorar: config.verify.ignorar,
				}),
			});
			ctx.result(result, humanSummary(result, ctx.lang));
		});
}
