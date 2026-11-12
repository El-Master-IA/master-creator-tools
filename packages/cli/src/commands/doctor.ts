import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import { loadConfig } from "@mct/core/config";
import {
	type DoctorOptions,
	type DoctorReport,
	runDoctor,
} from "@mct/core/doctor";
import type { Command } from "commander";
import type { Register } from "../main.js";
import { type CliContext, contextOf } from "../output.js";

const LABEL = {
	es: { ok: "OK", aviso: "AVISO", falla: "FALLA", next: "Siguiente" },
	en: { ok: "OK", aviso: "WARN", falla: "FAIL", next: "Next" },
} as const;

function render(ctx: CliContext, report: DoctorReport): string {
	const l = LABEL[ctx.lang];
	const lines: string[] = [];
	for (const c of report.checks) {
		lines.push(`${l[c.estado]}  ${c.mensaje}`);
		if (c.accion !== undefined) lines.push(`      -> ${c.accion}`);
	}
	lines.push(`${l.next}: ${report.siguiente}`);
	return lines.join("\n");
}

/** `deps` lets tests replace processes and the home directory. */
export function createDoctor(
	deps: Pick<
		DoctorOptions,
		"run" | "resolveExe" | "install" | "perms" | "home"
	> = {},
): Register {
	return (program: Command) => {
		program
			.command("doctor")
			.description("check the environment (read-only)")
			.option("--install-gitleaks", "download the pinned gitleaks release")
			.action(async (opts: { installGitleaks?: boolean }) => {
				const ctx = contextOf(program);
				// mct.config.json lives next to the workspace, not inside it.
				let remoto: string | undefined;
				let configInvalid = false;
				try {
					const config = await loadConfig(dirname(resolve(ctx.workspace)));
					remoto = config.verify?.remoto;
				} catch (e) {
					if (!(e instanceof MctError) || e.codigo !== "VALIDACION") throw e;
					configInvalid = true;
				}
				const report = await runDoctor({
					home: homedir(),
					env: ctx.io.env,
					lang: ctx.lang,
					remoto,
					configInvalid,
					installGitleaks: opts.installGitleaks === true,
					...deps,
				});
				ctx.result(report, render(ctx, report));
			});
	};
}

export const register: Register = createDoctor();
