import { lstat, readdir, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { readState, withLock } from "./workspace.js";

export type Lang = "es" | "en";

export interface CleanInfo {
	ruta: string;
	archivos: number;
}

export interface CleanOptions {
	/** The `.mct/` directory to delete. */
	raiz: string;
	force: boolean;
	isTTY: boolean;
	lang?: Lang;
	/** Asks the human; only used with a TTY and without --force. Only a literal `true` confirms. */
	confirmar?: (info: CleanInfo) => Promise<boolean>;
}

export interface CleanResult {
	borrado: string;
	archivos: number;
}

const MSG = {
	es: {
		sinTty:
			"No hay terminal para confirmar el borrado. No se borró nada. Usa --force para scripts.",
		rechazado: "Cancelado: no se borró nada.",
		accion: "Usa: mct clean --force",
		enlace: "El workspace contiene un enlace; no se borró nada",
		ilegible: "No se pudo inspeccionar el workspace; no se borró nada",
		fallo: "No se pudo borrar el workspace por completo",
	},
	en: {
		sinTty:
			"There is no terminal to confirm the deletion. Nothing was deleted. Use --force for scripts.",
		rechazado: "Cancelled: nothing was deleted.",
		accion: "Use: mct clean --force",
		enlace: "The workspace contains a link; nothing was deleted",
		ilegible: "Could not inspect the workspace; nothing was deleted",
		fallo: "Could not delete the whole workspace",
	},
} as const;

/** Counts files without following links and without reading any content. Any link or error aborts. */
async function countFiles(dir: string, m: (typeof MSG)[Lang]): Promise<number> {
	let total = 0;
	let entries: string[];
	try {
		entries = await readdir(dir);
	} catch (cause) {
		throw new MctError("WORKSPACE_INVALIDO", m.ilegible, { cause });
	}
	for (const name of entries) {
		const path = join(dir, name);
		let st: Awaited<ReturnType<typeof lstat>>;
		try {
			st = await lstat(path);
		} catch (cause) {
			throw new MctError("WORKSPACE_INVALIDO", m.ilegible, { cause });
		}
		if (st.isSymbolicLink()) {
			throw new MctError("WORKSPACE_INVALIDO", m.enlace);
		}
		if (st.isDirectory()) total += await countFiles(path, m);
		else total += 1;
	}
	return total;
}

/**
 * CLN-001 / SAN-005. Deletes the whole workspace (quarantine included) only if
 * it has a valid state.json. Never touches `<dest>/mct.config.json`, which
 * lives outside `raiz`; it does delete `<dest>/decisiones.json` (SAN-015). Fails closed: any doubt is an error and nothing is deleted.
 */
export async function cleanWorkspace(opts: CleanOptions): Promise<CleanResult> {
	const m = MSG[opts.lang ?? "es"];
	const { raiz } = opts;

	// Valid state.json (also rejects a linked workspace) before anything else.
	await readState(raiz);
	const archivos = await countFiles(raiz, m);

	if (!opts.force) {
		if (!opts.isTTY) {
			throw new MctError("CANCELADO", m.sinTty, {
				etapa: "clean",
				accion: m.accion,
			});
		}
		const answer: unknown =
			opts.confirmar === undefined
				? false
				: await opts.confirmar({ ruta: raiz, archivos });
		if (answer !== true) {
			throw new MctError("CANCELADO", m.rechazado, { etapa: "clean" });
		}
	}

	await withLock(raiz, async () => {
		// Re-check under the lock: the workspace may have changed while asking.
		await readState(raiz);
		await countFiles(raiz, m);
		// state.json is the commit point: it goes last, so a partial failure
		// leaves a valid workspace and `clean` can be retried.
		const quitar = (path: string) =>
			rm(path, {
				recursive: true,
				force: true,
				maxRetries: 5,
				retryDelay: 100,
			});
		try {
			await quitar(join(raiz, "quarantine"));
			for (const name of await readdir(raiz)) {
				if (name === "state.json" || name === "lock") continue;
				await quitar(join(raiz, name));
			}
			await quitar(join(raiz, "lock"));
			await quitar(join(raiz, "state.json"));
			await rm(raiz, { recursive: true, force: false });
		} catch (cause) {
			throw new MctError("INTERNO", m.fallo, {
				cause,
				etapa: "clean",
				accion: m.accion,
			});
		}
	});
	// SAN-015: the decisions file lives in <dest>/ (outside .mct); it goes with the workspace.
	if (basename(raiz) === ".mct") {
		const decisiones = join(dirname(raiz), "decisiones.json");
		try {
			if (!(await lstat(decisiones)).isDirectory()) {
				await rm(decisiones, { force: true });
			}
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code !== "ENOENT") {
				throw new MctError("INTERNO", m.fallo, {
					cause,
					etapa: "clean",
					accion: m.accion,
				});
			}
		}
	}
	return { borrado: raiz, archivos };
}
