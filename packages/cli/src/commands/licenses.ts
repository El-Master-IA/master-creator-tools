import { lstat, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding, State } from "@mct/contract/types";
import { readReportAvisos } from "@mct/core/avisos";
import { loadConfig } from "@mct/core/config";
import { hashTree } from "@mct/core/hash";
import {
	applyCascade,
	ETAPAS,
	readState,
	withLock,
	workspacePaths,
	writeState,
} from "@mct/core/workspace";
import type { Command } from "commander";
// The cli package does not declare these workspace packages yet (package.json is
// outside T22), so they are reached by relative path until it does.
import { listCommunityNodes } from "../../../adapter-n8n/src/index.js";
import {
	type AuditResult,
	auditLicenses,
} from "../../../licenses/src/audit.js";
import { auditPython } from "../../../licenses/src/python.js";
import {
	AVISO_SIN_GESTOR,
	auditSinGestor,
	writeLicenseAvisos,
} from "../../../licenses/src/sin-gestor.js";
import {
	formatAlternatives,
	gateExit,
	type LicenseEntry,
} from "../../../licenses/src/verdict.js";
import { renderReport } from "../../../templates/src/report.js";
import { type CliContext, contextOf, type Lang } from "../output.js";

const MAX_FINDINGS_BYTES = 64_000_000;

async function writeAtomic(path: string, content: string): Promise<void> {
	const tmp = `${path}.${process.pid}.tmp`;
	await writeFile(tmp, content, { mode: 0o600 });
	await rename(tmp, path);
}

/** `.mct/findings.json` feeds the shared report; missing is empty, malformed is an error. */
async function readFindings(raiz: string): Promise<Finding[]> {
	const file = join(raiz, "findings.json");
	let st: Awaited<ReturnType<typeof lstat>>;
	try {
		st = await lstat(file);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return [];
		throw new MctError("WORKSPACE_INVALIDO", "No se pudo leer findings.json", {
			cause,
		});
	}
	if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_FINDINGS_BYTES) {
		throw new MctError("WORKSPACE_INVALIDO", "findings.json no es válido");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(await readFile(file, "utf8"));
	} catch (cause) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"findings.json no es JSON válido",
			{ cause },
		);
	}
	const list =
		parsed !== null && typeof parsed === "object"
			? (parsed as { hallazgos?: unknown }).hallazgos
			: undefined;
	if (!Array.isArray(list)) {
		throw new MctError("WORKSPACE_INVALIDO", "findings.json sin hallazgos");
	}
	return list as Finding[];
}

/** EXPERIENCE.md: texto de los avisos de licencias. */
const AVISOS: Record<string, Record<Lang, string>> = {
	"indice-privado-fuera": {
		es: "Índice privado detectado fuera de requirements; no se consultó PyPI",
		en: "Private index detected outside requirements; PyPI was not queried",
	},
	[AVISO_SIN_GESTOR]: {
		es: "Sin gestor de dependencias reconocido: revisa a mano las librerías incluidas",
		en: "No recognized dependency manager: review bundled libraries by hand",
	},
};

/** Which mct.config.json override accepts this entry (LIC-005/LIC-006). */
export function overrideDe(
	paquete: string,
): "sinLock" | "gestorNoSoportado" | "allow" {
	if (paquete.startsWith("(gestor no soportado")) return "gestorNoSoportado";
	// Manifest below the root: unaudited tree, accepted like a missing lockfile (LIC-006).
	if (paquete.startsWith("(manifiesto en subcarpeta")) return "sinLock";
	if (paquete.startsWith("(")) return "sinLock";
	return "allow";
}

/** Entries still blocking the gate, for --json (plugin /liberar, PLG-005). */
function pendientes(entries: readonly LicenseEntry[]) {
	return entries
		.filter((e) => e.veredicto === "bloquea" || e.veredicto === "revisar")
		.map((e) => ({
			paquete: e.paquete,
			version: e.version,
			veredicto: e.veredicto,
			override: overrideDe(e.paquete),
		}));
}

function humanSummary(
	lang: Lang,
	data: {
		paquetes: number;
		bloquea: number;
		revisar: number;
		overrides: number;
	},
	entries: readonly LicenseEntry[],
	avisos: readonly string[] = [],
): string {
	const head =
		lang === "en"
			? `Licenses: ${data.paquetes} packages, ${data.bloquea} blocked, ${data.revisar} to review, ${data.overrides} overrides`
			: `Licencias: ${data.paquetes} paquetes, ${data.bloquea} bloquean, ${data.revisar} por revisar, ${data.overrides} overrides`;
	const lines = [head];
	for (const e of entries) {
		if (e.veredicto === "ok") continue;
		lines.push(
			`  ${e.veredicto}  ${e.paquete}@${e.version}  ${e.spdx ?? "-"}`,
			...formatAlternatives(e).map((l) => `    ${l}`),
		);
	}
	const tipos = new Set(
		entries
			.filter((e) => e.veredicto === "bloquea" || e.veredicto === "revisar")
			.map((e) => overrideDe(e.paquete)),
	);
	if (tipos.has("allow")) {
		lines.push(
			lang === "en"
				? "Accept a license with a reason in mct.config.json (licenses.allow) or replace the package."
				: "Acepta la licencia con motivo en mct.config.json (licenses.allow) o cambia el paquete.",
		);
	}
	if (tipos.has("sinLock")) {
		lines.push(
			lang === "en"
				? "Add a lockfile (uv lock) or accept it with a reason in mct.config.json (licenses.sinLock.motivo)."
				: "Agrega un lockfile (uv lock) o acéptalo con motivo en mct.config.json (licenses.sinLock.motivo).",
		);
	}
	if (tipos.has("gestorNoSoportado")) {
		lines.push(
			lang === "en"
				? "Review those dependencies by hand and accept with a reason in mct.config.json (licenses.gestorNoSoportado.motivo)."
				: "Revisa esas dependencias a mano y acéptalas con motivo en mct.config.json (licenses.gestorNoSoportado.motivo).",
		);
	}
	for (const a of avisos) {
		lines.push(
			`${lang === "en" ? "Warning" : "Aviso"}: ${AVISOS[a]?.[lang] ?? a}`,
		);
	}
	return lines.join("\n");
}

/** LIC-004 (node, n8n), LIC-005 (python) or LIC-006 (estatico, generico), by adapter. */
async function auditByAdapter(
	state: State,
	raiz: string,
	config: Awaited<ReturnType<typeof loadConfig>>,
	offline: boolean,
): Promise<AuditResult & { avisos: string[] }> {
	const ws = workspacePaths(raiz);
	const allow = config.licenses?.allow ?? [];
	const sinLock = config.licenses?.sinLock;
	if (state.adapter === "python") {
		const py = await auditPython({
			workDir: ws.work,
			quarantineDir: ws.quarantine,
			allow,
			offline,
			mctVersion: state.mctVersion,
			...(sinLock !== undefined && { sinLock }),
		});
		await writeLicenseAvisos(raiz, py.avisos);
		return py;
	}
	if (state.adapter === "estatico" || state.adapter === "generico") {
		const gestorNoSoportado = config.licenses?.gestorNoSoportado;
		return auditSinGestor({
			adapter: state.adapter,
			workDir: ws.work,
			mctDir: raiz,
			allow,
			offline,
			mctVersion: state.mctVersion,
			...(sinLock !== undefined && { sinLock }),
			...(gestorNoSoportado !== undefined && { gestorNoSoportado }),
			...(state.origen.tipo === "carpeta" && {
				node: { originDir: state.origen.ref },
			}),
		});
	}
	const extra =
		state.adapter === "n8n"
			? (await listCommunityNodes(ws)).map((c) => ({
					paquete: c.paquete,
					version: "latest",
				}))
			: undefined;
	const result = await auditLicenses({
		lockDir: ws.work,
		...(state.origen.tipo === "carpeta" && { originDir: state.origen.ref }),
		offline,
		...(extra !== undefined && { extra }),
		allow,
	});
	return { ...result, avisos: [] };
}

async function run(ctx: CliContext, offline: boolean): Promise<void> {
	const raiz = resolve(ctx.workspace);
	await withLock(raiz, async () => {
		const state = await readState(raiz);
		const ws = workspacePaths(raiz);
		const config = await loadConfig(dirname(raiz));
		const result = await auditByAdapter(state, raiz, config, offline);

		const ts = new Date().toISOString();
		const exit = gateExit(result.entries);
		let next: State = applyCascade(
			state,
			{ workSha256: await hashTree(ws.work) },
			ts,
		);
		next = {
			...next,
			etapas: {
				...next.etapas,
				licenses: { estado: exit === 0 ? "ok" : "bloqueada", ts },
			},
		};

		await writeAtomic(
			join(raiz, "license-report.json"),
			`${JSON.stringify(result.entries, null, 2)}\n`,
		);
		const html = renderReport({
			lang: ctx.lang,
			generadoEn: ts,
			puertas: ETAPAS.map((etapa) => ({
				etapa,
				estado: next.etapas[etapa].estado,
			})),
			hallazgos: await readFindings(raiz),
			avisos: await readReportAvisos(raiz, next.verificado),
			licencias: result.entries.map((e) => ({
				paquete: e.paquete,
				version: e.version,
				spdx: e.spdx ?? "-",
				relacion: e.origen,
				veredicto: e.veredicto,
				...(e.alternativa !== undefined && {
					alternativa: e.alternativa
						.map((a) => `${a.paquete} (${a.licencia})`)
						.join(", "),
				}),
			})),
		});
		await writeAtomic(join(raiz, "report.html"), html);
		await writeState(raiz, next);

		ctx.result(
			{
				...result.resumen,
				avisos: result.avisos,
				...(exit !== 0 && { pendientes: pendientes(result.entries) }),
			},
			humanSummary(ctx.lang, result.resumen, result.entries, result.avisos),
			exit,
		);
	});
}

/** `mct licenses [--offline]`: audits the full dependency tree (LIC-001…LIC-004). */
export function register(program: Command): void {
	program
		.command("licenses")
		.description("audit the license of every dependency (SPDX)")
		.option("--offline", "do not query the npm registry")
		.action(async (options: { offline?: boolean }, command: Command) => {
			await run(contextOf(command), options.offline === true);
		});
}
