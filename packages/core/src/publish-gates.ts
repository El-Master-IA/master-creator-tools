import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Etapa, State } from "@mct/contract/types";
import type { GithubClient } from "./github.js";
import { hashTree } from "./hash.js";
import { ETAPAS, readState } from "./workspace.js";

/** Largest JSON artefact read by the gates; bigger is refused (fail closed). */
export const GATE_FILE_MAX_BYTES = 50 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const REPO_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const DOTS_ONLY = /^\.+$/;
const ESTADOS = new Set([
	"abierto",
	"resuelto",
	"falso-positivo",
	"aceptado",
	"obsoleto",
	"aislado",
]);
const VEREDICTOS = new Set(["ok", "revisar", "bloquea"]);
/** Stages that must be `ok` before publish; `publish` itself is the one running. */
const PREVIAS: readonly Etapa[] = ETAPAS.filter((e) => e !== "publish");

export type PublishLang = "es" | "en";

export interface PublishChecksOptions {
	/** `.mct/` directory of the workspace. */
	raiz: string;
	/** `owner/name` the person asked to publish. */
	repo: string;
	/** PUB-006: only reads, locally and on GitHub. */
	dryRun?: boolean;
	/** PUB-004: repoId saved by this workspace in publish-state.json, for --resume. */
	resumeRepoId?: number;
	lang?: PublishLang;
}

export interface PublishChecksResult {
	repo: string;
	dryRun: boolean;
	/** `nuevo` when the repo is absent; `reanudar` when --resume matches our own repo. */
	modo: "nuevo" | "reanudar";
}

const MSG = {
	es: {
		etapas: "Hay etapas sin pasar antes de publicar",
		accionEtapas: "Corre las etapas pendientes (mct run)",
		abiertos: "Hay hallazgos sin resolver",
		accionAbiertos: "Corre: mct sanitize",
		licencias: "Hay licencias que bloquean o piden revisión",
		accionLicencias: "Corre: mct licenses",
		sinAprobacion: "No hay aprobación vigente",
		sinVerify: "verify no ha pasado",
		accionVerify: "Corre: mct verify",
		viejaWork: "El contenido de work/ cambió desde la aprobación",
		viejaDist: "dist/ no es el que pasó verify",
		accionVieja: "Corre de nuevo sanitize, package y verify",
		ilegible: "No se pudo leer un archivo del workspace",
		forma: "Un archivo del workspace tiene una forma inválida",
		enlace: "Un archivo del workspace es un enlace o no es un archivo",
		grande: "Un archivo del workspace supera el límite",
		accionWs: "Revisa el workspace o recréalo con init --force",
		repoMal: "El nombre del repo no es owner/nombre válido",
		accionRepo: "Usa --repo <owner/nombre>",
		existe: "El repo ya existe; no se hace push a un repo existente",
		accionExiste: "Elige otro nombre o borra el repo vacío a mano",
		resumeAjeno: "--resume no corresponde al repo creado por este workspace",
	},
	en: {
		etapas: "Some stages have not passed before publishing",
		accionEtapas: "Run the pending stages (mct run)",
		abiertos: "There are unresolved findings",
		accionAbiertos: "Run: mct sanitize",
		licencias: "Some licenses block or need review",
		accionLicencias: "Run: mct licenses",
		sinAprobacion: "There is no valid approval",
		sinVerify: "verify has not passed",
		accionVerify: "Run: mct verify",
		viejaWork: "The content of work/ changed since the approval",
		viejaDist: "dist/ is not the one that passed verify",
		accionVieja: "Run sanitize, package and verify again",
		ilegible: "A workspace file could not be read",
		forma: "A workspace file has an invalid shape",
		enlace: "A workspace file is a link or not a regular file",
		grande: "A workspace file is over the limit",
		accionWs: "Check the workspace or recreate it with init --force",
		repoMal: "The repo name is not a valid owner/name",
		accionRepo: "Use --repo <owner/name>",
		existe: "The repo already exists; no push to an existing repo",
		accionExiste: "Pick another name or delete the empty repo by hand",
		resumeAjeno: "--resume does not match the repo created by this workspace",
	},
} as const;

type Msg = (typeof MSG)[PublishLang];

function wsError(
	mensaje: string,
	accion: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		etapa: "publish",
		accion,
		...(detalle !== undefined && { detalle }),
	});
}

function blocked(
	mensaje: string,
	accion: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("PUERTA_BLOQUEADA", mensaje, {
		etapa: "publish",
		accion,
		...(detalle !== undefined && { detalle }),
	});
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

/** Reads a JSON artefact; `undefined` only when the file does not exist. Links refused. */
async function readJson(raiz: string, name: string, m: Msg): Promise<unknown> {
	const path = join(raiz, name);
	let info: Awaited<ReturnType<typeof lstat>>;
	try {
		info = await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw wsError(m.ilegible, m.accionWs, { archivo: name });
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		throw wsError(m.enlace, m.accionWs, { archivo: name });
	}
	if (info.size > GATE_FILE_MAX_BYTES) {
		throw wsError(m.grande, m.accionWs, { archivo: name });
	}
	let raw: string;
	try {
		raw = await readFile(path, "utf8");
	} catch {
		throw wsError(m.ilegible, m.accionWs, { archivo: name });
	}
	try {
		return JSON.parse(raw);
	} catch {
		throw wsError(m.forma, m.accionWs, { archivo: name });
	}
}

function countOpen(data: unknown, m: Msg): number {
	if (!isObj(data) || !Array.isArray(data.hallazgos)) {
		throw wsError(m.forma, m.accionWs, { archivo: "findings.json" });
	}
	let abiertos = 0;
	for (const h of data.hallazgos as unknown[]) {
		if (!isObj(h) || typeof h.estado !== "string" || !ESTADOS.has(h.estado)) {
			throw wsError(m.forma, m.accionWs, { archivo: "findings.json" });
		}
		if (h.estado === "abierto") abiertos++;
	}
	return abiertos;
}

function countLicenseBlocks(data: unknown, m: Msg): number {
	if (!Array.isArray(data)) {
		throw wsError(m.forma, m.accionWs, { archivo: "license-report.json" });
	}
	let bloquean = 0;
	for (const l of data as unknown[]) {
		if (
			!isObj(l) ||
			typeof l.veredicto !== "string" ||
			!VEREDICTOS.has(l.veredicto)
		) {
			throw wsError(m.forma, m.accionWs, { archivo: "license-report.json" });
		}
		// An accepted override already yields "ok" in judgePackage; ignore it here.
		if (l.veredicto !== "ok") bloquean++;
	}
	return bloquean;
}

/**
 * PUB-001: every gate must have passed. Reads only local files; GitHub is not involved.
 * Findings in `aislado` do not count as open.
 */
export async function checkGates(
	raiz: string,
	lang: PublishLang = "es",
): Promise<State> {
	const m = MSG[lang];
	const state = await readState(raiz);
	const pendientes = PREVIAS.filter((e) => state.etapas[e].estado !== "ok");
	if (pendientes.length > 0) {
		throw blocked(m.etapas, m.accionEtapas, { etapas: pendientes });
	}
	const findings = await readJson(raiz, "findings.json", m);
	if (findings === undefined) {
		throw blocked(m.abiertos, m.accionAbiertos, { motivo: "sin-findings" });
	}
	const abiertos = countOpen(findings, m);
	if (abiertos > 0) throw blocked(m.abiertos, m.accionAbiertos, { abiertos });
	const licencias = await readJson(raiz, "license-report.json", m);
	if (licencias === undefined) {
		throw blocked(m.licencias, m.accionLicencias, { motivo: "sin-reporte" });
	}
	const bloquean = countLicenseBlocks(licencias, m);
	if (bloquean > 0) throw blocked(m.licencias, m.accionLicencias, { bloquean });
	if (state.verificado === null) throw blocked(m.sinVerify, m.accionVerify);
	return state;
}

/**
 * PUB-010: the approval must still match work/ and the current dist/ must be the one
 * that passed verify. Reads only local files; GitHub is not involved.
 */
export async function checkHashes(
	raiz: string,
	state: State,
	lang: PublishLang = "es",
): Promise<void> {
	const m = MSG[lang];
	const approval = await readJson(raiz, "approval.json", m);
	if (approval === undefined) throw blocked(m.sinAprobacion, m.accionAbiertos);
	if (!isObj(approval) || approval.schemaVersion !== 1) {
		throw wsError(m.forma, m.accionWs, { archivo: "approval.json" });
	}
	const arbol = approval.arbolSha256;
	if (typeof arbol !== "string" || !SHA256.test(arbol)) {
		throw wsError(m.forma, m.accionWs, { archivo: "approval.json" });
	}
	const verificado = state.verificado;
	if (verificado === null) throw blocked(m.sinVerify, m.accionVerify);
	for (const h of [state.workSha256, state.distSha256, verificado.distSha256]) {
		if (!SHA256.test(h)) {
			throw wsError(m.forma, m.accionWs, { archivo: "state.json" });
		}
	}
	const work = await hashTree(join(raiz, "work"));
	if (work !== arbol || work !== state.workSha256) {
		throw new MctError("APROBACION_DESACTUALIZADA", m.viejaWork, {
			etapa: "publish",
			accion: m.accionVieja,
		});
	}
	const dist = await hashTree(join(raiz, "dist"));
	if (dist !== verificado.distSha256 || dist !== state.distSha256) {
		throw new MctError("APROBACION_DESACTUALIZADA", m.viejaDist, {
			etapa: "publish",
			accion: m.accionVieja,
		});
	}
}

/**
 * PUB-004: GET only. 404 means free. 200 aborts with VALIDACION unless --resume names
 * the repoId this workspace saved. Any other failure propagates (fail closed).
 */
export async function checkRepoAbsent(
	client: GithubClient,
	repo: string,
	resumeRepoId: number | undefined,
	lang: PublishLang = "es",
): Promise<"nuevo" | "reanudar"> {
	const m = MSG[lang];
	const [owner, name] = repo.split("/") as [string, string];
	let res: Awaited<ReturnType<GithubClient["request"]>>;
	try {
		res = await client.request("GET /repos/{owner}/{repo}", {
			owner,
			repo: name,
		});
	} catch (e) {
		if (
			e instanceof MctError &&
			e.codigo === "INTERNO" &&
			e.detalle?.estado === 404
		) {
			return "nuevo";
		}
		throw e;
	}
	const id = isObj(res.data) ? res.data.id : undefined;
	if (
		resumeRepoId !== undefined &&
		typeof id === "number" &&
		id === resumeRepoId
	) {
		return "reanudar";
	}
	throw new MctError(
		"VALIDACION",
		resumeRepoId === undefined ? m.existe : m.resumeAjeno,
		{ etapa: "publish", accion: m.accionExiste, detalle: { repo } },
	);
}

/**
 * Start of `publish` (PUB-001, PUB-004, PUB-006, PUB-010). Order: local gates, local hashes,
 * then GitHub reads (token permissions, repo exists). Never writes, locally or remotely,
 * so `--dry-run` runs exactly this.
 */
export async function runPublishChecks(
	client: GithubClient,
	opts: PublishChecksOptions,
): Promise<PublishChecksResult> {
	const lang = opts.lang ?? "es";
	const m = MSG[lang];
	const name = opts.repo.split("/")[1] ?? "";
	if (!REPO_NAME.test(opts.repo) || DOTS_ONLY.test(name)) {
		throw new MctError("VALIDACION", m.repoMal, {
			etapa: "publish",
			accion: m.accionRepo,
		});
	}
	const state = await checkGates(opts.raiz, lang);
	await checkHashes(opts.raiz, state, lang);
	await client.checkPermissions();
	const modo = await checkRepoAbsent(
		client,
		opts.repo,
		opts.resumeRepoId,
		lang,
	);
	return { repo: opts.repo, dryRun: opts.dryRun === true, modo };
}
