import { lstat, readFile, rename, rm, writeFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding, State } from "@mct/contract/types";
import { hashTree } from "./hash.js";
import { readState } from "./workspace.js";

export const APPROVAL_SCHEMA_VERSION = 1;
export const APPROVAL_FILE = "approval.json";

const SHA256 = /^[0-9a-f]{64}$/;
const DECIDIDOS = new Set(["resuelto", "falso-positivo", "aceptado"]);

/** Signed gate (datos.md): ids and hashes only, never a value or a reason. */
export interface Approval {
	schemaVersion: number;
	arbolSha256: string;
	hallazgosDecididos: string[];
	aprobadoPor: string;
	aprobadoEn: string;
	mctVersion: string;
	gitleaksVersion: string;
}

export interface SignInput {
	/** Absolute `.mct`. */
	raiz: string;
	/** Findings after the re-scan. Any `abierto` makes signing fail. */
	hallazgos: readonly Finding[];
	gitleaksVersion: string;
	mctVersion: string;
	now?: () => string;
	user?: () => string;
}

/** Atomic write (temp file + rename), 0600; the caller holds the lock. */
export async function writeFileAtomic(
	destino: string,
	data: string | Uint8Array,
	mode = 0o600,
): Promise<void> {
	const tmp = `${destino}.${process.pid}.tmp`;
	try {
		await writeFile(tmp, data, { mode });
		await rename(tmp, destino);
	} catch (cause) {
		await rm(tmp, { force: true });
		throw new MctError("WORKSPACE_INVALIDO", "No se pudo escribir un archivo", {
			cause,
		});
	}
}

function desactualizada(motivo: string): MctError {
	return new MctError(
		"APROBACION_DESACTUALIZADA",
		"La aprobación no es válida para el árbol actual",
		{
			accion: "Corre: mct sanitize",
			etapa: "sanitize",
			detalle: { motivo },
		},
	);
}

/** SAN-003: sha256 of `work/`, bound to the exact tree at signing time. */
export async function signApproval(input: SignInput): Promise<Approval> {
	const abiertos = input.hallazgos.filter((h) => h.estado === "abierto").length;
	if (abiertos > 0) {
		throw new MctError("PUERTA_BLOQUEADA", "Hay hallazgos sin resolver", {
			accion: "Corre: mct sanitize",
			etapa: "sanitize",
			detalle: { abiertos },
		});
	}
	const arbolSha256 = await hashTree(join(input.raiz, "work"));
	const decididos = [
		...new Set(
			input.hallazgos.filter((h) => DECIDIDOS.has(h.estado)).map((h) => h.id),
		),
	].sort();
	const approval: Approval = {
		schemaVersion: APPROVAL_SCHEMA_VERSION,
		arbolSha256,
		hallazgosDecididos: decididos,
		aprobadoPor: (input.user ?? (() => userInfo().username))(),
		aprobadoEn: (input.now ?? (() => new Date().toISOString()))(),
		mctVersion: input.mctVersion,
		gitleaksVersion: input.gitleaksVersion,
	};
	await writeFileAtomic(
		join(input.raiz, APPROVAL_FILE),
		`${JSON.stringify(approval, null, 2)}\n`,
	);
	return approval;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
	v !== null && typeof v === "object" && !Array.isArray(v);

/** Reads and shape-checks approval.json. Any defect means "not approved". */
export async function readApproval(raiz: string): Promise<Approval> {
	const file = join(raiz, APPROVAL_FILE);
	let raw: string;
	try {
		if ((await lstat(file)).isSymbolicLink()) throw desactualizada("enlace");
		raw = await readFile(file, "utf8");
	} catch (cause) {
		if (cause instanceof MctError) throw cause;
		throw desactualizada("ausente");
	}
	let v: unknown;
	try {
		v = JSON.parse(raw);
	} catch {
		throw desactualizada("ilegible");
	}
	if (!isObj(v)) throw desactualizada("forma");
	if (typeof v.schemaVersion !== "number") throw desactualizada("forma");
	if (v.schemaVersion !== APPROVAL_SCHEMA_VERSION) {
		throw new MctError(
			"WORKSPACE_INVALIDO",
			"approval.json trae un schemaVersion desconocido",
			{ detalle: { esperado: APPROVAL_SCHEMA_VERSION } },
		);
	}
	if (
		typeof v.arbolSha256 !== "string" ||
		!SHA256.test(v.arbolSha256) ||
		!Array.isArray(v.hallazgosDecididos) ||
		!v.hallazgosDecididos.every(
			(x) => typeof x === "string" && SHA256.test(x),
		) ||
		typeof v.aprobadoPor !== "string" ||
		typeof v.aprobadoEn !== "string" ||
		typeof v.mctVersion !== "string" ||
		typeof v.gitleaksVersion !== "string"
	) {
		throw desactualizada("forma");
	}
	return v as unknown as Approval;
}

/**
 * Fails closed (APROBACION_DESACTUALIZADA) on any change to `work/` since signing,
 * a missing/corrupt file, or a `sanitize` stage that is not `ok`.
 */
export async function verifyApproval(
	raiz: string,
	state?: State,
): Promise<Approval> {
	const st = state ?? (await readState(raiz));
	const approval = await readApproval(raiz);
	if (st.etapas.sanitize.estado !== "ok") throw desactualizada("etapa");
	const actual = await hashTree(join(raiz, "work"));
	if (actual !== approval.arbolSha256) throw desactualizada("arbol");
	if (st.workSha256 !== approval.arbolSha256) throw desactualizada("estado");
	return approval;
}

/** Drops the signature (reopen, blocked gate). Idempotent. */
export async function invalidateApproval(raiz: string): Promise<void> {
	await rm(join(raiz, APPROVAL_FILE), { force: true });
}
