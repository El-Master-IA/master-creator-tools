import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { State } from "@mct/contract/types";
import type { ReportAviso } from "@mct/templates/report";

/** `.mct/verify-avisos.json` (datos.md): notices of the last passing verify, readable by report and publish. */
export const VERIFY_AVISOS_FILE = "verify-avisos.json";
const SCHEMA_VERSION = 1;

async function readStrings(path: string): Promise<string[]> {
	try {
		const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
		const list = (parsed as { avisos?: unknown } | null)?.avisos;
		return Array.isArray(list)
			? list.filter((x): x is string => typeof x === "string")
			: [];
	} catch {
		return [];
	}
}

export async function writeVerifyAvisos(
	raiz: string,
	avisos: readonly string[],
): Promise<void> {
	const target = join(raiz, VERIFY_AVISOS_FILE);
	const tmp = `${target}.${process.pid}.tmp`;
	const body = `${JSON.stringify({ schemaVersion: SCHEMA_VERSION, avisos }, null, 2)}\n`;
	await writeFile(tmp, body, { mode: 0o600 });
	await rename(tmp, target);
}

export async function clearVerifyAvisos(raiz: string): Promise<void> {
	await rm(join(raiz, VERIFY_AVISOS_FILE), { force: true });
}

/**
 * Notices the report shows (VER-007, LIC-006, EXPERIENCE.md 1.1…1.3), in DOM order:
 * verify first, then licenses. Missing or malformed files mean no notice.
 */
export async function readReportAvisos(
	raiz: string,
	verificado: State["verificado"],
): Promise<ReportAviso[]> {
	const out: ReportAviso[] = [];
	if (verificado?.destino === "(omitido)") out.push("verify.omitido");
	const verify = await readStrings(join(raiz, VERIFY_AVISOS_FILE));
	if (verify.includes("verify.compilar")) out.push("verify.compilar");
	if (verify.includes("verify.poetrySinLock")) out.push("verify.poetrySinLock");
	if (verify.includes("verify.pipCheck")) out.push("verify.pipCheck");
	const lic = await readStrings(join(raiz, "license-avisos.json"));
	if (lic.includes("sin-gestor")) out.push("licenses.sinGestor");
	return out;
}
