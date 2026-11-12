import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";

export interface FindingIdInput {
	readonly motor: string;
	readonly regla: string;
	/** Path relative to work/ (or quarantine/), with `/`. */
	readonly archivo: string;
	readonly linea: number;
	readonly value: string;
}

/** Size of the per-workspace HMAC key (SCAN-015). */
export const CLAVE_BYTES = 32;

export function normalizeValue(value: string): string {
	return value.normalize("NFC").trim();
}

function sha256(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

function claveInvalida(motivo: string): MctError {
	return new MctError(
		"WORKSPACE_INVALIDO",
		"Falta la clave del workspace (.mct/clave) o es inválida",
		{
			accion: "mct init --force",
			detalle: { archivo: "clave", motivo },
		},
	);
}

/** Reads `.mct/clave` (`raiz` is the `.mct/` directory). Fail closed: never a default key. */
export async function leerClave(raiz: string): Promise<Buffer> {
	let clave: Buffer;
	try {
		clave = await readFile(join(raiz, "clave"));
	} catch {
		throw claveInvalida("ausente");
	}
	if (clave.length !== CLAVE_BYTES) throw claveInvalida("tamano");
	return clave;
}

/**
 * Finding id (datos.md, SCAN-015): HMAC-SHA256, keyed with `.mct/clave`, of
 * motor + regla + path + line + SHA-256 of the normalized value. The value
 * itself never appears in the result and the id cannot be recomputed without
 * the key.
 */
export function findingId(input: FindingIdInput, clave: Uint8Array): string {
	if (clave.length !== CLAVE_BYTES) throw claveInvalida("tamano");
	const normalized = normalizeValue(input.value);
	if (normalized.length === 0) {
		throw new MctError(
			"VALIDACION",
			"Cannot build a finding id from an empty value",
		);
	}
	if (!Number.isInteger(input.linea) || input.linea < 0) {
		throw new MctError("VALIDACION", "Line must be an integer >= 0");
	}
	return createHmac("sha256", clave)
		.update(
			[
				input.motor,
				input.regla,
				input.archivo,
				String(input.linea),
				sha256(normalized),
			].join("\n"),
			"utf8",
		)
		.digest("hex");
}
