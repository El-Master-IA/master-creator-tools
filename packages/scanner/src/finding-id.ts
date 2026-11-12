import { createHash } from "node:crypto";
import { MctError } from "@mct/contract/errors";

export interface FindingIdInput {
	readonly motor: string;
	readonly regla: string;
	/** Path relative to work/ (or quarantine/), with `/`. */
	readonly archivo: string;
	readonly linea: number;
	readonly value: string;
}

export function normalizeValue(value: string): string {
	return value.normalize("NFC").trim();
}

function sha256(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Finding id (datos.md): SHA-256 of motor + regla + path + line + SHA-256 of
 * the normalized value. The value itself never appears in the result.
 */
export function findingId(input: FindingIdInput): string {
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
	return sha256(
		[
			input.motor,
			input.regla,
			input.archivo,
			String(input.linea),
			sha256(normalized),
		].join("\n"),
	);
}
