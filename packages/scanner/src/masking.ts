import { MctError } from "@mct/contract/errors";

const MASK = "****";
const MAX_REAL = 4;

/**
 * Masks a value: at most 4 real leading characters followed by a fixed `****`.
 * Values shorter than 5 characters never show in full (SCAN-007).
 */
export function maskValue(value: string): string {
	if (value.length === 0) {
		throw new MctError("VALIDACION", "Cannot mask an empty value");
	}
	const chars = Array.from(value);
	const reveal = Math.min(MAX_REAL, Math.floor(chars.length / 2));
	return `${chars.slice(0, reveal).join("")}${MASK}`;
}

/** Dictionary matches are shown by index, never by term: `[dic:n]`. */
export function maskDictionary(index: number): string {
	if (!Number.isInteger(index) || index < 0) {
		throw new MctError(
			"VALIDACION",
			"Dictionary index must be an integer >= 0",
		);
	}
	return `[dic:${index}]`;
}
