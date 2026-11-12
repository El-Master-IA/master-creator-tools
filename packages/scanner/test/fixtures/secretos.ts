// Secretos sintéticos armados en tiempo de test a partir de fragmentos.
// Ningún valor completo existe literal en el repo (T05, D-002).

export type SecretKind =
	| "aws-key"
	| "github-token"
	| "stripe-key"
	| "generic-api-key";

export interface SeedSecret {
	readonly kind: SecretKind;
	readonly value: string;
}

const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
/** Alfabeto base32 de las claves de acceso de AWS. */
export const AWS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Relleno determinista (sin azar, mulberry32 con Math.imul) para que el truth.json sea reproducible. */
function filler(seed: number, length: number, alphabet = ALPHABET): string {
	let state = seed >>> 0;
	let out = "";
	for (let i = 0; i < length; i++) {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		const r = ((t ^ (t >>> 14)) >>> 0) / 4294967296;
		out += alphabet[Math.floor(r * alphabet.length)];
	}
	return out;
}

export function makeSecrets(): readonly SeedSecret[] {
	return [
		{
			kind: "aws-key",
			value: ["AK", "IA", filler(11, 16, AWS_ALPHABET)].join(""),
		},
		{
			kind: "github-token",
			value: ["gh", "p_", filler(23, 36)].join(""),
		},
		{
			kind: "stripe-key",
			value: ["sk", "_live", "_", filler(37, 24)].join(""),
		},
		{
			kind: "generic-api-key",
			value: ["api", "key", "-", filler(41, 32)].join(""),
		},
	];
}

/** Expresión de lectura de variable de entorno, armada por fragmentos. */
export function envExpression(name: string): string {
	return ["proc", "ess", ".env", ".", name].join("");
}
