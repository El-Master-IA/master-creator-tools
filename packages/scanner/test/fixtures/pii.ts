// Datos personales sintéticos armados en tiempo de test.

export type PiiKind = "email" | "phone" | "card" | "ssn" | "cedula-co";

export interface SeedPii {
	readonly kind: PiiKind;
	readonly value: string;
}

/** Dígito de control Luhn para un prefijo numérico. */
export function luhnCheckDigit(prefix: string): string {
	let sum = 0;
	let double = true;
	for (let i = prefix.length - 1; i >= 0; i--) {
		let digit = Number(prefix[i]);
		if (double) {
			digit *= 2;
			if (digit > 9) digit -= 9;
		}
		sum += digit;
		double = !double;
	}
	return String((10 - (sum % 10)) % 10);
}

export function makePii(): readonly SeedPii[] {
	const cardPrefix = ["4111", "1111", "1111", "111"].join("");
	return [
		{
			kind: "email",
			value: ["maria", ".gomez", "@", "ejemplo-fixture", ".test"].join(""),
		},
		{ kind: "phone", value: ["+57", " 300", " 555", " 0142"].join("") },
		{ kind: "card", value: cardPrefix + luhnCheckDigit(cardPrefix) },
		{ kind: "ssn", value: ["900", "-", "12", "-", "3456"].join("") },
		{
			kind: "cedula-co",
			value: ["1.", "020", ".", "304", ".", "050"].join(""),
		},
	];
}
