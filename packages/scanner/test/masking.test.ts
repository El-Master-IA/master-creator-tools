import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import {
	type FindingIdInput,
	findingId as findingIdConClave,
	normalizeValue,
} from "../src/finding-id.js";
import { maskDictionary, maskValue } from "../src/masking.js";
import { CLAVE_PRUEBA } from "./clave.js";

const findingId = (input: FindingIdInput) =>
	findingIdConClave(input, CLAVE_PRUEBA);

const sample = ["sk", "-", "proj", "-", "abcdef0123456789"].join("");

function leadingReal(masked: string): string {
	return masked.replace(/\*+$/, "");
}

describe("masking", () => {
	it("SCAN-007 conserva como maximo 4 caracteres reales y cierra con ****", () => {
		const masked = maskValue(sample);
		expect(masked).toBe(`${sample.slice(0, 4)}****`);
		expect(leadingReal(masked).length).toBeLessThanOrEqual(4);
		expect(masked).not.toContain(sample.slice(4));
	});

	it("SCAN-007 no revela completo un valor de menos de 5 caracteres", async () => {
		for (const v of ["a", "ab", "abc", "abcd"]) {
			const masked = maskValue(v);
			expect(masked).not.toContain(v);
			expect(masked.endsWith("****")).toBe(true);
			expect(leadingReal(masked).length).toBeLessThan(v.length);
		}
	});

	it("SCAN-007 el sufijo es de longitud fija", () => {
		expect(maskValue("x".repeat(6)).endsWith("****")).toBe(true);
		expect(maskValue("x".repeat(60))).toBe("xxxx****");
	});

	it("SCAN-007 formatea el diccionario como [dic:n] sin el termino", () => {
		expect(maskDictionary(3)).toBe("[dic:3]");
		expect(() => maskDictionary(-1)).toThrow(MctError);
		expect(() => maskDictionary(1.5)).toThrow(MctError);
	});

	it("SCAN-007 lanza VALIDACION con valor vacio", async () => {
		expect(() => maskValue("")).toThrow(MctError);
		try {
			maskValue("");
		} catch (e) {
			expect((e as MctError).codigo).toBe("VALIDACION");
		}
		expect(() => findingId({ ...base, value: "" })).toThrow(MctError);
	});
});

const base = {
	motor: "mct",
	regla: "openai-key",
	zona: "work",
	archivo: "src/a.ts",
	linea: 3,
	value: sample,
} as const;

describe("findingId", () => {
	it("SCAN-007 devuelve el mismo hash con las mismas entradas y sin el valor", () => {
		const a = findingId(base);
		expect(a).toBe(findingId({ ...base }));
		expect(a).toMatch(/^[0-9a-f]{64}$/);
		expect(a).not.toContain(sample.slice(0, 8));
	});

	it("SCAN-007 cambia el hash si cambia cualquier entrada", () => {
		const a = findingId(base);
		expect(findingId({ ...base, linea: 4 })).not.toBe(a);
		expect(findingId({ ...base, archivo: "src/b.ts" })).not.toBe(a);
		expect(findingId({ ...base, value: `${sample}x` })).not.toBe(a);
	});

	it("SCAN-007 normaliza el valor antes de hashear", () => {
		expect(normalizeValue(`  ${sample}\n`)).toBe(sample);
		expect(findingId({ ...base, value: `${sample}\n` })).toBe(findingId(base));
	});
});
