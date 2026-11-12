import { describe, expect, it } from "vitest";
import { validarMotivo } from "../src/decisiones.js";

// Reference values are assembled from fragments (T05).
const VALOR_OTRO = ["tok", "en-", "zz99yy88xx77"].join("");
const VALOR_QUARANTINE = ["pass", "-quarantine", "-4417"].join("");
const TERMINO = ["Cliente", " Reservado"].join("");
const BUENO = "Es un dato de ejemplo del manual de usuario";

function rechazo(motivo: unknown, refs: string[] = []): unknown {
	try {
		validarMotivo(motivo, refs);
	} catch (e) {
		return e;
	}
	return null;
}

describe("validarMotivo (SAN-002)", () => {
	it("SAN-002 acepta un motivo de 10 a 500 caracteres y lo devuelve sin espacios sobrantes", () => {
		expect(validarMotivo(`  ${BUENO}  `, [VALOR_OTRO])).toBe(BUENO);
		expect(validarMotivo("a".repeat(10))).toHaveLength(10);
		expect(validarMotivo("a".repeat(500))).toHaveLength(500);
	});

	it("SAN-002 rechaza menos de 10, mas de 500 y lo que no es texto", () => {
		for (const malo of ["corto", "a".repeat(501), undefined, 42]) {
			expect(rechazo(malo)).toMatchObject({ codigo: "VALIDACION" });
		}
	});

	it("SAN-002 rechaza saltos de linea y caracteres invisibles", () => {
		for (const malo of [
			"primera linea\nsegunda linea",
			"motivo con ​cero ancho aqui",
			"motivo con ‮direccion aqui",
		]) {
			expect(rechazo(malo)).toMatchObject({ codigo: "VALIDACION" });
		}
	});

	it("SAN-002 rechaza un token", () => {
		const token = [
			"gh",
			"p_",
			"A1b2C3d4E5f6G7h8I9j0",
			"K1l2M3n4O5p6Q7r8S9t0",
		].join("");
		expect(rechazo(`el valor es ${token} del archivo`)).toMatchObject({
			codigo: "VALIDACION",
		});
	});

	it("SAN-002 rechaza el valor de otro hallazgo y el de quarantine/ sin repetirlo", () => {
		for (const valor of [VALOR_OTRO, VALOR_QUARANTINE]) {
			const e = rechazo(`igual que ${valor} de otro archivo`, [valor]) as Error;
			expect(e).toMatchObject({ codigo: "VALIDACION" });
			expect(e.message).not.toContain(valor);
		}
	});

	it("SAN-002 compara sin mayusculas: el termino del diccionario en mayusculas se rechaza", () => {
		expect(
			rechazo(`pertenece a ${TERMINO.toUpperCase()} y es de prueba`, [TERMINO]),
		).toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-002 compara tras NFKC: una forma compatible (ancho completo) se rechaza", () => {
		const ancho = "ＣＬＩＥＮＴＥ ＲＥＳＥＲＶＡＤＯ";
		expect(rechazo(`dato de ${ancho} para pruebas`, [TERMINO])).toMatchObject({
			codigo: "VALIDACION",
		});
		expect(
			rechazo("dato de cliente reservado para pruebas", [ancho]),
		).toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-002 los valores de 3 caracteres no cuentan", () => {
		expect(validarMotivo("dato de prueba con abc dentro", ["abc"])).toContain(
			"abc",
		);
		expect(rechazo("dato de prueba con abcd dentro", ["abcd"])).toMatchObject({
			codigo: "VALIDACION",
		});
	});
});
