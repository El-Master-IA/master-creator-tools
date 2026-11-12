import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { ERROR_EXITS, exitFor, MctError, redactTokens } from "../src/errors.js";
import { GITLEAKS_MAJOR, N8N_IMAGE_REF } from "../src/pins.js";

const ghToken = (prefix: string) => `${prefix}_${"a1B2".repeat(9)}`;

describe("MctError", () => {
	it("ERR-001 devuelve el exit de la tabla de api.md para los 13 códigos", () => {
		const tabla: Record<string, number> = {
			VALIDACION: 2,
			ORIGEN_NO_ENCONTRADO: 3,
			WORKSPACE_INVALIDO: 4,
			PUERTA_BLOQUEADA: 10,
			APROBACION_DESACTUALIZADA: 11,
			MOTOR_NO_DISPONIBLE: 12,
			DOCKER_NO_DISPONIBLE: 13,
			SIN_CREDENCIAL: 14,
			LIMITE_GITHUB: 15,
			PERMISO_INSUFICIENTE: 16,
			CANCELADO: 20,
			INTERRUMPIDO: 130,
			INTERNO: 70,
		};
		expect(Object.keys(ERROR_EXITS)).toHaveLength(13);
		for (const [codigo, exit] of Object.entries(tabla)) {
			const err = new MctError(codigo, "x");
			expect(err.exit).toBe(exit);
			expect(err.codigo).toBe(codigo);
		}
	});

	it("ERR-002 redacta tokens de GitHub en mensaje, acción y detalle", () => {
		for (const p of ["ghp", "gho", "ghu", "ghs", "ghr"]) {
			const t = ghToken(p);
			expect(redactTokens(`fallo con ${t} al clonar`)).not.toContain(t);
		}
		const pat = `github_pat_${"Zz9_".repeat(12)}`;
		const t = ghToken("ghp");
		const err = new MctError("SIN_CREDENCIAL", `token ${t}`, {
			accion: `usa ${pat}`,
			detalle: { header: `Bearer ${t}` },
		});
		const json = JSON.stringify(err.toJSON());
		expect(json).not.toContain(t);
		expect(json).not.toContain(pat);
		expect(err.message).toContain("[REDACTADO]");
	});

	it("ERR-003 un código desconocido devuelve INTERNO con 70", () => {
		expect(exitFor("NO_EXISTE")).toBe(70);
		const err = new MctError("NO_EXISTE", "boom");
		expect(err.codigo).toBe("INTERNO");
		expect(err.exit).toBe(70);
	});

	it("ERR-004 serializa el formato de error de api.md", () => {
		const err = new MctError("PUERTA_BLOQUEADA", "Hay 3 hallazgos", {
			accion: "Corre: mct sanitize",
			etapa: "package",
			detalle: { abiertos: 3 },
		});
		expect(err.toJSON()).toEqual({
			error: {
				codigo: "PUERTA_BLOQUEADA",
				mensaje: "Hay 3 hallazgos",
				accion: "Corre: mct sanitize",
				etapa: "package",
				detalle: { abiertos: 3 },
			},
		});
	});

	it("ERR-005 pins fija gitleaks 8 y la imagen de n8n", () => {
		expect(GITLEAKS_MAJOR).toBe(8);
		expect(N8N_IMAGE_REF).toBe("n8nio/n8n:2.46.6");
	});
	it("ERR-006 redacta tokens precedidos de LF o TAB en el detalle", () => {
		const t = ghToken("ghp");
		for (const prefix of ["\n", "\t", "\r\n"]) {
			const err = new MctError("SIN_CREDENCIAL", "x", {
				detalle: {
					salida: `${prefix}${t}`,
					[`${prefix}${t}`]: 1,
					lista: [`${prefix}${t}`],
				},
			});
			expect(JSON.stringify(err.toJSON())).not.toContain(t);
			expect(inspect(err.detalle, { depth: 10 })).not.toContain(t);
		}
	});

	it("ERR-007 el detalle tolera ciclos, BigInt y Error sin lanzar", () => {
		const t = ghToken("ghs");
		const ciclo: Record<string, unknown> = { a: `\t${t}` };
		ciclo.self = ciclo;
		const make = () =>
			new MctError("INTERNO", "x", {
				detalle: { ciclo, grande: 10n, fallo: new Error(`boom ${t}`) },
			});
		expect(make).not.toThrow();
		const err = make();
		expect(JSON.stringify(err.toJSON())).not.toContain(t);
	});

	it("ERR-008 cause se sanea: sin token ni propiedades del error crudo", () => {
		const t = ghToken("gho");
		const crudo = Object.assign(new Error(`falló con ${t}`), {
			request: { headers: { authorization: `token ${t}` } },
			stderr: `
${t}`,
			command: `git clone ${t}`,
		});
		const err = new MctError("SIN_CREDENCIAL", "x", { cause: crudo });
		expect(err.cause).not.toBe(crudo);
		expect(inspect(err, { depth: 10, showHidden: true })).not.toContain(t);
		const cause = err.cause as Error;
		expect(cause.message).toContain("[REDACTADO]");
		expect(Object.keys(cause)).not.toContain("request");
		expect(Object.keys(cause)).not.toContain("stderr");
		expect(Object.keys(cause)).not.toContain("command");
	});
});
