import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";

const contenido = () => ({
	promesa: "Libera tu repo privado sin filtrar secretos.",
	porQueExiste:
		"Publicar un repo a mano deja pasar llaves y datos.\nEsto lo evita.",
	queObtienes: ["Escaneo de secretos", "README y licencia listos"],
	prompt: "Instala master-creator-tools y libera este repo.",
	queNecesitas: [{ que: "Node 22", paraQue: "correr mct", costo: "Gratis" }],
	comoFunciona: "Copia el repo, lo revisa y lo empaqueta.",
	faq: [{ p: "¿Publica solo?", r: "No. Siempre pide tu confirmación." }],
	siAlgoSaleMal: [{ sintoma: "verify falla", solucion: "Corre mct doctor" }],
	buenasPracticas: ["Revisa cada hallazgo"],
	creditos: [],
	repo: "El-Master-IA/master-creator-tools",
	laboratorio: "https://www.elmasteria.com/lab/master-creator-tools",
});

function falla(raw: unknown, campo: RegExp): MctError {
	let err: unknown;
	try {
		validateConfig(raw);
	} catch (e) {
		err = e;
	}
	expect(err).toBeInstanceOf(MctError);
	const e = err as MctError;
	expect(e.codigo).toBe("VALIDACION");
	expect(e.message).toMatch(campo);
	return e;
}

describe("CFG-003 readme en mct.config.json", () => {
	it("CFG-003 acepta el-master-ia con contenido válido y lo devuelve igual", () => {
		const raw = {
			readme: { plantilla: "el-master-ia", contenido: contenido() },
		};
		expect(validateConfig(raw).readme).toEqual(raw.readme);
	});

	it("CFG-003 acepta estandar sin contenido", () => {
		expect(
			validateConfig({ readme: { plantilla: "estandar" } }).readme,
		).toEqual({
			plantilla: "estandar",
		});
	});

	it("CFG-003 estandar con contenido es VALIDACION", () => {
		falla(
			{ readme: { plantilla: "estandar", contenido: contenido() } },
			/readme\.contenido/,
		);
	});

	it("CFG-003 el-master-ia sin contenido es VALIDACION", () => {
		falla({ readme: { plantilla: "el-master-ia" } }, /readme\.contenido/);
	});

	it("CFG-003 una plantilla desconocida es VALIDACION", () => {
		falla({ readme: { plantilla: "otra" } }, /readme\.plantilla/);
	});

	it("CFG-003 una clave desconocida en contenido es VALIDACION", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), extra: "x" },
				},
			},
			/readme\.contenido/,
		);
	});

	it("CFG-003 tres comillas invertidas nombran el campo sin repetir el valor", () => {
		const valor = ["fin", "``", "` del bloque raro"].join("");
		const e = falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), prompt: valor },
				},
			},
			/readme\.contenido\.prompt/,
		);
		expect(JSON.stringify({ m: e.message, d: e.detalle })).not.toContain(valor);
	});

	it("CFG-003 la secuencia de Eta está prohibida", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: {
						...contenido(),
						comoFunciona: `abre ${"<"}% it %> aquí`,
					},
				},
			},
			/readme\.contenido\.comoFunciona/,
		);
	});

	it("CFG-003 una línea no admite saltos y un texto sí", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), promesa: "dos\nlíneas largas aquí" },
				},
			},
			/readme\.contenido\.promesa/,
		);
	});

	it("CFG-003 caracteres invisibles son VALIDACION", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: {
						...contenido(),
						porQueExiste: "texto con​ invisible dentro",
					},
				},
			},
			/readme\.contenido\.porQueExiste/,
		);
	});

	it("CFG-003 límites de longitud y de cantidad", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), promesa: "corta" },
				},
			},
			/promesa/,
		);
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: {
						...contenido(),
						queObtienes: Array(13).fill("algo bueno"),
					},
				},
			},
			/queObtienes/,
		);
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), queObtienes: [] },
				},
			},
			/queObtienes/,
		);
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), prompt: "x".repeat(4001) },
				},
			},
			/prompt/,
		);
	});

	it("CFG-003 repo debe ser owner/nombre y laboratorio https", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), repo: "../x" },
				},
			},
			/repo/,
		);
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: {
						...contenido(),
						laboratorio: "http://www.elmasteria.com/lab",
					},
				},
			},
			/laboratorio/,
		);
	});

	it("CFG-003 repo y laboratorio son opcionales", () => {
		const c = contenido();
		delete (c as Partial<typeof c>).repo;
		delete (c as Partial<typeof c>).laboratorio;
		expect(
			validateConfig({ readme: { plantilla: "el-master-ia", contenido: c } })
				.readme,
		).toEqual({ plantilla: "el-master-ia", contenido: c });
	});

	it("CFG-003 queNecesitas y faq validan cada objeto", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), queNecesitas: [{ que: "Node" }] },
				},
			},
			/queNecesitas/,
		);
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), faq: [{ p: "¿Sí?", r: "Sí.", x: 1 }] },
				},
			},
			/faq/,
		);
	});

	it("CFG-003 los textos no abren bloques, títulos, reglas, tablas ni citas", () => {
		const c = (comoFunciona: string) => ({
			readme: {
				plantilla: "el-master-ia",
				contenido: { ...contenido(), comoFunciona },
			},
		});
		for (const t of [
			"uno\n~~~\ndos y tres",
			"uno\n# título falso",
			"uno\n---\ndos",
			"uno\n===",
			"uno\n| a | b |",
			"uno\n> cita",
		]) {
			falla(c(t), /readme\.contenido\.comoFunciona/);
		}
		expect(validateConfig(c("uno\ndos: tres - cuatro")).readme).toBeDefined();
	});

	it("CFG-003 el prompt sí admite esas líneas (va en un bloque de código)", () => {
		const prompt = "# Paso 1\n---\n> nota\n| tabla |";
		expect(
			validateConfig({
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), prompt },
				},
			}).readme,
		).toBeDefined();
	});

	it("CFG-003 sin enlaces ni imágenes Markdown fuera del prompt", () => {
		for (const comoFunciona of [
			"mira [esto](https://x.example/a) ahora",
			"pixel ![](https://x.example/p.gif) aquí",
		]) {
			falla(
				{
					readme: {
						plantilla: "el-master-ia",
						contenido: { ...contenido(), comoFunciona },
					},
				},
				/comoFunciona/,
			);
		}
	});

	it("CFG-003 laboratorio solo https simple y siAlgoSaleMal mide 3 o más", () => {
		for (const laboratorio of [
			"https:\\\\host\\lab",
			"https://x.example/a*b",
			'https://x.example/"y',
		]) {
			falla(
				{
					readme: {
						plantilla: "el-master-ia",
						contenido: { ...contenido(), laboratorio },
					},
				},
				/laboratorio/,
			);
		}
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: {
						...contenido(),
						siAlgoSaleMal: [{ sintoma: "a", solucion: "bien" }],
					},
				},
			},
			/siAlgoSaleMal/,
		);
	});

	it("CFG-003 una línea no admite separadores de línea Unicode", () => {
		falla(
			{
				readme: {
					plantilla: "el-master-ia",
					contenido: { ...contenido(), promesa: "una dos líneas aquí" },
				},
			},
			/promesa/,
		);
	});
});
