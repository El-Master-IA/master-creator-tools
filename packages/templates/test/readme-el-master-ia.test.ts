import type { ReadmeContenido } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { readmeElMaster } from "../src/readme-el-master-ia.js";
import { renderRepo } from "../src/render.js";

const FENCE = "`".repeat(3);

const contenido = (extra: Partial<ReadmeContenido> = {}): ReadmeContenido => ({
	promesa: "Libera tu repo privado sin filtrar secretos.",
	porQueExiste: "Publicar a mano deja pasar llaves.",
	queObtienes: ["Escaneo de secretos", "README listo"],
	prompt: "Instala mct y libera este repo <ya>.",
	queNecesitas: [{ que: "Node 22", paraQue: "correr mct", costo: "Gratis" }],
	comoFunciona: "Copia, revisa y empaqueta.",
	faq: [{ p: "¿Publica solo?", r: "No." }],
	siAlgoSaleMal: [{ sintoma: "verify falla", solucion: "mct doctor" }],
	buenasPracticas: ["Revisa cada hallazgo"],
	creditos: ["Gitleaks"],
	repo: "El-Master-IA/demo",
	laboratorio: "https://www.elmasteria.com/lab/demo",
	...extra,
});

const base = (c = contenido()) => ({
	nombre: "demo",
	titular: "El Máster IA",
	anio: 2026,
	contenido: c,
	queTrae: ["src/", "LICENSE", "README.md", "docs/"],
});

const titulos = (md: string): string[] =>
	md
		.split("\n")
		.filter((l) => l.startsWith("## "))
		.map((l) => l.slice(3));

describe("PKG-008 README el-master-ia", () => {
	it("PKG-008 el README en español sigue el orden de aduana", () => {
		const md = readmeElMaster(base(), "es");
		expect(titulos(md)).toEqual([
			"Por qué existe",
			"Qué obtienes",
			"Empieza aquí",
			"Qué necesitas",
			"Cómo funciona",
			"Preguntas frecuentes",
			"Si algo sale mal",
			"Buenas prácticas",
			"Qué trae",
			"Documentación",
			"Créditos",
			"Licencia",
		]);
		const lineas = md.split("\n");
		expect(lineas[0]).toBe("# demo");
		expect(lineas[2]).toBe(
			"> Read this in English: [README.en.md](README.en.md)",
		);
		expect(md).toContain(
			"[![CI](https://github.com/El-Master-IA/demo/actions/workflows/ci.yml/badge.svg)](https://github.com/El-Master-IA/demo/actions/workflows/ci.yml)",
		);
		expect(md).toContain(
			"**Libera tu repo privado sin filtrar secretos.**\n\nGratis y de código abierto.\n\n---",
		);
		expect(
			md
				.trimEnd()
				.endsWith(
					"Hecho con Claude Code por **El Máster IA · Alexander Cast**. Parte de [El Laboratorio](https://www.elmasteria.com/lab/demo).",
				),
		).toBe(true);
		expect(md).toContain(
			"MIT, © 2026 El Máster IA. Consulta [LICENSE](LICENSE). Los logos y marcas de terceros son de sus dueños.",
		);
	});

	it("PKG-008 el README en inglés tiene el mismo orden y enlaza al español", () => {
		const md = readmeElMaster(base(), "en");
		expect(titulos(md)).toEqual([
			"Why it exists",
			"What you get",
			"Start here",
			"What you need",
			"How it works",
			"FAQ",
			"If something goes wrong",
			"Good practices",
			"What's inside",
			"Documentation",
			"Credits",
			"License",
		]);
		expect(md.split("\n")[2]).toBe(
			"> Lee esto en español: [README.md](README.md)",
		);
		expect(md).toContain("Free and open source.");
		expect(md).toContain(
			"Made with Claude Code by **El Máster IA · Alexander Cast**.",
		);
	});

	it("PKG-008 el prompt va crudo en un bloque y el resto sale escapado", () => {
		const md = readmeElMaster(
			base(contenido({ comoFunciona: "Usa <script> & listo." })),
			"es",
		);
		expect(md).toContain(
			`${FENCE}text\nInstala mct y libera este repo <ya>.\n${FENCE}`,
		);
		expect(md).toContain("Usa &lt;script&gt; &amp; listo.");
		expect(md).not.toContain("<script>");
	});

	it("PKG-008 las secciones opcionales vacías no aparecen y sin repo no hay badge", () => {
		const c = contenido({
			queNecesitas: [],
			faq: [],
			siAlgoSaleMal: [],
			buenasPracticas: [],
			creditos: [],
		});
		delete c.repo;
		delete c.laboratorio;
		const md = readmeElMaster(base(c), "es");
		expect(titulos(md)).toEqual([
			"Por qué existe",
			"Qué obtienes",
			"Empieza aquí",
			"Cómo funciona",
			"Qué trae",
			"Documentación",
			"Licencia",
		]);
		expect(md).not.toContain("badge.svg");
		expect(md).not.toContain("El Laboratorio");
		expect(
			md
				.trimEnd()
				.endsWith(
					"Hecho con Claude Code por **El Máster IA · Alexander Cast**.",
				),
		).toBe(true);
	});

	it("PKG-008 Qué trae ordena, limita a 40 y descarta nombres raros", () => {
		const queTrae = [
			...Array.from({ length: 45 }, (_, i) => `f${String(i).padStart(2, "0")}`),
			"raro`nombre",
		];
		const md = readmeElMaster({ ...base(), queTrae }, "es");
		const bloque = md.split("## Qué trae\n\n")[1]?.split(`\n${FENCE}`)[0] ?? "";
		const lineas = bloque.split("\n").slice(1);
		expect(lineas).toHaveLength(40);
		expect(lineas[0]).toBe("f00");
		expect(md).not.toContain("raro`nombre");
	});

	it("PKG-008 una tabla no se rompe con un pipe en el contenido", () => {
		const md = readmeElMaster(
			base(
				contenido({ queNecesitas: [{ que: "a|b", paraQue: "x", costo: "0" }] }),
			),
			"es",
		);
		expect(md).toContain("| a\\|b | x | 0 |");
	});

	it("PKG-008 con el adaptador genérico va la verificación antes de Qué necesitas", () => {
		const md = readmeElMaster({ ...base(), adaptador: "generico" }, "es");
		const t = titulos(md);
		expect(t.indexOf("Estado de la verificación")).toBe(
			t.indexOf("Qué necesitas") - 1,
		);
	});
});

describe("PKG-008 / PKG-002 renderRepo con la plantilla", () => {
	const input = {
		hints: {
			instalacion: ["npm ci"],
			uso: ["npm start"],
			variables: [],
			requisitos: [],
		},
		titular: "El Máster IA",
		nombre: "demo",
		anio: 2026,
	};

	it("PKG-008 el-master-ia da README.md y README.en.md y no README.es.md", () => {
		const rutas = renderRepo({
			...input,
			readme: { plantilla: "el-master-ia", contenido: contenido() },
			queTrae: ["src/"],
		}).map((f) => f.ruta);
		expect(rutas).toContain("README.md");
		expect(rutas).toContain("README.en.md");
		expect(rutas).not.toContain("README.es.md");
		expect(rutas.filter((r) => r === "README.md")).toHaveLength(1);
		expect(rutas).toContain("LICENSE");
		expect(rutas).toContain("docs/es/uso.md");
	});

	it("PKG-002 sin readme o con estandar la salida es la misma de siempre", () => {
		const sin = renderRepo(input);
		const estandar = renderRepo({
			...input,
			readme: { plantilla: "estandar" },
		});
		expect(estandar).toEqual(sin);
		expect(sin.map((f) => f.ruta)).toContain("README.es.md");
		expect(sin.map((f) => f.ruta)).not.toContain("README.en.md");
	});
});
