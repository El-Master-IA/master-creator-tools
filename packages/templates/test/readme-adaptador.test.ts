import { describe, expect, it } from "vitest";
import { estadoVerificacion, readmeConAdaptador } from "../src/readme.js";
import { PLANTILLAS_DOCS } from "../src/repo-docs.js";

const base = (ruta: string) => {
	const p = PLANTILLAS_DOCS.find((x) => x.ruta === ruta);
	if (!p) throw new Error("missing template");
	return p.plantilla;
};

describe("PKG-007 / VER-007 README por adaptador", () => {
	it("VER-007 generico agrega la sección tras requisitos y antes de instalación (ES)", () => {
		const out = readmeConAdaptador(base("README.es.md"), "generico", "es");
		expect(out).toContain("## Estado de la verificación");
		expect(out).toContain("Este proyecto no se probó en un contenedor");
		expect(out.indexOf("## Requisitos")).toBeLessThan(
			out.indexOf("## Estado de la verificación"),
		);
		expect(out.indexOf("## Estado de la verificación")).toBeLessThan(
			out.indexOf("## Instalación"),
		);
	});

	it("VER-007 generico agrega la sección en inglés", () => {
		const out = readmeConAdaptador(base("README.md"), "generico", "en");
		expect(out).toContain("## Verification status");
		expect(out).toContain("This project was not tested in a container");
		expect(out.indexOf("## Verification status")).toBeLessThan(
			out.indexOf("## Installation"),
		);
	});

	it("VER-007 python y estatico no llevan la sección", () => {
		for (const a of ["python", "estatico", "node", "n8n"]) {
			expect(readmeConAdaptador(base("README.md"), a, "en")).toBe(
				base("README.md"),
			);
		}
	});

	it("VER-007 sin ancla de instalación la sección va al final", () => {
		const out = readmeConAdaptador("# x\n", "generico", "en");
		expect(out.endsWith(estadoVerificacion("en"))).toBe(true);
	});
});
