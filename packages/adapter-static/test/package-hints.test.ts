import { describe, expect, it } from "vitest";
import { staticAdapter } from "../src/index.js";

const base = { stack: ["estatico"], deps: [], comandos: {} };

describe("PKG-007 packageHints estatico", () => {
	it("PKG-007 requisitos un navegador, uso abre index.html y variables de WEB-001", () => {
		const h = staticAdapter.packageHints({
			...base,
			entrypoints: ["index.html"],
			envVars: [{ nombre: "SITE_URL", obligatoria: false }],
		});
		expect(h.requisitos).toEqual(["Un navegador"]);
		expect(h.instalacion).toEqual([]);
		expect(h.uso[0]).toContain("index.html");
		expect(h.variables.map((v) => v.nombre)).toEqual(["SITE_URL"]);
	});

	it("PKG-007 con el sitio en una subcarpeta usa python -m http.server", () => {
		const h = staticAdapter.packageHints({
			...base,
			entrypoints: ["docs/index.html"],
			envVars: [],
		});
		expect(h.uso[0]).toContain("python -m http.server");
		expect(h.uso[0]).toContain("docs");
	});
});
