import { describe, expect, it } from "vitest";
import {
	alternativesFor,
	formatAlternatives,
	judgePackage,
	loadAlternatives,
	verdictForSpdx,
} from "../src/verdict.js";

describe("LIC-002 alternatives", () => {
	it("LIC-002 a blocked package listed in alternatives.json shows alternatives with license", () => {
		const table = loadAlternatives();
		const name = "ckeditor5";
		expect(table[name]?.length).toBeGreaterThan(0);
		const entry = judgePackage(
			{
				paquete: name,
				version: "44.0.0",
				spdx: "GPL-2.0-or-later",
				origen: "directa",
			},
			[],
		);
		expect(entry.veredicto).toBe("bloquea");
		expect(entry.alternativa?.length).toBeGreaterThan(0);
		for (const alt of entry.alternativa ?? []) {
			expect(alt.paquete.length).toBeGreaterThan(0);
			expect(alt.licencia.length).toBeGreaterThan(0);
		}
		const json = JSON.parse(JSON.stringify(entry));
		expect(json.alternativa[0].licencia).toBeTypeOf("string");
		const lines = formatAlternatives(entry).join("\n");
		expect(lines).toContain(entry.alternativa?.[0]?.paquete);
		expect(lines).toContain(entry.alternativa?.[0]?.licencia);
	});

	it("LIC-002 every curated alternative has a name and a non-blocking SPDX license", () => {
		for (const [pkg, alts] of Object.entries(loadAlternatives())) {
			expect(pkg.length).toBeGreaterThan(0);
			expect(alts.length).toBeGreaterThan(0);
			for (const alt of alts) {
				expect(alt.paquete.length).toBeGreaterThan(0);
				expect(verdictForSpdx(alt.licencia), alt.paquete).toBe("ok");
			}
		}
	});

	it("LIC-002 packages not listed or not blocked get no alternative", () => {
		expect(alternativesFor("no-such-package-xyz")).toEqual([]);
		const entry = judgePackage(
			{
				paquete: "ckeditor5",
				version: "1.0.0",
				spdx: "MIT",
				origen: "directa",
			},
			[],
		);
		expect(entry.alternativa).toBeUndefined();
		const unknown = judgePackage(
			{
				paquete: "no-such-package-xyz",
				version: "1.0.0",
				spdx: "GPL-3.0",
				origen: "transitiva",
			},
			[],
		);
		expect(unknown.veredicto).toBe("bloquea");
		expect(unknown.alternativa).toBeUndefined();
	});
});
