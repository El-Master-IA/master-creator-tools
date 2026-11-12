import type { Finding } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { renderReport } from "../src/report.js";

const finding: Finding = {
	id: "f1",
	motor: "mct",
	regla: "SEC-TEST",
	tipo: "pii",
	zona: "work",
	archivo: `${"carpeta/".repeat(20)}archivo-con-nombre-muy-largo.json`,
	linea: 1,
	columna: 1,
	fragmento: "[dic:1]",
	severidad: "alto",
	estado: "abierto",
};

function html(lang: "es" | "en" = "es"): string {
	return renderReport({
		lang,
		generadoEn: "2026-11-08T14:12:00Z",
		puertas: [{ etapa: "scan", estado: "ok" }],
		hallazgos: [finding],
		licencias: [],
	});
}

function css(source: string): string {
	return /<style>([\s\S]*?)<\/style>/.exec(source)?.[1] ?? "";
}

describe("PKG-004 responsive", () => {
	it("PKG-004 incluye meta viewport en es y en", () => {
		for (const lang of ["es", "en"] as const) {
			expect(html(lang)).toContain(
				'<meta name="viewport" content="width=device-width, initial-scale=1">',
			);
		}
	});

	it("PKG-004 no fija anchos mayores a 360 px ni scroll horizontal", () => {
		const style = css(html());
		for (const m of style.matchAll(
			/(?<![a-z-])(?:min-)?width\s*:\s*(\d+)px/g,
		)) {
			expect(Number(m[1])).toBeLessThanOrEqual(360);
		}
		expect(style).not.toMatch(/overflow-x\s*:\s*scroll/);
		expect(style).toContain("box-sizing:border-box");
		expect(style).toContain("overflow-wrap:anywhere");
		expect(style).toContain("max-width:68ch");
	});

	it("PKG-004 las tablas colapsan a lista bajo 640 px", () => {
		const style = css(html());
		const media = /@media \(max-width:640px\)\{([\s\S]*?)\n\}/.exec(style);
		expect(media).not.toBeNull();
		expect(media?.[1]).toContain("display:block");
		expect(media?.[1]).toContain("attr(data-label)");
	});

	it("PKG-004 objetivos táctiles de al menos 44 px y foco visible", () => {
		const style = css(html());
		expect(style).toContain("min-height:44px");
		expect(style).toContain("outline:2px solid var(--foco)");
	});

	it("PKG-004 sin animación fuera de prefers-reduced-motion", () => {
		const style = css(html());
		const sinReducida = style.replace(
			/@media \(prefers-reduced-motion:reduce\)\{[^\n]*\}/,
			"",
		);
		expect(sinReducida).not.toMatch(/animation|transition|@keyframes/);
		expect(style).toContain("prefers-reduced-motion:reduce");
	});

	it("PKG-004 sin degradados, webfonts ni recursos externos", () => {
		const out = html();
		expect(out).not.toMatch(/gradient\(/i);
		expect(out).not.toMatch(/@font-face|@import|url\(/i);
		expect(out).not.toMatch(/<(script|link|img|iframe)/i);
	});
});
