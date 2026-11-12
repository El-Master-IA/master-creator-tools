import { MctError } from "@mct/contract/errors";
import type { Finding } from "@mct/contract/types";
import { Eta } from "eta";
import { describe, expect, it } from "vitest";
import {
	isMaskedFragment,
	REPORT_ETA_CONFIG,
	type ReportData,
	renderReport,
} from "../src/report.js";
import { REPORT_TEMPLATE } from "../src/report-template.js";

// Hostile strings are assembled from fragments so no payload sits whole in source.
const LT = "<";
const SCRIPT = `${LT}script>window.__pwn=1${LT}/script>`;
const IMG = `"${">"}${LT}img src=x on${"error"}=window.__pwn=1>`;
const HOSTILE_FILE = `${SCRIPT}${IMG}.js`;

function finding(over: Partial<Finding> = {}): Finding {
	return {
		id: "f1",
		motor: "mct",
		regla: "SEC-TEST",
		tipo: "secreto",
		zona: "work",
		archivo: "src/app.js",
		linea: 3,
		columna: 1,
		fragmento: "abcd****",
		severidad: "critico",
		estado: "abierto",
		...over,
	};
}

function data(hallazgos: Finding[]): ReportData {
	return {
		lang: "es",
		generadoEn: "2026-11-08T14:12:00Z",
		puertas: [
			{ etapa: "scan", estado: "ok" },
			{ etapa: "licenses", estado: "bloqueada" },
			{ etapa: "verify", estado: "pendiente" },
		],
		hallazgos,
		licencias: [
			{
				paquete: `pkg${SCRIPT}`,
				version: "1.0.0",
				spdx: "MIT",
				relacion: "directa",
				veredicto: IMG,
			},
		],
	};
}

/** Tag names and, for each tag, whether an on* attribute exists outside quotes. */
function inspectTags(html: string) {
	const names = new Set<string>();
	const handlers: string[] = [];
	const re = /<([a-zA-Z][a-zA-Z0-9-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
	for (const m of html.matchAll(re)) {
		names.add((m[1] ?? "").toLowerCase());
		const bare = (m[2] ?? "").replace(/"[^"]*"|'[^']*'/g, "");
		if (/\son[a-z]+\s*=/i.test(bare)) handlers.push(m[0]);
	}
	return { names, handlers };
}

const ALLOWED_TAGS = new Set([
	"html",
	"head",
	"meta",
	"title",
	"style",
	"body",
	"header",
	"main",
	"nav",
	"section",
	"h1",
	"h2",
	"p",
	"ul",
	"li",
	"strong",
	"span",
	"a",
	"details",
	"summary",
	"table",
	"caption",
	"thead",
	"tbody",
	"tr",
	"th",
	"td",
	"code",
]);

describe("REP-001 escape y CSP", () => {
	it("REP-001 escapa script y atributos on* en nombres de archivo", () => {
		const html = renderReport(data([finding({ archivo: HOSTILE_FILE })]));
		expect(html).not.toContain(`${LT}script`);
		expect(html).not.toContain(`${LT}img`);
		expect(html).toContain("&lt;script&gt;");
		const { names, handlers } = inspectTags(html);
		expect([...names].filter((n) => !ALLOWED_TAGS.has(n))).toEqual([]);
		expect(handlers).toEqual([]);
	});

	it("REP-001 escapa comillas en atributos (title, data-label)", () => {
		const html = renderReport(
			data([finding({ archivo: `a" autofocus on${"focus"}="x` })]),
		);
		expect(html).toContain('title="a&quot; autofocus onfocus=&quot;x"');
		const { handlers } = inspectTags(html);
		expect(handlers).toEqual([]);
	});

	it("REP-001 escapa regla, licencias y valores no confiables", () => {
		const html = renderReport(data([finding({ regla: SCRIPT, archivo: IMG })]));
		expect(html).not.toContain(`${LT}script`);
		expect(html).not.toContain(`${LT}img`);
		expect(inspectTags(html).handlers).toEqual([]);
	});

	it("REP-001 incluye la CSP exacta y no contiene JavaScript", () => {
		const html = renderReport(data([finding()]));
		expect(html).toContain(
			`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
		);
		expect(html).not.toMatch(/<script/i);
		expect(html).not.toMatch(/javascript:/i);
		expect(html).not.toMatch(/https?:\/\//i);
	});

	it("REP-001 rechaza un fragmento sin enmascarar", async () => {
		const raw = ["ghp", "_", "A".repeat(24)].join("");
		expect(() => renderReport(data([finding({ fragmento: raw })]))).toThrow(
			MctError,
		);
		try {
			renderReport(data([finding({ fragmento: raw })]));
		} catch (e) {
			expect((e as MctError).codigo).toBe("VALIDACION");
			expect(JSON.stringify((e as MctError).toJSON())).not.toContain(raw);
		}
	});

	it("REP-001 acepta solo fragmentos enmascarados", () => {
		expect(isMaskedFragment("abcd****")).toBe(true);
		expect(isMaskedFragment("ab••••")).toBe(true);
		expect(isMaskedFragment("[dic:3]")).toBe(true);
		expect(isMaskedFragment("abcde****")).toBe(false);
		expect(isMaskedFragment("abcd")).toBe(false);
		expect(isMaskedFragment("")).toBe(false);
		expect(isMaskedFragment("[dic:x]")).toBe(false);
	});

	it("REP-001 la versión instalada de Eta escapa con autoEscape y la plantilla no usa la etiqueta cruda", () => {
		expect(REPORT_ETA_CONFIG.autoEscape).toBe(true);
		const e = new Eta({ ...REPORT_ETA_CONFIG });
		expect(e.config.autoEscape).toBe(true);
		const out = e.renderString("<%= it.x %>", {
			x: `<a href="x" onclick='y'>&`,
		});
		expect(out).toBe("&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;");
		expect(REPORT_TEMPLATE).not.toContain("<%~");
		expect(REPORT_TEMPLATE).not.toContain("<%-");
	});

	it("REP-001 el orden del DOM es puertas, filtros, hallazgos, licencias", () => {
		const html = renderReport(data([finding()]));
		const idx = [
			"h-puertas",
			"<nav",
			'id="h-hallazgos"',
			'id="h-licencias"',
		].map((s) => html.indexOf(s));
		expect(idx.every((i) => i >= 0)).toBe(true);
		expect([...idx].sort((a, b) => a - b)).toEqual(idx);
		const sev = ["critico", "alto", "medio", "bajo"].map((s) =>
			html.indexOf(`id="sev-${s}"`),
		);
		expect([...sev].sort((a, b) => a - b)).toEqual(sev);
	});

	it("REP-001 sin datos muestra el texto de estado vacío", () => {
		const html = renderReport({ ...data([]), licencias: [] });
		expect(html).toContain(
			"Aún no hay resultados. Corre mct scan para llenar este reporte.",
		);
	});
});
