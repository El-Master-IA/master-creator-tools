import { expect, type Page, test } from "playwright/test";
import type { Finding } from "../packages/contract/src/types.js";
import { renderReport } from "../packages/templates/src/report.js";

function finding(id: string, severidad: Finding["severidad"]): Finding {
	return {
		id,
		motor: "mct",
		regla: "SEC-TEST",
		tipo: "pii",
		zona: "work",
		archivo: `${"carpeta/".repeat(20)}archivo-con-nombre-muy-largo.json`,
		linea: 1,
		columna: 1,
		fragmento: "[dic:1]",
		severidad,
		estado: "abierto",
	};
}

const puertas = [
	{ etapa: "scan", estado: "ok" },
	{ etapa: "sanitize", estado: "pendiente" },
] as const;

function fullReport(): string {
	return renderReport({
		lang: "es",
		generadoEn: "2026-11-08T14:12:00Z",
		puertas: [...puertas],
		hallazgos: [
			finding("a", "critico"),
			finding("b", "alto"),
			finding("c", "medio"),
			finding("d", "bajo"),
		],
		licencias: [
			{
				paquete: `${"paquete-largo-".repeat(8)}x`,
				version: "1.0.0",
				spdx: "MIT",
				relacion: "directa",
				veredicto: "permitida",
			},
		],
	});
}

function emptyReport(): string {
	return renderReport({
		lang: "es",
		generadoEn: "2026-11-08T14:12:00Z",
		puertas: [...puertas],
		hallazgos: [],
		licencias: [],
	});
}

interface Stop {
	tag: string;
	label: string;
	href: string;
	visible: boolean;
	top: number;
}

// Browser-side scripts are strings: the project tsconfig has no DOM lib.
const STOP_SCRIPT = `(() => {
	const el = document.activeElement;
	if (el === null || el === document.body) return null;
	const cs = getComputedStyle(el);
	const rect = el.getBoundingClientRect();
	return {
		tag: el.tagName.toLowerCase(),
		label: (el.textContent ?? "").trim(),
		href: el.getAttribute("href") ?? "",
		visible:
			el.matches(":focus-visible") &&
			cs.outlineStyle !== "none" &&
			Number.parseFloat(cs.outlineWidth) >= 2 &&
			cs.outlineColor !== "rgba(0, 0, 0, 0)" &&
			rect.width > 0 &&
			rect.height > 0,
		top: rect.top + window.scrollY,
	};
})()`;

const ORDER_SCRIPT = `(() => {
	const items = [
		["h-puertas", document.getElementById("h-puertas")],
		["nav-filtros", document.querySelector("nav.nav-filtros")],
		["h-hallazgos", document.getElementById("h-hallazgos")],
		["h-licencias", document.getElementById("h-licencias")],
	].filter((x) => x[1] !== null);
	items.sort((a, b) =>
		a[1].compareDocumentPosition(b[1]) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1,
	);
	return items.map((x) => x[0]);
})()`;

const WIDTH_SCRIPT = `({
	scroll: document.documentElement.scrollWidth,
	client: document.documentElement.clientWidth,
})`;

function isStop(value: unknown): value is Stop {
	if (typeof value !== "object" || value === null) return false;
	const v = value as Record<string, unknown>;
	return (
		typeof v.tag === "string" &&
		typeof v.label === "string" &&
		typeof v.href === "string" &&
		typeof v.visible === "boolean" &&
		typeof v.top === "number"
	);
}

/** Presses Tab until focus leaves the document, collecting each stop. */
async function tabStops(page: Page): Promise<Stop[]> {
	const stops: Stop[] = [];
	for (let i = 0; i < 40; i++) {
		await page.keyboard.press("Tab");
		const stop: unknown = await page.evaluate(STOP_SCRIPT);
		if (stop === null) return stops;
		if (!isStop(stop)) throw new Error("unexpected focus probe result");
		stops.push(stop);
	}
	throw new Error("focus never left the document after 40 Tab presses");
}

/** Document order of the four report landmarks. */
async function landmarkOrder(page: Page): Promise<string[]> {
	const order: unknown = await page.evaluate(ORDER_SCRIPT);
	if (!Array.isArray(order)) throw new Error("unexpected order result");
	return order.map(String);
}

async function expectNoHorizontalScroll(page: Page): Promise<void> {
	const w = (await page.evaluate(WIDTH_SCRIPT)) as {
		scroll: number;
		client: number;
	};
	expect(w.scroll).toBeLessThanOrEqual(w.client);
}

test.describe("ACC-001 report.html con teclado", () => {
	test("ACC-001 Tab sigue el orden resumen, filtros, hallazgos y licencias", async ({
		page,
	}) => {
		await page.setContent(fullReport());
		expect(await landmarkOrder(page)).toEqual([
			"h-puertas",
			"nav-filtros",
			"h-hallazgos",
			"h-licencias",
		]);

		const stops = await tabStops(page);
		const hrefs = stops.filter((s) => s.tag === "a").map((s) => s.href);
		expect(hrefs).toEqual([
			"#sev-critico",
			"#sev-alto",
			"#sev-medio",
			"#sev-bajo",
			"#licencias",
		]);
		const summaries = stops.filter((s) => s.tag === "summary");
		expect(summaries).toHaveLength(4);
		// Filters first, then findings groups from critico to bajo.
		expect(stops.map((s) => s.tag)).toEqual([
			"a",
			"a",
			"a",
			"a",
			"a",
			"summary",
			"summary",
			"summary",
			"summary",
		]);
		expect(summaries.map((s) => s.label)).toEqual([
			expect.stringContaining("CRÍTICO"),
			expect.stringContaining("ALTO"),
			expect.stringContaining("MEDIO"),
			expect.stringContaining("BAJO"),
		]);
		// Focus order equals visual (vertical) order within the findings groups.
		const tops = summaries.map((s) => s.top);
		expect(tops).toEqual([...tops].sort((a, b) => a - b));
	});

	test("ACC-001 cada elemento enfocado muestra foco visible", async ({
		page,
	}) => {
		await page.setContent(fullReport());
		const stops = await tabStops(page);
		expect(stops.length).toBeGreaterThan(0);
		for (const s of stops) {
			expect(s.visible, `${s.tag} ${s.label}`).toBe(true);
		}
	});

	test("ACC-001 sin scroll horizontal a 360 px", async ({ page }) => {
		await page.setViewportSize({ width: 360, height: 740 });
		await page.setContent(fullReport());
		await expectNoHorizontalScroll(page);
	});

	test("ACC-001 estado vacío mantiene el orden de foco", async ({ page }) => {
		await page.setViewportSize({ width: 360, height: 740 });
		await page.setContent(emptyReport());
		await expect(page.locator(".vacio")).toBeVisible();
		expect(await landmarkOrder(page)).toEqual([
			"h-puertas",
			"nav-filtros",
			"h-hallazgos",
			"h-licencias",
		]);
		const stops = await tabStops(page);
		expect(stops.map((s) => s.tag)).toEqual([
			"a",
			"a",
			"a",
			"a",
			"a",
			"summary",
			"summary",
			"summary",
			"summary",
		]);
		for (const s of stops) {
			expect(s.visible, `${s.tag} ${s.label}`).toBe(true);
		}
		await expectNoHorizontalScroll(page);
	});
});
