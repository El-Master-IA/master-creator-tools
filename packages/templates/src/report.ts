import { MctError } from "@mct/contract/errors";
import type {
	EstadoEtapa,
	Etapa,
	Finding,
	Severidad,
} from "@mct/contract/types";
import { Eta } from "eta";
import { REPORT_TEMPLATE } from "./report-template.js";

export type ReportLang = "es" | "en";

export interface LicenseRow {
	paquete: string;
	version: string;
	spdx: string;
	relacion: "directa" | "transitiva";
	veredicto: string;
	alternativa?: string;
}

export interface ReportData {
	lang: ReportLang;
	/** ISO-8601 UTC; shown as local time with offset (DESIGN.md). */
	generadoEn: string;
	puertas: { etapa: Etapa; estado: EstadoEtapa }[];
	hallazgos: Finding[];
	licencias: LicenseRow[];
}

const SEVERIDADES: readonly Severidad[] = ["critico", "alto", "medio", "bajo"];
const ESTADOS: readonly EstadoEtapa[] = ["pendiente", "ok", "bloqueada"];

const SIMBOLO_SEV: Record<Severidad, string> = {
	critico: "✖",
	alto: "▲",
	medio: "◆",
	bajo: "○",
};
const SIMBOLO_ESTADO: Record<EstadoEtapa, string> = {
	ok: "✔",
	bloqueada: "✖",
	pendiente: "○",
};

const TEXTOS = {
	es: {
		title: "Reporte de mct",
		generated: "Generado",
		gates: "Puertas",
		filters: "Filtros",
		findings: "Hallazgos",
		licenses: "Licencias",
		file: "Archivo",
		line: "Línea",
		rule: "Regla",
		fragment: "Fragmento",
		status: "Estado",
		pkg: "Paquete",
		version: "Versión",
		relation: "Relación",
		verdict: "Veredicto",
		alternative: "Alternativa",
		none: "Sin elementos.",
		empty: "Aún no hay resultados. Corre mct scan para llenar este reporte.",
		sev: { critico: "CRÍTICO", alto: "ALTO", medio: "MEDIO", bajo: "BAJO" },
		estado: { ok: "pasa", bloqueada: "bloqueada", pendiente: "pendiente" },
	},
	en: {
		title: "mct report",
		generated: "Generated",
		gates: "Gates",
		filters: "Filters",
		findings: "Findings",
		licenses: "Licenses",
		file: "File",
		line: "Line",
		rule: "Rule",
		fragment: "Fragment",
		status: "Status",
		pkg: "Package",
		version: "Version",
		relation: "Relation",
		verdict: "Verdict",
		alternative: "Alternative",
		none: "No items.",
		empty: "No results yet. Run mct scan to fill this report.",
		sev: { critico: "CRITICAL", alto: "HIGH", medio: "MEDIUM", bajo: "LOW" },
		estado: { ok: "passed", bloqueada: "blocked", pendiente: "pending" },
	},
} as const;

/** Masked: at most 4 real chars + fixed mask, or a `[dic:N]` reference. */
const MASKED = /^(?:[^*•]{0,4}(?:\*{4}|•{4})|\[dic:\d+\])$/u;

export function isMaskedFragment(value: string): boolean {
	return MASKED.test(value);
}

function two(n: number): string {
	return String(n).padStart(2, "0");
}

/** `AAAA-MM-DD HH:MM ±HH:MM` in local time. */
export function formatLocal(iso: string): string {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) {
		throw new MctError("VALIDACION", "generadoEn must be an ISO-8601 date");
	}
	const off = -d.getTimezoneOffset();
	const sign = off >= 0 ? "+" : "-";
	const abs = Math.abs(off);
	return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())} ${two(d.getHours())}:${two(d.getMinutes())} ${sign}${two(Math.floor(abs / 60))}:${two(abs % 60)}`;
}

// autoEscape is stated explicitly: every interpolation goes through XML
// escaping (& < > " '). The raw tag is not used by the template.
export const REPORT_ETA_CONFIG = {
	autoEscape: true,
	autoFilter: false,
	cache: false,
} as const;

const eta = new Eta({ ...REPORT_ETA_CONFIG });

export function renderReport(data: ReportData): string {
	const t = Object.hasOwn(TEXTOS, data.lang) ? TEXTOS[data.lang] : undefined;
	if (t === undefined) {
		throw new MctError("VALIDACION", "lang must be es or en");
	}
	for (const f of data.hallazgos) {
		if (!SEVERIDADES.includes(f.severidad)) {
			throw new MctError("VALIDACION", "Unknown severity in finding");
		}
		if (!isMaskedFragment(f.fragmento)) {
			throw new MctError(
				"VALIDACION",
				"Report refused: a fragment is not masked",
				{
					accion: "Mask the fragment (max 4 real characters) before rendering",
					detalle: { regla: f.regla },
				},
			);
		}
	}
	for (const p of data.puertas) {
		if (!ESTADOS.includes(p.estado)) {
			throw new MctError("VALIDACION", "Unknown gate state");
		}
	}

	const grupos = SEVERIDADES.map((s) => {
		const items = data.hallazgos.filter((f) => f.severidad === s);
		return {
			severidad: s,
			palabra: t.sev[s],
			simbolo: SIMBOLO_SEV[s],
			total: items.length,
			abierto: s === "critico" || s === "alto",
			items,
		};
	});

	return eta.renderString(REPORT_TEMPLATE, {
		lang: data.lang,
		t,
		generadoEn: formatLocal(data.generadoEn),
		puertas: data.puertas.map((p) => ({
			etapa: p.etapa,
			estado: p.estado,
			simbolo: SIMBOLO_ESTADO[p.estado],
			palabra: t.estado[p.estado],
		})),
		grupos,
		vacio: data.hallazgos.length === 0 && data.licencias.length === 0,
		licencias: data.licencias.map((l) => ({
			...l,
			alternativa: l.alternativa ?? "",
		})),
	});
}
