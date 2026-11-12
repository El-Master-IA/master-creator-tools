import { createRequire } from "node:module";
import { MctError } from "@mct/contract/errors";
import alternativesData from "../data/alternatives.json" with { type: "json" };

// spdx-expression-parse and spdx-satisfies are CommonJS without types.
const require = createRequire(import.meta.url);
const parseSpdx = require("spdx-expression-parse") as (
	expression: string,
) => SpdxNode;
const satisfies = require("spdx-satisfies") as (
	expression: string,
	approved: string[],
) => boolean;

export type Verdict = "ok" | "revisar" | "bloquea";

interface SpdxLeaf {
	license: string;
	plus?: boolean;
	exception?: string;
}
interface SpdxBranch {
	conjunction: "and" | "or";
	left: SpdxNode;
	right: SpdxNode;
}
type SpdxNode = SpdxLeaf | SpdxBranch;

export interface LicenseAllow {
	spdx: string;
	motivo: string;
	/** Package names the override is limited to; without it the override covers the whole tree. */
	paquetes?: string[];
}

export interface Alternative {
	paquete: string;
	licencia: string;
}

export interface PackageInput {
	paquete: string;
	version: string;
	spdx: string | null | undefined;
	origen: "directa" | "transitiva";
}

export interface LicenseEntry {
	paquete: string;
	version: string;
	spdx: string | null;
	origen: "directa" | "transitiva";
	veredicto: Verdict;
	alternativa?: Alternative[];
	override?: { motivo: string };
}

const RANK: Record<Verdict, number> = { ok: 0, revisar: 1, bloquea: 2 };

const BLOCK_PREFIXES = ["GPL-", "AGPL-", "SSPL-"];
const REVIEW_PREFIXES = ["LGPL-", "EPL-", "CC-BY-SA-"];
const REVIEW_EXACT = new Set(["MPL-2.0"]);
const OK_PREFIXES = ["BSD-"];
const OK_EXACT = new Set([
	"MIT",
	"ISC",
	"Apache-2.0",
	"0BSD",
	"Unlicense",
	"CC0-1.0",
]);
// npm's marker for proprietary / no-grant packages.
const PROPRIETARY = new Set(["UNLICENSED"]);

function worst(a: Verdict, b: Verdict): Verdict {
	return RANK[a] >= RANK[b] ? a : b;
}

function best(a: Verdict, b: Verdict): Verdict {
	return RANK[a] <= RANK[b] ? a : b;
}

// Anything not listed in the table is "revisar": never allowed by default.
function leafVerdict(id: string): Verdict {
	if (BLOCK_PREFIXES.some((p) => id.startsWith(p))) return "bloquea";
	if (REVIEW_EXACT.has(id) || REVIEW_PREFIXES.some((p) => id.startsWith(p))) {
		return "revisar";
	}
	if (OK_EXACT.has(id) || OK_PREFIXES.some((p) => id.startsWith(p))) {
		return "ok";
	}
	return "revisar";
}

function leafString(leaf: SpdxLeaf): string {
	return `${leaf.license}${leaf.plus ? "+" : ""}${
		leaf.exception ? ` WITH ${leaf.exception}` : ""
	}`;
}

function isBranch(node: SpdxNode): node is SpdxBranch {
	return "conjunction" in node;
}

function parseExpression(spdx: unknown): SpdxNode | undefined {
	if (typeof spdx !== "string") return undefined;
	const text = spdx.trim();
	if (text === "") return undefined;
	try {
		const node = parseSpdx(text);
		return node && typeof node === "object" ? node : undefined;
	} catch {
		return undefined;
	}
}

function leafAllowedBy(leaf: SpdxLeaf, allow: LicenseAllow): boolean {
	try {
		return satisfies(leafString(leaf), [allow.spdx]) === true;
	} catch {
		return false;
	}
}

function evaluate(
	node: SpdxNode,
	allow: readonly LicenseAllow[],
	used: Set<string>,
): Verdict {
	if (isBranch(node)) {
		const left = evaluate(node.left, allow, used);
		const right = evaluate(node.right, allow, used);
		if (node.conjunction === "or") return best(left, right);
		if (node.conjunction === "and") return worst(left, right);
		return "revisar";
	}
	if (typeof node.license !== "string") return "revisar";
	const base = leafVerdict(node.license);
	if (base === "ok") return base;
	const hit = allow.find((a) => leafAllowedBy(node, a));
	if (hit) {
		used.add(hit.motivo);
		return "ok";
	}
	return base;
}

function verdictWith(
	spdx: unknown,
	allow: readonly LicenseAllow[],
	used: Set<string>,
): Verdict {
	if (typeof spdx === "string" && PROPRIETARY.has(spdx.trim())) {
		return "bloquea";
	}
	const node = parseExpression(spdx);
	if (!node) return "revisar";
	return evaluate(node, allow, used);
}

/** Verdict of a SPDX expression per the table in pipeline.md (LIC-001). */
export function verdictForSpdx(spdx: string | null | undefined): Verdict {
	return verdictWith(spdx, [], new Set());
}

function validationError(mensaje: string, detalle?: Record<string, unknown>) {
	return new MctError("VALIDACION", mensaje, {
		accion: "Corrige licenses.allow en mct.config.json",
		...(detalle ? { detalle } : {}),
	});
}

const MIN_REASON_LENGTH = 5;
const MAX_SCOPED_PACKAGES = 200;
// npm package name: optional @scope/, lowercase-ish URL-safe chars, max 214.
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;

function parseScope(raw: unknown, index: number): string[] | undefined {
	if (raw === undefined) return undefined;
	if (!Array.isArray(raw) || raw.length === 0) {
		throw validationError(
			`licenses.allow[${index}].paquetes debe ser una lista no vacía de nombres de paquete`,
		);
	}
	if (raw.length > MAX_SCOPED_PACKAGES) {
		throw validationError(
			`licenses.allow[${index}].paquetes admite hasta ${MAX_SCOPED_PACKAGES} nombres`,
		);
	}
	const names = raw.map((name, j) => {
		if (
			typeof name !== "string" ||
			name.length > 214 ||
			!PACKAGE_NAME.test(name)
		) {
			throw validationError(
				`licenses.allow[${index}].paquetes[${j}] no es un nombre de paquete válido`,
			);
		}
		return name;
	});
	return [...new Set(names)];
}

/** Drops invisible format characters (U+200B, U+202E, ...) and trims (SEG-110). */
function cleanReason(motivo: string): string {
	return motivo.replace(/\p{Cf}/gu, "").trim();
}

/** Validates `licenses.allow` of mct.config.json; every entry needs a motivo (LIC-003). */
export function parseAllow(config: unknown): LicenseAllow[] {
	if (config === undefined || config === null) return [];
	if (typeof config !== "object" || Array.isArray(config)) {
		throw validationError("mct.config.json debe ser un objeto");
	}
	const licenses = (config as Record<string, unknown>).licenses;
	if (licenses === undefined) return [];
	if (
		licenses === null ||
		typeof licenses !== "object" ||
		Array.isArray(licenses)
	) {
		throw validationError("licenses debe ser un objeto");
	}
	const allow = (licenses as Record<string, unknown>).allow;
	if (allow === undefined) return [];
	if (!Array.isArray(allow)) {
		throw validationError("licenses.allow debe ser una lista");
	}
	return allow.map((raw, index) => {
		if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
			throw validationError(`licenses.allow[${index}] debe ser un objeto`);
		}
		const { spdx, motivo, paquetes } = raw as Record<string, unknown>;
		if (typeof spdx !== "string" || spdx.trim() === "") {
			throw validationError(`licenses.allow[${index}] necesita spdx`);
		}
		const node = parseExpression(spdx);
		if (!node || isBranch(node)) {
			throw validationError(
				`licenses.allow[${index}].spdx debe ser un identificador SPDX válido y simple`,
			);
		}
		const cleanMotivo =
			typeof motivo === "string" ? cleanReason(motivo) : undefined;
		if (cleanMotivo === undefined || cleanMotivo.length < MIN_REASON_LENGTH) {
			throw validationError(
				`licenses.allow[${index}] (${spdx.trim()}) necesita motivo de al menos ${MIN_REASON_LENGTH} caracteres visibles`,
			);
		}
		const scope = parseScope(paquetes, index);
		return scope
			? { spdx: spdx.trim(), motivo: cleanMotivo, paquetes: scope }
			: { spdx: spdx.trim(), motivo: cleanMotivo };
	});
}

let alternativesCache: Record<string, Alternative[]> | undefined;

/** Curated alternatives by package name (LIC-002). Fails closed on a malformed file. */
export function loadAlternatives(): Record<string, Alternative[]> {
	if (alternativesCache) return alternativesCache;
	const data: unknown = alternativesData;
	const table: Record<string, Alternative[]> = {};
	if (data === null || typeof data !== "object" || Array.isArray(data)) {
		throw new MctError("INTERNO", "alternatives.json con formato inválido");
	}
	for (const [name, list] of Object.entries(data)) {
		if (!Array.isArray(list)) {
			throw new MctError("INTERNO", "alternatives.json con formato inválido");
		}
		table[name] = list.map((item: unknown) => {
			const alt = item as Partial<Alternative> | null;
			if (
				!alt ||
				typeof alt.paquete !== "string" ||
				typeof alt.licencia !== "string" ||
				alt.paquete === "" ||
				alt.licencia === ""
			) {
				throw new MctError("INTERNO", "alternatives.json con formato inválido");
			}
			return { paquete: alt.paquete, licencia: alt.licencia };
		});
	}
	alternativesCache = table;
	return table;
}

export function alternativesFor(paquete: string): Alternative[] {
	const table = loadAlternatives();
	return Object.hasOwn(table, paquete) ? (table[paquete] ?? []) : [];
}

/** Judges one package: verdict, override (LIC-003) and alternatives if blocked (LIC-002). */
export function judgePackage(
	input: PackageInput,
	allow: readonly LicenseAllow[],
): LicenseEntry {
	const baseline = verdictForSpdx(input.spdx);
	const used = new Set<string>();
	// An override scoped with `paquetes` only applies to those packages (LIC-003).
	const applicable = allow.filter(
		(a) => a.paquetes === undefined || a.paquetes.includes(input.paquete),
	);
	const veredicto = verdictWith(input.spdx, applicable, used);
	const entry: LicenseEntry = {
		paquete: input.paquete,
		version: input.version,
		spdx: input.spdx ?? null,
		origen: input.origen,
		veredicto,
	};
	if (RANK[veredicto] < RANK[baseline] && used.size > 0) {
		entry.override = { motivo: [...used].join("; ") };
	}
	if (veredicto === "bloquea") {
		const alternativa = alternativesFor(input.paquete);
		if (alternativa.length > 0) entry.alternativa = alternativa;
	}
	return entry;
}

/** Terminal lines for the alternatives of a blocked package (LIC-002). */
export function formatAlternatives(entry: LicenseEntry): string[] {
	return (entry.alternativa ?? []).map(
		(alt) => `${entry.paquete} -> ${alt.paquete} (${alt.licencia})`,
	);
}

/** Exit 10 if anything is left in `bloquea` or `revisar` (LIC-001), else 0. */
export function gateExit(entries: readonly LicenseEntry[]): 0 | 10 {
	return entries.some((e) => e.veredicto !== "ok") ? 10 : 0;
}
