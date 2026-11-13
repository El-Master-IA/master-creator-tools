import { MctError } from "@mct/contract/errors";
import type { PackageHints, ReadmeConfig } from "@mct/contract/types";
import { Eta } from "eta";
import { readmeConAdaptador } from "./readme.js";
import { readmeElMaster } from "./readme-el-master-ia.js";
import { PLANTILLAS_COMUNIDAD } from "./repo-community.js";
import { PLANTILLAS_DOCS } from "./repo-docs.js";
import {
	type CiOpciones,
	ciParaAdaptador,
	PLANTILLAS_GITHUB,
} from "./repo-github.js";

export interface RepoInput {
	hints: PackageHints;
	/** Copyright holder for LICENSE; required. */
	titular: string;
	/** Project name for the READMEs. */
	nombre: string;
	/** Copyright year. */
	anio: number;
	/** Adapter id; absent keeps the node CI and the plain README. */
	adaptador?: string;
	/** CI data from the Analysis (PKG-006). */
	ci?: Omit<CiOpciones, "adaptador">;
	/** README template (CFG-003); absent or "estandar" keeps the plain README. */
	readme?: ReadmeConfig;
	/** First-level entries of dist/ for "Qué trae" (PKG-008). */
	queTrae?: string[];
}

export interface RepoFile {
	/** POSIX relative path inside dist/. */
	ruta: string;
	contenido: string;
}

const MAX_TEXT = 200;
const MAX_ITEMS = 100;
const CONTROL = /\p{Cc}/u;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

// Templates carry only scalars validated here; raw output keeps commands intact.
const eta = new Eta({ autoEscape: false, autoTrim: false, cache: false });

function line(value: unknown, what: string): string {
	if (typeof value !== "string") {
		throw new MctError("VALIDACION", `${what} must be a string`);
	}
	const v = value.trim();
	if (v === "" || v.length > MAX_TEXT || CONTROL.test(v)) {
		throw new MctError(
			"VALIDACION",
			`${what} must be a non-empty single line of at most ${MAX_TEXT} characters`,
		);
	}
	// Eta tag opener and markdown fences would break or inject structure.
	if (v.includes("<%") || v.includes("```")) {
		throw new MctError("VALIDACION", `${what} contains a forbidden sequence`);
	}
	return v;
}

function list(value: unknown, what: string): string[] {
	if (!Array.isArray(value) || value.length > MAX_ITEMS) {
		throw new MctError("VALIDACION", `${what} must be a short list`);
	}
	return value.map((x) => line(x, `${what} item`));
}

interface Texts {
	none: string;
	required: string;
	optional: string;
}
const TEXTS: Record<"es" | "en", Texts> = {
	es: { none: "Ninguno.", required: "obligatoria", optional: "opcional" },
	en: { none: "None.", required: "required", optional: "optional" },
};

function bullets(items: string[], t: Texts): string {
	return items.length === 0 ? t.none : items.map((i) => `- ${i}`).join("\n");
}

function steps(items: string[], t: Texts): string {
	if (items.length === 0) return t.none;
	return `\`\`\`sh\n${items.join("\n")}\n\`\`\``;
}

export function renderRepo(input: RepoInput): RepoFile[] {
	const titular = line(input?.titular, "titular");
	const nombre = line(input?.nombre, "nombre");
	if (!Number.isInteger(input.anio) || input.anio < 1970 || input.anio > 9999) {
		throw new MctError("VALIDACION", "anio must be a four-digit year");
	}
	const h = input.hints;
	if (h === null || typeof h !== "object") {
		throw new MctError("VALIDACION", "hints are required");
	}
	const instalacion = list(h.instalacion, "instalacion");
	const uso = list(h.uso, "uso");
	const requisitos = list(h.requisitos, "requisitos");
	if (!Array.isArray(h.variables) || h.variables.length > MAX_ITEMS) {
		throw new MctError("VALIDACION", "variables must be a short list");
	}
	const vars = h.variables.map((v) => {
		if (typeof v?.nombre !== "string" || !ENV_NAME.test(v.nombre)) {
			throw new MctError("VALIDACION", "variable name is not valid");
		}
		return {
			nombre: v.nombre,
			descripcion: line(v.descripcion, "variable description"),
			obligatoria: v.obligatoria === true,
		};
	});

	const envLineas = vars.map((v) => `${v.nombre}=`).join("\n");
	const render = (lang: "es" | "en", plantilla: string): string => {
		const t = TEXTS[lang];
		const variables =
			vars.length === 0
				? t.none
				: vars
						.map(
							(v) =>
								`- \`${v.nombre}\` (${v.obligatoria ? t.required : t.optional}): ${v.descripcion}`,
						)
						.join("\n");
		return eta.renderString(plantilla, {
			titular,
			nombre,
			anio: input.anio,
			requisitos: bullets(requisitos, t),
			instalacion: steps(instalacion, t),
			uso: steps(uso, t),
			variables,
			envLineas,
		});
	};

	const elMaster =
		input.readme?.plantilla === "el-master-ia" ? input.readme : undefined;
	const out: RepoFile[] = [];
	if (elMaster !== undefined) {
		const base = {
			nombre,
			titular,
			anio: input.anio,
			contenido: elMaster.contenido,
			queTrae: input.queTrae ?? [],
			...(input.adaptador !== undefined && { adaptador: input.adaptador }),
		};
		out.push(
			{ ruta: "README.md", contenido: readmeElMaster(base, "es") },
			{ ruta: "README.en.md", contenido: readmeElMaster(base, "en") },
		);
	}
	for (const p of [
		...PLANTILLAS_DOCS,
		...PLANTILLAS_COMUNIDAD,
		...PLANTILLAS_GITHUB,
	]) {
		if (
			elMaster !== undefined &&
			(p.ruta === "README.md" || p.ruta === "README.es.md")
		) {
			continue;
		}
		const lang =
			p.ruta.includes("/es/") || p.ruta.endsWith(".es.md") ? "es" : "en";
		if (p.ruta === ".github/workflows/ci.yml" && input.adaptador) {
			// Built by code (no Eta): only static text plus pinned versions.
			out.push({
				ruta: p.ruta,
				contenido: ciParaAdaptador({ ...input.ci, adaptador: input.adaptador }),
			});
			continue;
		}
		let contenido = render(lang, p.plantilla);
		if (
			input.adaptador &&
			(p.ruta === "README.md" || p.ruta === "README.es.md")
		) {
			contenido = readmeConAdaptador(contenido, input.adaptador, lang);
		}
		out.push({ ruta: p.ruta, contenido });
	}
	return out;
}
