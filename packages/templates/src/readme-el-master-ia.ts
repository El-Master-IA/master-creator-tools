/**
 * PKG-008: README with the El Máster IA structure (the aduana order), built by
 * code. Content comes from `mct.config.json` › `readme.contenido`, already
 * validated by CFG-003; here it is only escaped and placed.
 */
import type { ReadmeContenido } from "@mct/contract/types";
import { estadoVerificacion, type Lang } from "./readme.js";

export interface ElMasterInput {
	nombre: string;
	titular: string;
	anio: number;
	adaptador?: string;
	contenido: ReadmeContenido;
	/** First-level entries of dist/, folders end with "/". */
	queTrae: string[];
}

const FENCE = "`".repeat(3);
const MAX_QUE_TRAE = 40;

/** HTML entities for author text outside code blocks. */
export function escapar(t: string): string {
	return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Table cells: escaped, one line, no pipe that would split the cell. */
const celda = (t: string): string => escapar(t).replace(/\|/g, "\\|");

interface Textos {
	otro: string;
	gratis: string;
	porQue: string;
	queObtienes: string;
	empieza: string;
	empiezaIntro: string;
	queNecesitas: string;
	cabNecesitas: [string, string, string];
	comoFunciona: string;
	faq: string;
	siAlgo: string;
	cabSiAlgo: [string, string];
	practicas: string;
	queTrae: string;
	docs: string;
	docsLista: (d: string) => string[];
	creditos: string;
	licencia: string;
	licenciaTexto: (anio: number, titular: string) => string;
	firma: string;
	parte: (url: string) => string;
}

const T: Record<Lang, Textos> = {
	es: {
		otro: "> Read this in English: [README.en.md](README.en.md)",
		gratis: "Gratis y de código abierto.",
		porQue: "Por qué existe",
		queObtienes: "Qué obtienes",
		empieza: "Empieza aquí",
		empiezaIntro: "Copia este prompt en Claude Code:",
		queNecesitas: "Qué necesitas",
		cabNecesitas: ["Qué", "Para qué", "Costo"],
		comoFunciona: "Cómo funciona",
		faq: "Preguntas frecuentes",
		siAlgo: "Si algo sale mal",
		cabSiAlgo: ["Síntoma", "Solución"],
		practicas: "Buenas prácticas",
		queTrae: "Qué trae",
		docs: "Documentación",
		docsLista: () => [
			"[Instalación](docs/es/instalacion.md)",
			"[Uso](docs/es/uso.md)",
			"[Qué hacer ante un incidente](docs/es/incidentes.md)",
			"[Cómo contribuir](CONTRIBUTING.md), [código de conducta](CODE_OF_CONDUCT.md) y [seguridad](SECURITY.md)",
		],
		creditos: "Créditos",
		licencia: "Licencia",
		licenciaTexto: (anio, titular) =>
			`MIT, © ${anio} ${titular}. Consulta [LICENSE](LICENSE). Los logos y marcas de terceros son de sus dueños.`,
		firma: "Hecho con Claude Code por **El Máster IA · Alexander Cast**.",
		parte: (url) => `Parte de [El Laboratorio](${url}).`,
	},
	en: {
		otro: "> Lee esto en español: [README.md](README.md)",
		gratis: "Free and open source.",
		porQue: "Why it exists",
		queObtienes: "What you get",
		empieza: "Start here",
		empiezaIntro: "Paste this prompt into Claude Code:",
		queNecesitas: "What you need",
		cabNecesitas: ["What", "What for", "Cost"],
		comoFunciona: "How it works",
		faq: "FAQ",
		siAlgo: "If something goes wrong",
		cabSiAlgo: ["Symptom", "Fix"],
		practicas: "Good practices",
		queTrae: "What's inside",
		docs: "Documentation",
		docsLista: () => [
			"[Install](docs/en/install.md)",
			"[Usage](docs/en/usage.md)",
			"[What to do after an incident](docs/en/incidents.md)",
			"[Contributing](CONTRIBUTING.md), [code of conduct](CODE_OF_CONDUCT.md) and [security](SECURITY.md)",
		],
		creditos: "Credits",
		licencia: "License",
		licenciaTexto: (anio, titular) =>
			`MIT, © ${anio} ${titular}. See [LICENSE](LICENSE). Third-party logos and brands belong to their owners.`,
		firma: "Made with Claude Code by **El Máster IA · Alexander Cast**.",
		parte: (url) => `Part of [El Laboratorio](${url}).`,
	},
};

const lista = (items: string[]): string =>
	items.map((i) => `- ${escapar(i)}`).join("\n");

/** Builds README.md (es) or README.en.md (en). */
export function readmeElMaster(input: ElMasterInput, lang: Lang): string {
	const t = T[lang];
	const c = input.contenido;
	const partes: string[] = [];
	const seccion = (titulo: string, cuerpo: string): void => {
		partes.push(`## ${titulo}\n\n${cuerpo}`);
	};

	const cabecera = [`# ${escapar(input.nombre)}`, "", t.otro];
	if (c.repo !== undefined) {
		const url = `https://github.com/${c.repo}/actions/workflows/ci.yml`;
		cabecera.push("", `[![CI](${url}/badge.svg)](${url})`);
	}
	cabecera.push("", `**${escapar(c.promesa)}**`, "", t.gratis, "", "---");
	partes.push(cabecera.join("\n"));

	seccion(t.porQue, escapar(c.porQueExiste));
	seccion(t.queObtienes, lista(c.queObtienes));
	seccion(
		t.empieza,
		`${t.empiezaIntro}\n\n${FENCE}text\n${c.prompt}\n${FENCE}`,
	);
	if (input.adaptador === "generico") {
		partes.push(estadoVerificacion(lang).trimEnd());
	}
	if (c.queNecesitas.length > 0) {
		const [a, b, d] = t.cabNecesitas;
		const filas = c.queNecesitas.map(
			(f) => `| ${celda(f.que)} | ${celda(f.paraQue)} | ${celda(f.costo)} |`,
		);
		seccion(
			t.queNecesitas,
			[`| ${a} | ${b} | ${d} |`, "|---|---|---|", ...filas].join("\n"),
		);
	}
	seccion(t.comoFunciona, escapar(c.comoFunciona));
	if (c.faq.length > 0) {
		seccion(
			t.faq,
			c.faq.map((f) => `### ${escapar(f.p)}\n\n${escapar(f.r)}`).join("\n\n"),
		);
	}
	if (c.siAlgoSaleMal.length > 0) {
		const [a, b] = t.cabSiAlgo;
		const filas = c.siAlgoSaleMal.map(
			(f) => `| ${celda(f.sintoma)} | ${celda(f.solucion)} |`,
		);
		seccion(t.siAlgo, [`| ${a} | ${b} |`, "|---|---|", ...filas].join("\n"));
	}
	if (c.buenasPracticas.length > 0) {
		seccion(t.practicas, lista(c.buenasPracticas));
	}
	const entradas = input.queTrae
		.filter((e) => e !== "" && !/[`\p{Cc}\p{Cf}]/u.test(e))
		.sort((x, y) => (x < y ? -1 : x > y ? 1 : 0))
		.slice(0, MAX_QUE_TRAE);
	if (entradas.length > 0) {
		seccion(t.queTrae, `${FENCE}text\n${entradas.join("\n")}\n${FENCE}`);
	}
	seccion(
		t.docs,
		t
			.docsLista("")
			.map((l) => `- ${l}`)
			.join("\n"),
	);
	if (c.creditos.length > 0) seccion(t.creditos, lista(c.creditos));
	seccion(t.licencia, t.licenciaTexto(input.anio, escapar(input.titular)));

	const firma = [
		"---",
		"",
		c.laboratorio === undefined
			? t.firma
			: `${t.firma} ${t.parte(c.laboratorio)}`,
	];
	partes.push(firma.join("\n"));
	return `${partes.join("\n\n")}\n`;
}
