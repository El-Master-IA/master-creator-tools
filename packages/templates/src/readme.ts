/**
 * README sections that depend on the adapter (PKG-007, VER-007). The base
 * README lives in repo-docs.ts; these helpers add what that template lacks.
 */
export type Lang = "es" | "en";

// EXPERIENCE.md: verify.omitido plus the invitation to say how it runs.
const ESTADO: Record<Lang, string> = {
	es: `## Estado de la verificación

Este proyecto no se probó en un contenedor (adaptador genérico). Revisa a mano que arranca antes de usarlo. Si lo ejecutas, cuéntanos en un issue cómo se ejecuta.
`,
	en: `## Verification status

This project was not tested in a container (generic adapter). Check by hand that it runs before using it. If you run it, tell us in an issue how it runs.
`,
};

const ANCLA: Record<Lang, string> = {
	es: "## Instalación",
	en: "## Installation",
};

/** Verification-status section for the generic adapter (VER-007). */
export function estadoVerificacion(lang: Lang): string {
	return ESTADO[lang];
}

/**
 * Adds the adapter sections to a rendered README. Generic: the verification
 * status goes right after the requirements, before the install section.
 */
export function readmeConAdaptador(
	readme: string,
	adaptador: string,
	lang: Lang,
): string {
	if (adaptador !== "generico") return readme;
	const i = readme.indexOf(ANCLA[lang]);
	if (i < 0) return `${readme.trimEnd()}\n\n${ESTADO[lang]}`;
	return `${readme.slice(0, i)}${ESTADO[lang]}\n${readme.slice(i)}`;
}
