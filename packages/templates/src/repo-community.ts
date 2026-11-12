import type { RepoTemplate } from "./repo-docs.js";

/** CONTRIBUTING, CODE_OF_CONDUCT and SECURITY, bilingual in one file each. */
const CONTRIBUTING = `# Contributing / Contribuir

## English

1. Open an issue before a large change.
2. Fork, create a branch and keep each pull request focused on one change.
3. Add or update tests and docs for your change.
4. Never include secrets, personal data or \`.env\` files.

## Español

1. Abre un issue antes de un cambio grande.
2. Haz un fork, crea una rama y mantén cada pull request enfocado en un solo cambio.
3. Agrega o actualiza pruebas y documentación.
4. Nunca incluyas secretos, datos personales ni archivos \`.env\`.

Licensed under MIT, copyright <%= it.anio %> <%= it.titular %>.
`;

const CODE_OF_CONDUCT = `# Code of Conduct / Código de conducta

## English

We want a respectful and harassment-free space for everyone. Be kind, assume
good intent, accept feedback, and focus on what is best for the project.
Harassment, insults, discrimination and publishing other people's private
information are not acceptable. Maintainers may remove content and block
people who break these rules. Report problems to <%= it.titular %> through the
private channel described in SECURITY.md.

## Español

Queremos un espacio respetuoso y libre de acoso para todas las personas. Sé
amable, asume buena intención, acepta la retroalimentación y prioriza lo mejor
para el proyecto. No se aceptan acoso, insultos, discriminación ni publicar
información privada de otras personas. Quienes mantienen el proyecto pueden
retirar contenido y bloquear a quien incumpla estas reglas. Reporta los
problemas a <%= it.titular %> por el canal privado descrito en SECURITY.md.
`;

const SECURITY = `# Security Policy / Política de seguridad

## English

Do not open a public issue for a vulnerability. Use the private vulnerability
reporting of the repository host (Security tab) and describe the problem and
the steps to reproduce it. If you find a secret or personal data in this
repository, report it the same way and read docs/en/incidents.md.

## Español

No abras un issue público por una vulnerabilidad. Usa el reporte privado de
vulnerabilidades del repositorio (pestaña Security) y describe el problema y
los pasos para reproducirlo. Si encuentras un secreto o datos personales en
este repositorio, repórtalo igual y lee docs/es/incidentes.md.
`;

export const PLANTILLAS_COMUNIDAD: readonly RepoTemplate[] = [
	{ ruta: "CONTRIBUTING.md", plantilla: CONTRIBUTING },
	{ ruta: "CODE_OF_CONDUCT.md", plantilla: CODE_OF_CONDUCT },
	{ ruta: "SECURITY.md", plantilla: SECURITY },
];
