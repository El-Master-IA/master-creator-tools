/**
 * Eta templates (as strings, for the single bundle) for the published repo:
 * README, LICENSE and docs. Placeholders are plain scalars prepared and
 * validated by render.ts (no loops inside the templates).
 */
export interface RepoTemplate {
	ruta: string;
	plantilla: string;
}

const README_ES = `# <%= it.nombre %>

> Read this in English: [README.md](README.md)

## Requisitos

<%= it.requisitos %>

## Instalación

<%= it.instalacion %>

## Uso

<%= it.uso %>

## Variables de entorno

<%= it.variables %>

Copia \`.env.example\` a \`.env\` y completa los valores. Nunca subas \`.env\` al repositorio.

## Documentación

- [Instalación](docs/es/instalacion.md)
- [Uso](docs/es/uso.md)
- [Qué hacer ante un incidente](docs/es/incidentes.md)

## Contribuir y seguridad

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) y [SECURITY.md](SECURITY.md).

## Licencia

MIT, copyright <%= it.anio %> <%= it.titular %>. Consulta [LICENSE](LICENSE).
`;

const README_EN = `# <%= it.nombre %>

> Lee esto en español: [README.es.md](README.es.md)

## Requirements

<%= it.requisitos %>

## Installation

<%= it.instalacion %>

## Usage

<%= it.uso %>

## Environment variables

<%= it.variables %>

Copy \`.env.example\` to \`.env\` and fill in the values. Never commit \`.env\` to the repository.

## Documentation

- [Installation](docs/en/install.md)
- [Usage](docs/en/usage.md)
- [What to do after an incident](docs/en/incidents.md)

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).

## License

MIT, copyright <%= it.anio %> <%= it.titular %>. See [LICENSE](LICENSE).
`;

const LICENSE_MIT = `MIT License

Copyright (c) <%= it.anio %> <%= it.titular %>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

const INSTALL_ES = `# Instalación

## Requisitos

<%= it.requisitos %>

## Pasos

<%= it.instalacion %>

## Variables de entorno

<%= it.variables %>
`;

const INSTALL_EN = `# Installation

## Requirements

<%= it.requisitos %>

## Steps

<%= it.instalacion %>

## Environment variables

<%= it.variables %>
`;

const USAGE_ES = `# Uso

<%= it.uso %>
`;

const USAGE_EN = `# Usage

<%= it.uso %>
`;

const INCIDENTS_ES = `# Qué hacer ante un incidente

Si un dato personal o un secreto llegó a este repositorio público, actúa en este orden:

1. Haz el repositorio privado de inmediato.
2. Rota todos los secretos expuestos (claves, tokens, contraseñas) en el servicio que los emitió.
3. Borra el repositorio y créalo de nuevo sin el historial afectado.
4. Cumple tus propias obligaciones de aviso al titular de los datos y a la autoridad de tu país.

Esta guía no fija plazos legales: consulta la normativa que te aplica.
`;

const INCIDENTS_EN = `# What to do after an incident

If personal data or a secret reached this public repository, act in this order:

1. Make the repository private right away.
2. Rotate every exposed secret (keys, tokens, passwords) at the service that issued it.
3. Delete the repository and create it again without the affected history.
4. Meet your own notification obligations to the data subject and to the authority in your country.

This guide does not set legal deadlines: check the rules that apply to you.
`;

export const PLANTILLAS_DOCS: readonly RepoTemplate[] = [
	{ ruta: "README.md", plantilla: README_EN },
	{ ruta: "README.es.md", plantilla: README_ES },
	{ ruta: "LICENSE", plantilla: LICENSE_MIT },
	{ ruta: "docs/es/instalacion.md", plantilla: INSTALL_ES },
	{ ruta: "docs/es/uso.md", plantilla: USAGE_ES },
	{ ruta: "docs/es/incidentes.md", plantilla: INCIDENTS_ES },
	{ ruta: "docs/en/install.md", plantilla: INSTALL_EN },
	{ ruta: "docs/en/usage.md", plantilla: USAGE_EN },
	{ ruta: "docs/en/incidents.md", plantilla: INCIDENTS_EN },
];
