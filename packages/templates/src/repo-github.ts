import type { RepoTemplate } from "./repo-docs.js";

const GITIGNORE = `# Dependencies / Dependencias
node_modules/

# Environment and secrets / Entorno y secretos
.env
.env.*
!.env.example
*.pem
*.key

# Build and tooling / Construcción y herramientas
dist/
build/
coverage/
.mct/

# System / Sistema
.DS_Store
Thumbs.db
*.log
`;

const ENV_EXAMPLE = `# Copy to .env and fill in the values. / Copia a .env y completa los valores.
<%= it.envLineas %>
`;

const ISSUE_BUG = `name: Bug report / Reporte de error
description: Report something that does not work / Reporta algo que no funciona
labels: [bug]
body:
  - type: textarea
    id: what
    attributes:
      label: What happened? / ¿Qué pasó?
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to reproduce / Pasos para reproducir
    validations:
      required: true
  - type: markdown
    attributes:
      value: Do not paste secrets or personal data. / No pegues secretos ni datos personales.
`;

const ISSUE_FEATURE = `name: Feature request / Solicitud de mejora
description: Suggest an idea / Sugiere una idea
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem to solve / Problema a resolver
    validations:
      required: true
  - type: textarea
    id: idea
    attributes:
      label: Proposed solution / Solución propuesta
`;

const ISSUE_CONFIG = `blank_issues_enabled: false
`;

const PULL_REQUEST = `## What changes / Qué cambia

## How it was tested / Cómo se probó

## Checklist

- [ ] Tests pass / Las pruebas pasan
- [ ] Docs updated / Documentación actualizada
- [ ] No secrets or personal data / Sin secretos ni datos personales
`;

const CI = `name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        if: hashFiles('package.json') != ''
        with:
          node-version: 22
      - name: Install dependencies
        if: hashFiles('package.json') != ''
        run: |
          if [ -f pnpm-lock.yaml ]; then
            corepack enable
            pnpm install --frozen-lockfile
          elif [ -f yarn.lock ]; then
            corepack enable
            yarn install --immutable
          elif [ -f package-lock.json ]; then
            npm ci
          else
            npm install
          fi
      - name: Test
        if: hashFiles('package.json') != ''
        run: |
          if ! grep -q '"test"' package.json; then
            echo "No test script; skipping."
          elif [ -f pnpm-lock.yaml ]; then
            pnpm test
          elif [ -f yarn.lock ]; then
            yarn test
          else
            npm test
          fi
`;

export const PLANTILLAS_GITHUB: readonly RepoTemplate[] = [
	{ ruta: ".gitignore", plantilla: GITIGNORE },
	{ ruta: ".env.example", plantilla: ENV_EXAMPLE },
	{ ruta: ".github/ISSUE_TEMPLATE/bug_report.yml", plantilla: ISSUE_BUG },
	{
		ruta: ".github/ISSUE_TEMPLATE/feature_request.yml",
		plantilla: ISSUE_FEATURE,
	},
	{ ruta: ".github/ISSUE_TEMPLATE/config.yml", plantilla: ISSUE_CONFIG },
	{ ruta: ".github/pull_request_template.md", plantilla: PULL_REQUEST },
	{ ruta: ".github/workflows/ci.yml", plantilla: CI },
];
