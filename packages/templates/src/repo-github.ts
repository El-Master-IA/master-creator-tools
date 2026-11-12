import { GITLEAKS_VERSION, UV_VERSION } from "@mct/contract/pins";
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

/** What the generated CI needs to know about the project (PKG-006). */
export interface CiOpciones {
	/** Adapter id: "python", "estatico", "generico"; anything else keeps the node/n8n CI. */
	adaptador: string;
	/** python: version picked in PY-003 (e.g. "3.14"). */
	pythonVersion?: string;
	/** python: install strategy, same precedence as PY-003. */
	instalacion?: "uv" | "poetry" | "requirements" | "proyecto" | "ninguna";
	/** python: the repo has tests/, test/ or test_*.py / *_test.py files. */
	tests?: boolean;
	/** python: a poetry.lock exists (the install ignores it). */
	poetryLock?: boolean;
}

const CI_HEAD = `name: CI

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
`;

const GITLEAKS_STEP = `      - name: Gitleaks
        run: |
          base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
          file="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
          curl -sSfL -o "$RUNNER_TEMP/$file" "$base/$file"
          curl -sSfL -o "$RUNNER_TEMP/checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
          (cd "$RUNNER_TEMP" && grep " $file$" checksums.txt | sha256sum -c -)
          tar -xzf "$RUNNER_TEMP/$file" -C "$RUNNER_TEMP" gitleaks
          "$RUNNER_TEMP/gitleaks" detect --source . --no-banner --redact
`;

// Plain Python, no dependencies: index.html exists and local href/src resolve.
const STATIC_CHECK = String.raw`      - name: Check HTML / Revisar HTML
        run: |
          python3 - <<'PY'
          import os, re, sys
          if not os.path.isfile("index.html"):
              sys.exit("index.html not found / no existe index.html")
          html = open("index.html", encoding="utf-8").read()
          missing = []
          for ref in re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", html):
              if re.match(r"^([a-z][a-z0-9+.-]*:|//|#)", ref, re.I):
                  continue
              path = re.split(r"[?#]", ref)[0]
              if path and not os.path.exists(path.lstrip("/")):
                  missing.append(ref)
          if missing:
              sys.exit("Missing local files / Archivos locales que faltan: " + ", ".join(missing))
          PY
`;

function pythonInstall(o: CiOpciones): string {
	const inst = o.instalacion ?? "ninguna";
	if (inst === "ninguna") return "";
	const body: Record<string, string[]> = {
		uv: [
			`pip install uv==${UV_VERSION}`,
			'uv export --frozen --format requirements-txt > "$RUNNER_TEMP/requirements.txt"',
			'pip install -r "$RUNNER_TEMP/requirements.txt"',
		],
		poetry: ["pip install ."],
		requirements: ["pip install -r requirements.txt"],
		proyecto: ["pip install ."],
	};
	const comment = o.poetryLock
		? "      # Installs without honoring poetry.lock. / Instala sin respetar poetry.lock.\n"
		: "";
	const lines = (body[inst] ?? []).map((l) => `          ${l}`).join("\n");
	return `${comment}      - name: Install dependencies / Instalar dependencias\n        run: |\n${lines}\n`;
}

/** Builds `.github/workflows/ci.yml` for the adapter (PKG-006). */
export function ciParaAdaptador(o: CiOpciones): string {
	if (o.adaptador === "generico") return `${CI_HEAD}${GITLEAKS_STEP}`;
	if (o.adaptador === "estatico") {
		return `${CI_HEAD}${STATIC_CHECK}${GITLEAKS_STEP}`;
	}
	if (o.adaptador === "python") {
		const version = o.pythonVersion ?? "3.13";
		const setup = `      - uses: actions/setup-python@v5\n        with:\n          python-version: "${version}"\n`;
		const compile = `      - name: Compile / Compilar\n        run: python -m compileall -q .\n`;
		const tests = o.tests
			? `      - name: Test / Pruebas\n        run: |\n          pip install pytest\n          pytest\n`
			: "";
		return `${CI_HEAD}${setup}${pythonInstall(o)}${compile}${tests}${GITLEAKS_STEP}`;
	}
	return CI;
}

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
