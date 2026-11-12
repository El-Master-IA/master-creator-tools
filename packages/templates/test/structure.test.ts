import { MctError } from "@mct/contract/errors";
import type { PackageHints } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { type RepoInput, renderRepo } from "../src/render.js";

const HINTS: PackageHints = {
	instalacion: ["npm install"],
	uso: ["npm start"],
	variables: [
		{ nombre: "API_URL", descripcion: "Base URL", obligatoria: true },
		{ nombre: "DEBUG_MODE", descripcion: "Verbose logs", obligatoria: false },
	],
	requisitos: ["Node >= 22"],
};
const input = (over: Partial<RepoInput> = {}): RepoInput => ({
	hints: HINTS,
	titular: "Ana Pérez",
	nombre: "demo-project",
	anio: 2026,
	...over,
});
const byPath = (o: Partial<RepoInput> = {}) =>
	new Map(renderRepo(input(o)).map((f) => [f.ruta, f.contenido]));

const REQUIRED = [
	"README.md",
	"README.es.md",
	"LICENSE",
	"CONTRIBUTING.md",
	"CODE_OF_CONDUCT.md",
	"SECURITY.md",
	".env.example",
	".gitignore",
	"docs/es/instalacion.md",
	"docs/es/uso.md",
	"docs/es/incidentes.md",
	"docs/en/install.md",
	"docs/en/usage.md",
	"docs/en/incidents.md",
	".github/ISSUE_TEMPLATE/bug_report.yml",
	".github/ISSUE_TEMPLATE/feature_request.yml",
	".github/pull_request_template.md",
	".github/workflows/ci.yml",
];

function codeOf(fn: () => unknown): string {
	try {
		fn();
	} catch (e) {
		if (e instanceof MctError) return e.codigo;
		throw e;
	}
	return "no-error";
}

describe("PKG-002 estructura del repo publicado", () => {
	it("PKG-002 produces every required file", () => {
		const files = byPath();
		for (const r of REQUIRED) expect(files.has(r), r).toBe(true);
		expect(files.size).toBe(renderRepo(input()).length);
	});

	it("PKG-002 LICENSE is MIT with the configured holder", () => {
		const lic = byPath().get("LICENSE") ?? "";
		expect(lic).toContain("MIT License");
		expect(lic).toContain("Copyright (c) 2026 Ana Pérez");
	});

	it("PKG-002 READMEs are in each language and use the hints", () => {
		const f = byPath();
		expect(f.get("README.md")).toContain("## Installation");
		expect(f.get("README.es.md")).toContain("## Instalación");
		expect(f.get("README.es.md")).toContain("npm install");
		expect(f.get("README.md")).toContain("`API_URL` (required)");
		expect(f.get("README.es.md")).toContain("`DEBUG_MODE` (opcional)");
	});

	it("PKG-002 docs include the incidents guide in both languages", () => {
		const f = byPath();
		expect(f.get("docs/es/incidentes.md")).toContain("privado");
		expect(f.get("docs/en/incidents.md")).toContain("private");
	});

	it("PKG-002 .env.example has names with empty values", () => {
		const env = byPath().get(".env.example") ?? "";
		expect(env).toContain("\nAPI_URL=\n");
		expect(env).toContain("\nDEBUG_MODE=");
		expect(env).not.toMatch(/^[A-Z_]+=\S/m);
	});

	it("PKG-002 output uses LF and no unrendered tags", () => {
		for (const [ruta, c] of byPath()) {
			expect(c.includes("\r"), ruta).toBe(false);
			expect(c.includes("<%"), ruta).toBe(false);
		}
	});

	it("PKG-002 missing holder fails with VALIDACION", () => {
		for (const titular of ["", "   ", undefined as unknown as string]) {
			expect(codeOf(() => renderRepo(input({ titular })))).toBe("VALIDACION");
		}
	});

	it("PKG-002 rejects multi-line holder and bad variable names", () => {
		expect(codeOf(() => renderRepo(input({ titular: "A\nB" })))).toBe(
			"VALIDACION",
		);
		const bad = {
			...HINTS,
			variables: [{ nombre: "bad name", descripcion: "x", obligatoria: true }],
		};
		expect(codeOf(() => renderRepo(input({ hints: bad })))).toBe("VALIDACION");
		for (const nombre of ["A=B", "A\nB", "", "1ABC", "A-B"]) {
			const h = {
				...HINTS,
				variables: [{ nombre, descripcion: "x", obligatoria: true }],
			};
			expect(codeOf(() => renderRepo(input({ hints: h })))).toBe("VALIDACION");
		}
	});

	it("PKG-002 accepts names emitted by adapters (lowercase, leading underscore)", () => {
		const h: PackageHints = {
			...HINTS,
			variables: [
				{ nombre: "npm_package_version", descripcion: "v", obligatoria: false },
				{ nombre: "_PRIVATE", descripcion: "p", obligatoria: true },
			],
		};
		const f = byPath({ hints: h });
		expect(f.get("README.md")).toContain("`npm_package_version` (optional)");
		expect(f.get("README.md")).toContain("`_PRIVATE` (required)");
		expect(f.get(".env.example")).toContain("\nnpm_package_version=\n");
		expect(f.get(".env.example")).toContain("\n_PRIVATE=");
	});

	it("PKG-002 CI does not hard-code an unconditional npm ci", () => {
		const ci = byPath().get(".github/workflows/ci.yml") ?? "";
		expect(ci).not.toMatch(/run:\s*npm ci\s*$/m);
		expect(ci).toContain("package-lock.json");
		expect(ci).toContain("pnpm-lock.yaml");
		expect(ci).toContain("yarn.lock");
		expect(ci).toContain("package.json");
	});
});
