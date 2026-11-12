import type { PackageHints } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { type RepoInput, renderRepo } from "../src/render.js";

const HINTS: PackageHints = {
	instalacion: [],
	uso: [],
	variables: [],
	requisitos: ["ver el código"],
};
const files = (over: Partial<RepoInput>) =>
	new Map(
		renderRepo({
			hints: HINTS,
			titular: "Ana Pérez",
			nombre: "demo",
			anio: 2026,
			...over,
		}).map((f) => [f.ruta, f.contenido]),
	);

describe("PKG-006 / VER-007 renderRepo por adaptador", () => {
	it("PKG-006 un proyecto python produce ci.yml con setup-python", () => {
		const f = files({
			adaptador: "python",
			ci: { pythonVersion: "3.14", instalacion: "uv", tests: true },
		});
		const ci = f.get(".github/workflows/ci.yml") ?? "";
		expect(ci).toContain("actions/setup-python@v5");
		expect(ci).toContain("compileall");
		expect(ci).toContain("pytest");
		expect(f.get("README.md")).not.toContain("Verification status");
	});

	it("VER-007 un proyecto genérico trae la sección de verificación en ambos README", () => {
		const f = files({ adaptador: "generico" });
		expect(f.get("README.md")).toContain("## Verification status");
		expect(f.get("README.es.md")).toContain("## Estado de la verificación");
		const ci = f.get(".github/workflows/ci.yml") ?? "";
		expect(ci).toContain("gitleaks");
		expect(ci).not.toContain("setup-");
	});

	it("PKG-006 sin adaptador (node) el CI no cambia", () => {
		const ci = files({}).get(".github/workflows/ci.yml") ?? "";
		expect(ci).toContain("actions/setup-node@v4");
	});
});
