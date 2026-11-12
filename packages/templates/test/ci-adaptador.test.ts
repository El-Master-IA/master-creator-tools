import { GITLEAKS_VERSION } from "@mct/contract/pins";
import { describe, expect, it } from "vitest";
import { ciParaAdaptador } from "../src/repo-github.js";

describe("PKG-006 CI por adaptador", () => {
	it("PKG-006 python usa setup-python, compileall y gitleaks", () => {
		const ci = ciParaAdaptador({
			adaptador: "python",
			pythonVersion: "3.14",
			instalacion: "requirements",
		});
		expect(ci).toContain("actions/setup-python@v5");
		expect(ci).toContain('python-version: "3.14"');
		expect(ci).toContain("python -m compileall -q .");
		expect(ci).toContain("pip install -r requirements.txt");
		expect(ci).toContain(`v${GITLEAKS_VERSION}`);
		expect(ci).toContain("sha256sum -c");
		expect(ci).toContain("permissions:\n  contents: read");
		expect(ci).not.toContain("pytest");
	});

	it("PKG-006 python corre pytest solo si hay pruebas", () => {
		const ci = ciParaAdaptador({ adaptador: "python", tests: true });
		expect(ci).toContain("pip install pytest");
		expect(ci).toMatch(/^\s+pytest$/m);
	});

	it("PKG-006 python con uv exporta el lock e instala", () => {
		const ci = ciParaAdaptador({ adaptador: "python", instalacion: "uv" });
		expect(ci).toContain("pip install uv==");
		expect(ci).toContain("uv export --frozen --format requirements-txt");
	});

	it("PKG-006 python con poetry.lock avisa en ES/EN que no lo respeta", () => {
		const ci = ciParaAdaptador({
			adaptador: "python",
			instalacion: "poetry",
			poetryLock: true,
		});
		expect(ci).toContain("pip install .");
		expect(ci).toContain("without honoring poetry.lock");
		expect(ci).toContain("sin respetar poetry.lock");
	});

	it("PKG-006 estatico comprueba index.html y enlaces locales, más gitleaks", () => {
		const ci = ciParaAdaptador({ adaptador: "estatico" });
		expect(ci).toContain("index.html");
		expect(ci).toContain("href|src");
		expect(ci).toContain("gitleaks");
		expect(ci).not.toContain("setup-python");
		expect(ci).not.toContain("setup-node");
	});

	it("PKG-006 generico solo corre gitleaks", () => {
		const ci = ciParaAdaptador({ adaptador: "generico" });
		expect(ci).toContain("gitleaks");
		expect(ci).not.toContain("setup-");
		expect(ci).not.toContain("compileall");
		expect(ci).toContain("permissions:\n  contents: read");
	});

	it("PKG-006 node y n8n conservan el CI de node", () => {
		for (const adaptador of ["node", "n8n"]) {
			const ci = ciParaAdaptador({ adaptador });
			expect(ci).toContain("actions/setup-node@v4");
			expect(ci).not.toContain("gitleaks");
		}
	});
});
