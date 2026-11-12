import type { Analysis } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { pythonAdapter } from "../src/index.js";

function analysis(extra: Partial<Analysis> = {}): Analysis {
	return {
		stack: ["python"],
		entrypoints: [],
		envVars: [],
		deps: [],
		lenguaje: "python",
		gestor: "pip",
		comandos: {},
		...extra,
	};
}

describe("adapter-python: packageHints (PKG-007)", () => {
	it("PKG-007 requisito Python <requires-python> o Python >= 3.13", () => {
		expect(
			pythonAdapter.packageHints(analysis({ requiresPython: ">=3.12" }))
				.requisitos,
		).toEqual(["Python >=3.12"]);
		expect(pythonAdapter.packageHints(analysis()).requisitos).toEqual([
			"Python >= 3.13",
		]);
		expect(
			pythonAdapter.packageHints(
				analysis({ requiresPython: ">=3.12,==3.13.*" }),
			).requisitos,
		).toEqual(["Python >=3.12"]);
	});

	it("PKG-007 instalacion: uv sync con uv, pip install . con poetry o pyproject, requirements si no", () => {
		expect(
			pythonAdapter.packageHints(analysis({ gestor: "uv" })).instalacion,
		).toEqual(["uv sync"]);
		expect(
			pythonAdapter.packageHints(analysis({ gestor: "poetry" })).instalacion,
		).toEqual(["pip install ."]);
		expect(
			pythonAdapter.packageHints(
				analysis({ comandos: { install: "pip install ." } }),
			).instalacion,
		).toEqual(["pip install ."]);
		expect(
			pythonAdapter.packageHints(
				analysis({ comandos: { install: "pip install -r requirements.txt" } }),
			).instalacion,
		).toEqual(["pip install -r requirements.txt"]);
	});

	it("PKG-007 uso segun el primer entrypoint", () => {
		const uso = (e: string[]): string[] =>
			pythonAdapter.packageHints(analysis({ entrypoints: e })).uso;
		expect(uso(["manage.py", "main.py"])).toEqual([
			"python manage.py runserver",
		]);
		expect(uso(["main.py"])).toEqual(["python main.py"]);
		expect(uso(["demo", "main.py"])).toEqual(["demo"]);
		expect(uso([])).toEqual([]);
	});

	it("PKG-007 variables de PY-002", () => {
		const hints = pythonAdapter.packageHints(
			analysis({
				envVars: [
					{ nombre: "DB_URL", obligatoria: true },
					{ nombre: "MODE", obligatoria: false },
				],
			}),
		);
		expect(hints.variables.map((v) => [v.nombre, v.obligatoria])).toEqual([
			["DB_URL", true],
			["MODE", false],
		]);
		expect(hints.variables.every((v) => v.descripcion.length > 0)).toBe(true);
	});
});
