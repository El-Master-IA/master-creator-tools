import { MctError } from "@mct/contract/errors";
import { PYTHON_IMAGE_REFS } from "@mct/contract/pins";
import type { Analysis, VerifyStep } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { pythonAdapter } from "../src/index.js";
import { buildVerifySpec, pickPythonImage } from "../src/verify.js";

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

const COMPILE = ["python", "-m", "compileall", "-q", "."];

describe("adapter-python: verify (PY-003)", () => {
	it("PY-003 elige 3.14 si cumple, o la mas alta que cumpla", () => {
		expect(pickPythonImage(undefined)).toBe(PYTHON_IMAGE_REFS["3.14-slim"]);
		expect(pickPythonImage(">=3.12")).toBe(PYTHON_IMAGE_REFS["3.14-slim"]);
		expect(pickPythonImage(">=3.15")).toBe(PYTHON_IMAGE_REFS["3.15-slim"]);
		expect(pickPythonImage(">=3.9,<3.14")).toBe(PYTHON_IMAGE_REFS["3.13-slim"]);
		expect(pickPythonImage("~=3.13")).toBe(PYTHON_IMAGE_REFS["3.14-slim"]);
		expect(pickPythonImage(">=3.12,==3.13.*")).toBe(
			PYTHON_IMAGE_REFS["3.13-slim"],
		);
		expect(pickPythonImage("==3.15.*")).toBe(PYTHON_IMAGE_REFS["3.15-slim"]);
		expect(pickPythonImage("!=3.14.*")).toBe(PYTHON_IMAGE_REFS["3.15-slim"]);
	});

	it("PY-003 requires-python que ninguna imagen cumple da PUERTA_BLOQUEADA version-python", () => {
		for (const spec of ["<3.13", ">=3.16", "==3.12.*", ">=3.12,<3.13"]) {
			const run = (): unknown =>
				pythonAdapter.verifyCommand(analysis({ requiresPython: spec }));
			expect(run).toThrow(MctError);
			try {
				run();
			} catch (e) {
				const err = e as MctError;
				expect(err.codigo).toBe("PUERTA_BLOQUEADA");
				expect(err.detalle).toEqual({ motivo: "version-python" });
			}
		}
	});

	it("PY-003 sin puerto: compileall + pip check en secuencia y salida-cero", () => {
		const spec = pythonAdapter.verifyCommand(analysis());
		expect(spec.imagen).toBe(PYTHON_IMAGE_REFS["3.14-slim"]);
		expect(spec.start).toEqual([COMPILE, ["pip", "check"]]);
		expect(spec.healthcheck).toEqual({ tipo: "salida-cero" });
		expect(spec.timeoutMin).toBe(15);
		expect(spec.install).toBeUndefined();
	});

	it("PY-003 con puerto arranca el primer entrypoint y espera 2xx, 3xx o 404", () => {
		const spec = pythonAdapter.verifyCommand(
			analysis({ entrypoints: ["manage.py", "main.py"], puerto: 8000 }),
		);
		expect(spec.start).toEqual([
			COMPILE,
			["pip", "check"],
			["python", "manage.py", "runserver", "0.0.0.0:8000", "--noreload"],
		]);
		expect(spec.healthcheck).toEqual({
			tipo: "http",
			puerto: 8000,
			ruta: "/",
			aceptar: ["2xx", "3xx", 404],
		});
		const plain = pythonAdapter.verifyCommand(
			analysis({ entrypoints: ["main.py"], puerto: 5000 }),
		);
		expect(plain.start.at(-1)).toEqual(["python", "main.py"]);
	});

	it("PY-003 modo compilar: pip check pasa a aviso y no arranca el servidor", () => {
		const spec = buildVerifySpec(
			analysis({ entrypoints: ["main.py"], puerto: 5000 }),
			{ modo: "compilar" },
		);
		const step: VerifyStep = {
			argv: ["pip", "check"],
			avisoSiFalla: "verify.pipCheck",
		};
		expect(spec.start).toEqual([COMPILE, step]);
		expect(spec.healthcheck).toEqual({ tipo: "salida-cero" });
	});

	it("PY-003 verify.ignorar saca los globs de compileall", () => {
		const spec = buildVerifySpec(analysis(), {
			ignorar: ["legacy/**", "*.gen.py"],
		});
		const first = spec.start[0] as string[];
		expect(first.slice(0, 4)).toEqual(["python", "-m", "compileall", "-q"]);
		const i = first.indexOf("-x");
		expect(i).toBeGreaterThan(-1);
		const re = new RegExp(first[i + 1] as string);
		expect(re.test("./legacy/old/x.py")).toBe(true);
		expect(re.test("./pkg/a.gen.py")).toBe(true);
		expect(re.test("./pkg/ok.py")).toBe(false);
		expect(first.at(-1)).toBe(".");
	});

	it("PY-003 la instalacion corre en un venv /tmp/venv con el comando del analisis", () => {
		const spec = pythonAdapter.verifyCommand(
			analysis({ comandos: { install: "pip install -r requirements.txt" } }),
		);
		expect(spec.install?.slice(0, 2)).toEqual(["sh", "-c"]);
		expect(spec.install?.[2]).toBe(
			"python -m venv /tmp/venv && . /tmp/venv/bin/activate && pip install -r requirements.txt",
		);
		expect(spec.avisos).toBeUndefined();
	});

	it("PY-003 poetry.lock instala con pip install . y muestra verify.poetrySinLock", () => {
		const spec = pythonAdapter.verifyCommand(
			analysis({ gestor: "poetry", comandos: { install: "pip install ." } }),
		);
		expect(spec.avisos).toEqual(["verify.poetrySinLock"]);
		expect(spec.install?.[2]).toContain("pip install .");
	});
});
