import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { pythonAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-py-analyze-"));
	roots.push(raiz);
	for (const [zone, files] of [
		["work", work],
		["quarantine", quarantine],
	] as const) {
		await mkdir(join(raiz, zone), { recursive: true });
		for (const [rel, content] of Object.entries(files)) {
			const target = join(raiz, zone, rel);
			await mkdir(dirname(target), { recursive: true });
			await writeFile(target, content, "utf8");
		}
	}
	return {
		raiz,
		work: join(raiz, "work"),
		quarantine: join(raiz, "quarantine"),
		dist: join(raiz, "dist"),
		estado: () => Promise.reject(new Error("no usado")),
	};
}

afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
	);
});

const PYPROJECT = [
	"[project]",
	'name = "demo"',
	'requires-python = ">=3.12"',
	'dependencies = ["fastapi>=0.110", "uvicorn[standard]==0.30.1", "Requests"]',
	"",
	"[project.scripts]",
	'demo = "demo.cli:main"',
	"",
].join("\n");

describe("adapter-python: analisis (PY-001)", () => {
	it("PY-001 escribe stack, lenguaje, requiresPython, deps y entrypoints en orden", async () => {
		const ws = await makeWs({
			"pyproject.toml": PYPROJECT,
			"manage.py": "x = 1\n",
			"main.py": "x = 1\n",
			"__main__.py": "x = 1\n",
		});
		const a = await pythonAdapter.analyze(ws);
		expect(a.stack).toEqual(["python", "fastapi"]);
		expect(a.lenguaje).toBe("python");
		expect(a.requiresPython).toBe(">=3.12");
		expect(a.gestor).toBe("pip");
		expect(a.entrypoints).toEqual([
			"demo",
			"__main__.py",
			"main.py",
			"manage.py",
		]);
		expect(a.deps).toEqual([
			{ nombre: "fastapi", version: ">=0.110" },
			{ nombre: "uvicorn", version: "==0.30.1" },
			{ nombre: "Requests", version: "*" },
		]);
	});

	it("PY-001 gestor uv con uv.lock y poetry con poetry.lock", async () => {
		const uv = await makeWs({
			"pyproject.toml": PYPROJECT,
			"uv.lock": "version = 1\n",
		});
		expect((await pythonAdapter.analyze(uv)).gestor).toBe("uv");
		const poetry = await makeWs({
			"pyproject.toml": PYPROJECT,
			"poetry.lock": '[metadata]\nlock-version = "2.0"\n',
		});
		expect((await pythonAdapter.analyze(poetry)).gestor).toBe("poetry");
	});

	it("PY-001 lee dependencias de [tool.poetry.dependencies] y el python de poetry", async () => {
		const ws = await makeWs({
			"pyproject.toml": [
				"[tool.poetry.dependencies]",
				'python = "^3.11"',
				'flask = "^3.0"',
				'django = { version = "^5.0" }',
				"",
			].join("\n"),
		});
		const a = await pythonAdapter.analyze(ws);
		expect(a.requiresPython).toBe(">=3.11,<4");
		expect(a.stack).toEqual(["python", "flask", "django"]);
		expect(a.deps.map((d) => d.nombre)).toEqual(["flask", "django"]);
	});

	it("PY-001 lee requirements*.txt y omite VCS, rutas y opciones", async () => {
		const ws = await makeWs({
			"requirements.txt": [
				"# comentario",
				"-r otro.txt",
				"flask==3.0.0  # web",
				"git+https://example.test/x.git#egg=x",
				"./local",
				"",
			].join("\n"),
			"main.py": "x = 1\n",
		});
		const a = await pythonAdapter.analyze(ws);
		expect(a.deps).toEqual([{ nombre: "flask", version: "==3.0.0" }]);
		expect(a.stack).toEqual(["python", "flask"]);
		expect(a.comandos.install).toBe("pip install -r requirements.txt");
	});

	it("PY-001 .python-version se suma a requiresPython", async () => {
		const ws = await makeWs({
			"pyproject.toml": PYPROJECT,
			".python-version": "3.13\n",
		});
		expect((await pythonAdapter.analyze(ws)).requiresPython).toBe(
			">=3.12,==3.13.*",
		);
	});

	it("PY-001 detecta el puerto en uvicorn, app.run, runserver y PORT por defecto", async () => {
		const cases: [string, number][] = [
			[
				'import uvicorn\nuvicorn.run("m:app", host="0.0.0.0", port=8123)\n',
				8123,
			],
			["app.run(debug=True, port=5055)\n", 5055],
			["# python manage.py runserver 0.0.0.0:9090\n", 9090],
			['port = int(os.environ.get("PORT", 3100))\n', 3100],
			["# uvicorn main:app --port 7001\n", 7001],
		];
		for (const [code, port] of cases) {
			const ws = await makeWs({ "requirements.txt": "", "main.py": code });
			expect((await pythonAdapter.analyze(ws)).puerto).toBe(port);
		}
		const none = await makeWs({ "requirements.txt": "", "main.py": "x = 1\n" });
		expect((await pythonAdapter.analyze(none)).puerto).toBeUndefined();
	});

	it("PY-001 elige el comando de instalacion por precedencia", async () => {
		const build = "[build-system]\nrequires = []\n";
		const uv = await makeWs({
			"pyproject.toml": `${PYPROJECT}${build}`,
			"uv.lock": "version = 1\n",
			"poetry.lock": "[metadata]\n",
			"requirements.txt": "",
		});
		expect((await pythonAdapter.analyze(uv)).comandos.install).toContain(
			"uv export --frozen --format requirements-txt",
		);
		const poetry = await makeWs({
			"pyproject.toml": `${PYPROJECT}${build}`,
			"poetry.lock": "[metadata]\n",
			"requirements.txt": "",
		});
		expect((await pythonAdapter.analyze(poetry)).comandos.install).toBe(
			"pip install .",
		);
		const poetryNoBuild = await makeWs({
			"pyproject.toml": PYPROJECT,
			"poetry.lock": "[metadata]\n",
			"requirements.txt": "",
		});
		expect((await pythonAdapter.analyze(poetryNoBuild)).comandos.install).toBe(
			"pip install -r requirements.txt",
		);
		const proj = await makeWs({ "pyproject.toml": PYPROJECT });
		expect((await pythonAdapter.analyze(proj)).comandos.install).toBe(
			"pip install .",
		);
		const none = await makeWs({ "a.py": "x = 1\n", "b.py": "y = 2\n" });
		expect(
			(await pythonAdapter.analyze(none)).comandos.install,
		).toBeUndefined();
	});

	it("PY-001 TOML invalido en pyproject, uv.lock o poetry.lock sale con VALIDACION sin repetir el contenido", async () => {
		const marker = ["valor", "privado", "xyz"].join("-");
		for (const file of ["pyproject.toml", "uv.lock", "poetry.lock"]) {
			const ws = await makeWs({ [file]: `[roto\nclave = "${marker}"\n` });
			const err = await pythonAdapter.analyze(ws).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(MctError);
			const e = err as MctError;
			expect(e.codigo).toBe("VALIDACION");
			expect(JSON.stringify([e.message, e.accion, e.detalle])).not.toContain(
				marker,
			);
			expect(e.cause).toBeUndefined();
		}
	});
});
