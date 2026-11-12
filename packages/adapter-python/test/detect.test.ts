import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { pythonAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeDir(files: Record<string, string>): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "mct-py-detect-"));
	roots.push(dir);
	for (const [rel, content] of Object.entries(files)) {
		const target = join(dir, rel);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, content, "utf8");
	}
	return dir;
}

afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
	);
});

const PYPROJECT = '[project]\nname = "demo"\nversion = "0.1.0"\n';

describe("adapter-python: deteccion (DET-001)", () => {
	it("PY-001 pyproject.toml da confianza 0.6 o mas", async () => {
		const dir = await makeDir({ "pyproject.toml": PYPROJECT });
		expect(await pythonAdapter.detect(dir)).toBeGreaterThanOrEqual(0.6);
		expect(await pythonAdapter.detect(dir)).toBeCloseTo(0.6);
	});

	it("PY-001 cada manifiesto reconocido da 0.6", async () => {
		for (const file of [
			"requirements.txt",
			"requirements-dev.txt",
			"setup.py",
			"Pipfile",
		]) {
			const dir = await makeDir({ [file]: "" });
			expect(await pythonAdapter.detect(dir)).toBeCloseTo(0.6);
		}
	});

	it("PY-001 un lock suma 0.15 y un entrypoint reconocido otros 0.15", async () => {
		const lock = await makeDir({
			"pyproject.toml": PYPROJECT,
			"uv.lock": "version = 1\n",
		});
		expect(await pythonAdapter.detect(lock)).toBeCloseTo(0.75);
		const poetry = await makeDir({
			"pyproject.toml": PYPROJECT,
			"poetry.lock": "[metadata]\n",
			"main.py": "print(1)\n",
		});
		expect(await pythonAdapter.detect(poetry)).toBeCloseTo(0.9);
		const entry = await makeDir({
			"requirements.txt": "",
			"app.py": "x = 1\n",
		});
		expect(await pythonAdapter.detect(entry)).toBeCloseTo(0.75);
	});

	it("PY-001 un [project.scripts] cuenta como entrypoint y el tope es 0.9", async () => {
		const dir = await makeDir({
			"pyproject.toml": `${PYPROJECT}[project.scripts]\ndemo = "demo.cli:main"\n`,
			"uv.lock": "version = 1\n",
			"main.py": "x = 1\n",
		});
		expect(await pythonAdapter.detect(dir)).toBeCloseTo(0.9);
	});

	it("PY-001 python por archivos: 0.35 con 2 .py dominantes y sin manifiesto", async () => {
		const dir = await makeDir({
			"a.py": "print('a')\n".repeat(20),
			"b.py": "print('b')\n".repeat(20),
			"README.md": "hola\n",
		});
		expect(await pythonAdapter.detect(dir)).toBeCloseTo(0.35);
	});

	it("PY-001 python por archivos: 0 con un solo .py o si otro lenguaje pesa mas", async () => {
		const one = await makeDir({ "a.py": "x = 1\n" });
		expect(await pythonAdapter.detect(one)).toBe(0);
		const mixed = await makeDir({
			"a.py": "x = 1\n",
			"b.py": "y = 2\n",
			"big.go": "package main\n".repeat(100),
		});
		expect(await pythonAdapter.detect(mixed)).toBe(0);
	});

	it("PY-001 un origen sin Python da 0", async () => {
		const dir = await makeDir({ "index.html": "<html></html>" });
		expect(await pythonAdapter.detect(dir)).toBe(0);
	});

	it("PY-001 un pyproject.toml invalido no rompe la deteccion", async () => {
		const dir = await makeDir({ "pyproject.toml": "[project\nname =" });
		expect(await pythonAdapter.detect(dir)).toBeGreaterThanOrEqual(0.6);
	});

	it("SCAN-014 las reglas propias son de secreto y criticas", () => {
		const rules = pythonAdapter.rules();
		expect(rules.length).toBeGreaterThan(0);
		for (const r of rules) {
			expect(r.tipo).toBe("secreto");
			expect(r.severidad).toBe("critico");
		}
	});

	it("SCAN-014 detecta credenciales en index-url y SECRET_KEY literal", () => {
		const [urlRule, keyRule] = pythonAdapter.rules();
		const pass = ["p", "w", "d", "x", "y", "z", "1", "2"].join("");
		const url = `--extra-index-url https://${["bo", "t"].join("")}:${pass}@pypi.example.test/simple`;
		expect(urlRule?.patron.exec(url)?.[1]).toBe(pass);
		const val = ["abcd", "efgh", "ijkl", "mnop", "qrst"].join("");
		expect(keyRule?.patron.exec(`SECRET_KEY = "${val}"`)?.[1]).toBe(val);
		expect(keyRule?.patron.test('SECRET_KEY = os.environ["SECRET_KEY"]')).toBe(
			false,
		);
		expect(urlRule?.patron.test("--index-url https://pypi.org/simple")).toBe(
			false,
		);
	});
});
