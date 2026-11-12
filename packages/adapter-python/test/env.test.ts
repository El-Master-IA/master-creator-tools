import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { pythonAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-py-env-"));
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

async function vars(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Record<string, boolean>> {
	const a = await pythonAdapter.analyze(await makeWs(work, quarantine));
	return Object.fromEntries(a.envVars.map((v) => [v.nombre, v.obligatoria]));
}

describe("adapter-python: variables de entorno (PY-002)", () => {
	it("PY-002 os.environ[X] y environ[X] son obligatorias", async () => {
		const got = await vars({
			"requirements.txt": "",
			"app.py": [
				"import os",
				"from os import environ",
				'a = os.environ["DB_URL"]',
				"b = environ['API_HOST']",
				"",
			].join("\n"),
		});
		expect(got).toEqual({ DB_URL: true, API_HOST: true });
	});

	it("PY-002 get y getenv sin valor por defecto son obligatorias, con defecto opcionales", async () => {
		const got = await vars({
			"requirements.txt": "",
			"app.py": [
				"import os",
				'a = os.environ.get("NEEDED")',
				'b = os.getenv("ALSO_NEEDED")',
				'c = os.getenv("WITH_DEFAULT", "x")',
				'd = os.environ.get("TIMEOUT", "30")',
				'e = os.getenv("NONE_DEFAULT", None)',
				"",
			].join("\n"),
		});
		expect(got).toEqual({
			NEEDED: true,
			ALSO_NEEDED: true,
			WITH_DEFAULT: false,
			TIMEOUT: false,
			NONE_DEFAULT: true,
		});
	});

	it("PY-002 una variable leida con y sin defecto queda obligatoria", async () => {
		const got = await vars({
			"requirements.txt": "",
			"a.py": 'import os\nx = os.getenv("MIXED", "d")\n',
			"b.py": 'import os\ny = os.environ["MIXED"]\n',
		});
		expect(got).toEqual({ MIXED: true });
	});

	it("PY-002 asignar a os.environ no cuenta como lectura", async () => {
		const got = await vars({
			"requirements.txt": "",
			"app.py": 'import os\nos.environ["WRITTEN"] = "1"\n',
		});
		expect(got).toEqual({});
	});

	it("PY-002 campos de BaseSettings con env= o alias=", async () => {
		const got = await vars({
			"requirements.txt": "",
			"settings.py": [
				"from pydantic_settings import BaseSettings",
				"from pydantic import Field",
				"class S(BaseSettings):",
				'    token: str = Field(..., env="SERVICE_TOKEN")',
				'    mode: str = Field("dev", alias="APP_MODE")',
				'    url: str = Field(default="x", env="BASE_URL")',
				"",
			].join("\n"),
		});
		expect(got).toEqual({
			SERVICE_TOKEN: true,
			APP_MODE: false,
			BASE_URL: false,
		});
	});

	it("PY-002 nombres de .env* en quarantine son opcionales y nunca se guardan valores", async () => {
		const secret = ["valor", "secreto", "123"].join("-");
		const a = await pythonAdapter.analyze(
			await makeWs(
				{
					"requirements.txt": "",
					"app.py": 'import os\nx = os.environ["REQ"]\n',
				},
				{
					".env": `DB_PASSWORD=${secret}\nexport REQ=1\n# nada\n`,
					".env.local": "OTHER=1\n",
				},
			),
		);
		const byName = Object.fromEntries(
			a.envVars.map((v) => [v.nombre, v.obligatoria]),
		);
		expect(byName).toEqual({ REQ: true, DB_PASSWORD: false, OTHER: false });
		expect(JSON.stringify(a)).not.toContain(secret);
	});
});
