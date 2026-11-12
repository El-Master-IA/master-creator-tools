import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { envExpression } from "../../scanner/test/fixtures/secretos.js";
import { nodeAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-node-env-"));
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

const pkg = `${JSON.stringify({ name: "demo", scripts: { start: "node src/index.js" } })}\n`;

describe("adapter-node: variables de entorno", () => {
	it("NODE-001 lista las variables leidas en process.env e import.meta.env", async () => {
		const meta = ["import", ".meta", ".env", ".", "VITE_API"].join("");
		const ws = await makeWs({
			"package.json": pkg,
			"src/index.js": [
				`const a = ${envExpression("SERVICE_URL")};`,
				`const b = ${envExpression("PORT")} || 3000;`,
				`const c = ${meta};`,
			].join("\n"),
		});
		const a = await nodeAdapter.analyze(ws);
		const names = a.envVars.map((v) => v.nombre).sort();
		expect(names).toEqual(["PORT", "SERVICE_URL", "VITE_API"]);
		const byName = Object.fromEntries(
			a.envVars.map((v) => [v.nombre, v.obligatoria]),
		);
		expect(byName.SERVICE_URL).toBe(true);
		expect(byName.PORT).toBe(false);
	});

	it("NODE-001 lista los nombres de .env* sin guardar sus valores", async () => {
		const value = ["val", "ue-", "oculto"].join("");
		const ws = await makeWs(
			{ "package.json": pkg, ".env.example": "EXAMPLE_VAR=\n" },
			{ ".env": `export DB_HOST=${value}\n# nota=1\nOTHER_ONE = x\n` },
		);
		const a = await nodeAdapter.analyze(ws);
		const names = a.envVars.map((v) => v.nombre).sort();
		expect(names).toEqual(["DB_HOST", "EXAMPLE_VAR", "OTHER_ONE"]);
		expect(JSON.stringify(a)).not.toContain(value);
	});

	it("NODE-001 ignora node_modules y devuelve nombres unicos", async () => {
		const ws = await makeWs({
			"package.json": pkg,
			"src/a.js": `${envExpression("DUP")};\n${envExpression("DUP")};\n`,
			"node_modules/x/index.js": `${envExpression("DENTRO")};\n`,
		});
		const a = await nodeAdapter.analyze(ws);
		expect(a.envVars.map((v) => v.nombre)).toEqual(["DUP"]);
	});
});
