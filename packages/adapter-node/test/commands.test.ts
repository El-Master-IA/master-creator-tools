import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { nodeAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	dist: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-node-cmd-"));
	roots.push(raiz);
	for (const [zone, files] of [
		["work", work],
		["quarantine", {}],
		["dist", dist],
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

const json = (o: unknown): string => `${JSON.stringify(o, null, 2)}\n`;

describe("adapter-node: gestor y comandos", () => {
	it("NODE-002 detecta pnpm por pnpm-lock.yaml y arma install, build y start", async () => {
		const ws = await makeWs({
			"package.json": json({
				name: "demo",
				scripts: { start: "node src/index.js", build: "tsc" },
				dependencies: { commander: "15.1.0" },
			}),
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		});
		const a = await nodeAdapter.analyze(ws);
		expect(a.gestor).toBe("pnpm");
		expect(a.comandos.install).toBe(
			"pnpm install --frozen-lockfile && pnpm run build",
		);
		expect(a.comandos.build).toBe("pnpm run build");
		expect(a.comandos.start).toBe("pnpm start");
		expect(a.deps).toEqual([{ nombre: "commander", version: "15.1.0" }]);
	});

	it("NODE-002 detecta yarn y npm", async () => {
		const yarn = await makeWs({
			"package.json": json({ scripts: { start: "node a.js" } }),
			"yarn.lock": "",
		});
		const a1 = await nodeAdapter.analyze(yarn);
		expect(a1.gestor).toBe("yarn");
		expect(a1.comandos.install).toBe("yarn install --frozen-lockfile");
		const npm = await makeWs({
			"package.json": json({ scripts: { start: "node a.js" } }),
			"package-lock.json": "{}\n",
		});
		const a2 = await nodeAdapter.analyze(npm);
		expect(a2.gestor).toBe("npm");
		expect(a2.comandos.install).toBe("npm ci");
	});

	it("NODE-002 detecta el puerto declarado", async () => {
		const ws = await makeWs({
			"package.json": json({ scripts: { start: "PORT=8080 node a.js" } }),
		});
		const a = await nodeAdapter.analyze(ws);
		expect(a.puerto).toBe(8080);
		expect(nodeAdapter.verifyCommand(a).healthcheck).toEqual({
			tipo: "http",
			puerto: 8080,
		});
	});

	it("NODE-002 sin script start usa node <bin> --version", async () => {
		const ws = await makeWs({
			"package.json": json({ name: "x", bin: { x: "./bin/x.js" } }),
		});
		const a = await nodeAdapter.analyze(ws);
		expect(a.comandos.start).toBe("node bin/x.js --version");
		expect(a.entrypoints).toContain("bin/x.js");
		const spec = nodeAdapter.verifyCommand(a);
		expect(spec.start).toEqual(["node", "bin/x.js", "--version"]);
		expect(spec.healthcheck).toEqual({ tipo: "salida-cero" });
		expect(spec.imagen).toBe("node:22-slim");
	});

	it("NODE-002 sin start ni bin da PUERTA_BLOQUEADA con motivo sin-arranque", async () => {
		const ws = await makeWs({ "package.json": json({ name: "x" }) });
		const a = await nodeAdapter.analyze(ws);
		expect(a.comandos.start).toBeUndefined();
		let caught: unknown;
		try {
			nodeAdapter.verifyCommand(a);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(MctError);
		const err = caught as MctError;
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle).toEqual({ motivo: "sin-arranque" });
	});

	it("NODE-002 detect da confianza alta con package.json y 0 sin el", async () => {
		const ws = await makeWs({
			"package.json": json({ name: "x" }),
			"pnpm-lock.yaml": "",
		});
		expect(await nodeAdapter.detect(ws.work)).toBeGreaterThan(0.5);
		const vacio = await makeWs({});
		expect(await nodeAdapter.detect(vacio.work)).toBe(0);
	});

	it("NODE-002 generalize quita author, repository, homepage y bugs de dist", async () => {
		const ws = await makeWs(
			{ "package.json": json({ name: "x" }) },
			{
				"package.json": json({
					name: "x",
					author: "Alguien",
					repository: { type: "git", url: "git+https://example.com/x.git" },
					homepage: "https://example.com",
					bugs: { url: "https://example.com/issues" },
					license: "MIT",
				}),
			},
		);
		const changes = await nodeAdapter.generalize?.(ws);
		expect(changes).toHaveLength(1);
		const change = changes?.[0];
		if (change?.tipo !== "editar") throw new Error("se esperaba editar");
		expect(change.ruta).toBe("package.json");
		const original = await readFile(join(ws.dist, "package.json"), "utf8");
		const result = original.slice(0, change.desde) + change.texto;
		expect(change.hasta).toBe(original.length);
		expect(JSON.parse(result)).toEqual({ name: "x", license: "MIT" });
		expect(result.endsWith("\n")).toBe(true);
		expect(result).not.toContain("\r");
	});

	it("NODE-002 generalize no cambia nada si no hay esos campos", async () => {
		const ws = await makeWs({}, { "package.json": json({ name: "x" }) });
		expect(await nodeAdapter.generalize?.(ws)).toEqual([]);
	});

	it("NODE-002 packageHints lista instalacion, uso y variables", async () => {
		const ws = await makeWs({
			"package.json": json({ scripts: { start: "node a.js" } }),
			"pnpm-lock.yaml": "",
			"a.js": "",
		});
		const a = await nodeAdapter.analyze(ws);
		const hints = nodeAdapter.packageHints({
			...a,
			envVars: [{ nombre: "TOKEN_X", obligatoria: true }],
		});
		expect(hints.instalacion).toContain("pnpm install --frozen-lockfile");
		expect(hints.uso).toContain("pnpm start");
		expect(hints.variables[0]?.nombre).toBe("TOKEN_X");
		expect(hints.requisitos[0]).toMatch(/Node/);
	});
});
