import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Rule, Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { makeSecrets } from "../../scanner/test/fixtures/secretos.js";
import { findRegistryIssues, nodeAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-node-reg-"));
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

function secret(): string {
	const s = makeSecrets()[3];
	if (!s) throw new Error("secreto ausente");
	return s.value;
}

function rule(id: string): Rule {
	const r = nodeAdapter.rules().find((x) => x.id === id);
	if (!r) throw new Error(`regla ausente: ${id}`);
	return r;
}

const host = ["registry", ".privado", ".test"].join("");
const pkg = `${JSON.stringify({ name: "x", scripts: { start: "node a.js" } })}\n`;

function matches(r: Rule, text: string): string[] {
	const re = new RegExp(r.patron.source, `${r.patron.flags}g`);
	return [...text.matchAll(re)].map((m) => m[1] ?? m[0]);
}

describe("adapter-node: registros privados", () => {
	it("SCAN-012 reporta credenciales en una URL del lockfile sin guardarlas", async () => {
		const pass = secret();
		const lock = `resolved: https://deploy:${pass}@${host}/pkg/-/pkg-1.0.0.tgz\n`;
		const ws = await makeWs({ "package.json": pkg, "pnpm-lock.yaml": lock });
		const issues = await findRegistryIssues(ws);
		const hit = issues.find((i) => i.tipo === "credenciales-en-url");
		expect(hit).toMatchObject({
			archivo: "pnpm-lock.yaml",
			zona: "work",
			linea: 1,
		});
		expect(JSON.stringify(issues)).not.toContain(pass);
		const r = rule("node-url-credenciales");
		expect(r.tipo).toBe("secreto");
		expect(matches(r, lock)).toEqual([pass]);
	});

	it("SCAN-012 reporta un registro privado en el lockfile", async () => {
		const lock = `resolved: https://${host}/pkg/-/pkg-1.0.0.tgz\n`;
		const ws = await makeWs({ "package.json": pkg, "package-lock.json": lock });
		const issues = await findRegistryIssues(ws);
		expect(issues.map((i) => i.tipo)).toEqual(["registro-privado"]);
		const r = rule("node-registro-privado");
		expect(r.tipo).toBe("estructura");
		expect(matches(r, lock)).toEqual([`https://${host}/pkg/-/pkg-1.0.0.tgz`]);
	});

	it("SCAN-012 no reporta el registro publico de npm", async () => {
		const lock = "resolved: https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz\n";
		const ws = await makeWs({ "package.json": pkg, "package-lock.json": lock });
		expect(await findRegistryIssues(ws)).toEqual([]);
	});

	it("SCAN-012 lee .npmrc solo de quarantine y reporta registro y credencial", async () => {
		const pass = secret();
		const npmrc = [
			`registry=https://${host}/`,
			`//${host}/:_authToken=${pass}`,
			"",
		].join("\n");
		const ws = await makeWs({ "package.json": pkg }, { ".npmrc": npmrc });
		const issues = await findRegistryIssues(ws);
		const tipos = issues.map((i) => i.tipo).sort();
		expect(tipos).toEqual(["credenciales-en-npmrc", "registro-privado"]);
		expect(issues.every((i) => i.zona === "quarantine")).toBe(true);
		expect(JSON.stringify(issues)).not.toContain(pass);
	});

	it("SCAN-012 reporta una dependencia git por ssh", async () => {
		const lock = "resolved: git+ssh://git@github.com/org/repo.git#abc123\n";
		const ws = await makeWs({ "package.json": pkg, "yarn.lock": lock });
		const issues = await findRegistryIssues(ws);
		expect(issues.map((i) => i.tipo)).toEqual(["git-privado"]);
	});

	it("SCAN-012 un .npmrc en work no se lee (va a cuarentena)", async () => {
		const ws = await makeWs({
			"package.json": pkg,
			".npmrc": `registry=https://${host}/\n`,
		});
		expect(await findRegistryIssues(ws)).toEqual([]);
	});
});

describe("SCAN-012 el registro público oficial no es privado", () => {
	const patron = (): RegExp => rule("node-registro-privado").patron;

	it("SCAN-012 una constante con el host público de npm o yarn, con o sin barra, no es hallazgo", () => {
		const host = ["https://registry", "npmjs", "org"].join(".");
		const yarn = ["https://registry", "yarnpkg", "com"].join(".");
		for (const line of [
			`const REGISTRY = "${host}";`,
			`registry=${host}/`,
			`"resolved": "${host}/left-pad/-/left-pad-1.0.0.tgz"`,
			`registry = '${yarn}'`,
		]) {
			expect(patron().test(line), line).toBe(false);
		}
	});

	it("SCAN-012 un host que solo empieza igual sigue siendo privado", () => {
		const base = ["https://registry", "npmjs", "org"].join(".");
		for (const line of [
			`registry=${base}.interno.test/`,
			`registry=${base}-mirror.test`,
			`registry=https://npm.interno.test`,
		]) {
			expect(patron().test(line), line).toBe(true);
		}
	});
});
