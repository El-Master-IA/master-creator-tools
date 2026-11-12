import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import {
	envExpression,
	makeSecrets,
} from "../../scanner/test/fixtures/secretos.js";
import { findRegistryIssues, nodeAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	quarantine: Record<string, string> = {},
	dist: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-node-rev-"));
	roots.push(raiz);
	for (const [zone, files] of [
		["work", work],
		["quarantine", quarantine],
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

const host = ["registry", ".privado", ".test"].join("");
const pkg = `${JSON.stringify({ name: "x", scripts: { start: "node a.js" } })}\n`;
const envBase = ["proc", "ess", ".env"].join("");
const TICK = String.fromCharCode(96);

function secret(): string {
	const s = makeSecrets()[3];
	if (!s) throw new Error("secreto ausente");
	return s.value;
}

describe("adapter-node: arreglos de revision", () => {
	it("VER-001 install usa un shim de corepack sin root en $HOME y start usa corepack <gestor>", async () => {
		for (const [lock, gestor] of [
			["pnpm-lock.yaml", "pnpm"],
			["yarn.lock", "yarn"],
		] as const) {
			const ws = await makeWs({ "package.json": pkg, [lock]: "" });
			const spec = nodeAdapter.verifyCommand(await nodeAdapter.analyze(ws));
			const install = spec.install?.[2] ?? "";
			// The system-wide "corepack enable" needs root; only the $HOME shim is allowed.
			expect(install).not.toMatch(
				/corepack enable(?! --install-directory "\$HOME\/\.mct-bin")/,
			);
			expect(install).toContain(
				`corepack enable --install-directory "$HOME/.mct-bin" ${gestor} && export PATH="$HOME/.mct-bin:$PATH" && corepack ${gestor} `,
			);
			expect(spec.start.slice(0, 2)).toEqual(["corepack", gestor]);
		}
	});

	it("SCAN-012 detecta resolved de package-lock.json y yarn v1", async () => {
		const a = await makeWs({
			"package.json": pkg,
			"package-lock.json": `{\n  "resolved": "https://${host}/p/-/p-1.tgz"\n}\n`,
		});
		expect((await findRegistryIssues(a)).map((i) => i.tipo)).toEqual([
			"registro-privado",
		]);
		const b = await makeWs({
			"package.json": pkg,
			"yarn.lock": `  resolved "https://${host}/p/-/p-1.tgz#abc"\n`,
		});
		expect((await findRegistryIssues(b)).map((i) => i.tipo)).toEqual([
			"registro-privado",
		]);
	});

	it("SCAN-012 credencial sin password en la URL da hallazgo", async () => {
		const token = secret();
		const lock = `  resolved "https://${token}@${host}/p/-/p-1.tgz"\n`;
		const ws = await makeWs({ "package.json": pkg, "yarn.lock": lock });
		const issues = await findRegistryIssues(ws);
		expect(issues.map((i) => i.tipo)).toContain("credenciales-en-url");
		expect(JSON.stringify(issues)).not.toContain(token);
	});

	it("SCAN-012 lockfile de 3 MB se lee entero", async () => {
		const filler = `${"a".repeat(99)}\n`.repeat(30_000);
		const lock = `${filler}resolved: https://${host}/p.tgz\n`;
		expect(lock.length).toBeGreaterThan(3_000_000);
		const ws = await makeWs({ "package.json": pkg, "pnpm-lock.yaml": lock });
		const issues = await findRegistryIssues(ws);
		expect(issues.map((i) => i.tipo)).toEqual(["registro-privado"]);
		expect(issues[0]?.linea).toBe(30_001);
	});

	it("SCAN-012 lockfile ilegible lanza MctError (fail closed)", async () => {
		const ws = await makeWs({ "package.json": pkg });
		await mkdir(join(ws.work, "package-lock.json"));
		let caught: unknown;
		try {
			await findRegistryIssues(ws);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(MctError);
	});

	it("SCAN-012 recorre lockfiles anidados y .npmrc anidados solo de quarantine", async () => {
		const ws = await makeWs(
			{
				"package.json": pkg,
				"packages/a/package-lock.json": `{"resolved": "https://${host}/x.tgz"}\n`,
				"packages/a/.npmrc": `registry=https://${host}/\n`,
			},
			{ "packages/b/.npmrc": `registry=https://${host}/\n` },
		);
		const issues = await findRegistryIssues(ws);
		expect(issues.map((i) => `${i.zona}:${i.archivo}`).sort()).toEqual([
			"quarantine:packages/b/.npmrc",
			"work:packages/a/package-lock.json",
		]);
	});

	it("SCAN-012 detecta git+https y no exime codeload.github.com", async () => {
		const a = await makeWs({
			"package.json": pkg,
			"package-lock.json": `{"resolved": "git+https://github.com/org/repo.git#abc"}\n`,
		});
		expect((await findRegistryIssues(a)).map((i) => i.tipo)).toContain(
			"git-privado",
		);
		const b = await makeWs({
			"package.json": pkg,
			"package-lock.json": `{"resolved": "https://codeload.github.com/org/repo/tar.gz/abc"}\n`,
		});
		expect((await findRegistryIssues(b)).map((i) => i.tipo)).toContain(
			"registro-privado",
		);
	});

	it("SEG-004 las reglas no sufren ReDoS (a x 200 KB y git@ x 50 mil)", () => {
		const inputs = ["a".repeat(200_000), "git@".repeat(50_000)];
		for (const r of nodeAdapter.rules()) {
			for (const input of inputs) {
				const t0 = performance.now();
				new RegExp(r.patron.source, "gi").test(input);
				expect(performance.now() - t0).toBeLessThan(1000);
			}
		}
	});

	it("NODE-002 generalize calcula offsets sobre el contenido crudo con CRLF", async () => {
		const raw =
			`${JSON.stringify({ name: "x", author: "A", license: "MIT" }, null, 2)}\n`.replace(
				/\n/g,
				"\r\n",
			);
		const ws = await makeWs({}, {}, { "package.json": raw });
		const changes = await nodeAdapter.generalize?.(ws);
		const change = changes?.[0];
		if (change?.tipo !== "editar") throw new Error("se esperaba editar");
		expect(change.desde).toBe(0);
		expect(change.hasta).toBe(raw.length);
		expect(JSON.parse(raw.slice(0, change.desde) + change.texto)).toEqual({
			name: "x",
			license: "MIT",
		});
	});

	it("NODE-002 el fallback node <bin> --version fuerza salida-cero aunque haya puerto", async () => {
		const ws = await makeWs(
			{ "package.json": `${JSON.stringify({ name: "x", bin: "bin/x.js" })}\n` },
			{ ".env": "PORT=4000\n" },
		);
		const a = await nodeAdapter.analyze(ws);
		expect(a.puerto).toBe(4000);
		expect(nodeAdapter.verifyCommand(a).healthcheck).toEqual({
			tipo: "salida-cero",
		});
	});

	it("NODE-001 infiere el puerto de PORT || 3000 usado en listen(PORT)", async () => {
		const ws = await makeWs({
			"package.json": `${JSON.stringify({ name: "x", main: "a.js" })}\n`,
			"a.js": `const PORT = ${envExpression("PORT")} || 3000;\napp.listen(PORT);\n`,
		});
		const a = await nodeAdapter.analyze(ws);
		expect(a.puerto).toBe(3000);
	});

	it("NODE-001 capta desestructuracion y corchetes con backtick", async () => {
		const ws = await makeWs({
			"package.json": pkg,
			"a.js": [
				`const { ALPHA, BETA = 1, GAMMA: g } = ${envBase};`,
				`const d = ${envBase}[${TICK}DELTA${TICK}];`,
			].join("\n"),
		});
		const a = await nodeAdapter.analyze(ws);
		const by = Object.fromEntries(
			a.envVars.map((v) => [v.nombre, v.obligatoria]),
		);
		expect(by).toEqual({
			ALPHA: true,
			BETA: false,
			GAMMA: true,
			DELTA: true,
		});
	});

	it("SCAN-012 credencial en URL con password sigue captando solo el password", () => {
		const pass = secret();
		const r = nodeAdapter.rules().find((x) => x.id === "node-url-credenciales");
		const m = new RegExp(r?.patron.source ?? "", "i").exec(
			`https://deploy:${pass}@${host}/p`,
		);
		expect(m?.[1]).toBe(pass);
	});
});

describe("adapter-node: re-auditoria findRegistryIssues", () => {
	it("SCAN-012 raiz work inexistente lanza WORKSPACE_INVALIDO", async () => {
		const ws = await makeWs({ "package.json": "{}" });
		const roto: Workspace = { ...ws, work: join(ws.raiz, "no-existe") };
		const err: unknown = await findRegistryIssues(roto).catch((e) => e);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("SCAN-012 raiz quarantine inexistente lanza WORKSPACE_INVALIDO", async () => {
		const ws = await makeWs({ "package.json": "{}" });
		const roto: Workspace = { ...ws, quarantine: join(ws.raiz, "no-existe") };
		const err: unknown = await findRegistryIssues(roto).catch((e) => e);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("WORKSPACE_INVALIDO");
	});
});
