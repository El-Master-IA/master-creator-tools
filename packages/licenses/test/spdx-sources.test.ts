import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { register } from "../../cli/src/commands/licenses.js";
import { runCli } from "../../cli/src/main.js";
import type { Io } from "../../cli/src/output.js";
import { createWorkspace, readState } from "../../core/src/workspace.js";
import { auditLicenses, type FetchLike } from "../src/audit.js";

let root: string;
let work: string;
let origin: string;

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "mct-lic-"));
	work = join(root, "work");
	origin = join(root, "origin");
	await mkdir(work, { recursive: true });
	await mkdir(origin, { recursive: true });
});

afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});

async function put(path: string, content: string): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, content);
}

const json = (v: unknown) => JSON.stringify(v);

function toDeps(names: string[]): Record<string, string> {
	return Object.fromEntries(names.map((n) => [n, "*"]));
}

function packageLock(
	packages: Record<string, unknown>,
	deps: string[] = [],
): string {
	return json({
		name: "app",
		lockfileVersion: 3,
		packages: {
			"": { name: "app", version: "1.0.0", dependencies: toDeps(deps) },
			...packages,
		},
	});
}

function registryOk(table: Record<string, unknown>): FetchLike {
	return vi.fn(async (url: string) => {
		const hit = table[new URL(url).pathname];
		if (hit === undefined) return new Response("{}", { status: 404 });
		return new Response(json(hit), { status: 200 });
	});
}

function neverCalled(): FetchLike {
	return vi.fn(async () => {
		throw new Error("the registry must not be called");
	});
}

describe("LIC-004 source (a): lockfile", () => {
	it("LIC-004 CUANDO el lockfile trae license EL SISTEMA DEBE usarlo sin red", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock(
				{
					"node_modules/left-pad": { version: "1.3.0", license: "MIT" },
					"node_modules/left-pad/node_modules/inner": {
						version: "2.0.0",
						license: "GPL-3.0",
					},
				},
				["left-pad"],
			),
		);
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		const byName = Object.fromEntries(
			result.entries.map((e) => [e.paquete, e]),
		);
		expect(byName["left-pad"]).toMatchObject({
			spdx: "MIT",
			origen: "directa",
			veredicto: "ok",
		});
		expect(byName.inner).toMatchObject({
			spdx: "GPL-3.0",
			origen: "transitiva",
			veredicto: "bloquea",
		});
		expect(result.resumen).toEqual({
			paquetes: 2,
			bloquea: 1,
			revisar: 0,
			overrides: 0,
		});
	});

	it("LIC-004 the lockfile wins over node_modules and the registry", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({ "node_modules/a": { version: "1.0.0", license: "MIT" } }),
		);
		await put(
			join(origin, "node_modules/a/package.json"),
			json({ name: "a", version: "1.0.0", license: "GPL-3.0" }),
		);
		const fetchFn = neverCalled();
		const result = await auditLicenses({
			lockDir: work,
			originDir: origin,
			fetch: fetchFn,
		});
		expect(result.entries[0]?.spdx).toBe("MIT");
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-004 accepts the legacy license object and licenses array", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({
				"node_modules/a": { version: "1.0.0", license: { type: "ISC" } },
				"node_modules/b": {
					version: "1.0.0",
					license: [{ type: "MIT" }, { type: "Apache-2.0" }],
				},
			}),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => e.spdx)).toEqual([
			"ISC",
			"(MIT OR Apache-2.0)",
		]);
	});

	it("LIC-004 an unreadable lockfile is an error, never an empty report", async () => {
		await put(join(work, "package-lock.json"), "{ not json");
		await expect(auditLicenses({ lockDir: work })).rejects.toBeInstanceOf(
			MctError,
		);
	});

	it("LIC-004 a package-lock without packages (v1) is refused", async () => {
		await put(
			join(work, "package-lock.json"),
			json({ lockfileVersion: 1, dependencies: {} }),
		);
		await expect(auditLicenses({ lockDir: work })).rejects.toMatchObject({
			codigo: "VALIDACION",
		});
	});

	it("LIC-004 a Node project without lockfile closes the gate", async () => {
		await expect(auditLicenses({ lockDir: work })).rejects.toMatchObject({
			codigo: "PUERTA_BLOQUEADA",
		});
	});
});

describe("LIC-004 source (b): node_modules of the origin", () => {
	const lock = () =>
		packageLock({ "node_modules/dep": { version: "1.2.3" } }, ["dep"]);

	it("LIC-004 reads node_modules/<pkg>/package.json when the lockfile has no license", async () => {
		await put(join(work, "package-lock.json"), lock());
		await put(
			join(origin, "node_modules/dep/package.json"),
			json({ name: "dep", version: "1.2.3", license: "BSD-3-Clause" }),
		);
		const fetchFn = neverCalled();
		const result = await auditLicenses({
			lockDir: work,
			originDir: origin,
			fetch: fetchFn,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries[0]).toMatchObject({
			spdx: "BSD-3-Clause",
			veredicto: "ok",
		});
	});

	it("LIC-004 ignores a node_modules copy of another version", async () => {
		await put(join(work, "package-lock.json"), lock());
		await put(
			join(origin, "node_modules/dep/package.json"),
			json({ name: "dep", version: "9.9.9", license: "MIT" }),
		);
		const result = await auditLicenses({
			lockDir: work,
			originDir: origin,
			offline: true,
		});
		expect(result.entries[0]).toMatchObject({
			spdx: null,
			veredicto: "revisar",
		});
	});

	it("LIC-004 never follows a linked package directory", async () => {
		await put(join(work, "package-lock.json"), lock());
		const outside = join(root, "outside");
		await put(
			join(outside, "package.json"),
			json({ name: "dep", version: "1.2.3", license: "MIT" }),
		);
		await mkdir(join(origin, "node_modules"), { recursive: true });
		try {
			await symlink(outside, join(origin, "node_modules/dep"), "junction");
		} catch {
			return; // the platform refuses links: nothing to prove here
		}
		const result = await auditLicenses({
			lockDir: work,
			originDir: origin,
			offline: true,
		});
		expect(result.entries[0]?.spdx).toBeNull();
	});
});

describe("LIC-004 source (c): registry", () => {
	const lock = () =>
		packageLock({ "node_modules/@s/dep": { version: "1.2.3" } }, ["@s/dep"]);

	it("LIC-004 asks the registry without credentials when nothing else has the SPDX", async () => {
		await put(join(work, "package-lock.json"), lock());
		const fetchFn = registryOk({ "/@s%2Fdep/1.2.3": { license: "MIT" } });
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(result.entries[0]).toMatchObject({ spdx: "MIT", veredicto: "ok" });
		const calls = vi.mocked(fetchFn).mock.calls;
		expect(calls).toHaveLength(1);
		const [url, init] = calls[0] ?? [];
		expect(String(url)).toBe("https://registry.npmjs.org/@s%2Fdep/1.2.3");
		const headers = JSON.stringify(init?.headers ?? {}).toLowerCase();
		expect(headers).not.toContain("authorization");
		expect(headers).not.toContain("cookie");
	});

	it("LIC-004 CUANDO se usa --offline EL SISTEMA DEBE no llamar al registro", async () => {
		await put(join(work, "package-lock.json"), lock());
		const fetchFn = neverCalled();
		const result = await auditLicenses({
			lockDir: work,
			offline: true,
			fetch: fetchFn,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries[0]).toMatchObject({
			spdx: null,
			veredicto: "revisar",
		});
	});

	it("LIC-004 CUANDO el registro vence EL SISTEMA DEBE dejar el paquete en revisar", async () => {
		await put(join(work, "package-lock.json"), lock());
		const hang: FetchLike = (_url, init) =>
			new Promise((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () =>
					reject(new Error("aborted")),
				);
			});
		const result = await auditLicenses({
			lockDir: work,
			fetch: hang,
			timeoutMs: 20,
		});
		expect(result.entries[0]).toMatchObject({
			spdx: null,
			veredicto: "revisar",
		});
		expect(result.resumen.revisar).toBe(1);
	});

	it("LIC-004 a 404, a network error or an oversized body leave the package in revisar", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({
				"node_modules/a": { version: "1.0.0" },
				"node_modules/b": { version: "1.0.0" },
				"node_modules/c": { version: "1.0.0" },
			}),
		);
		const fetchFn: FetchLike = async (url) => {
			if (url.endsWith("/a/1.0.0")) return new Response("{}", { status: 404 });
			if (url.endsWith("/b/1.0.0")) throw new Error("ECONNRESET");
			return new Response(`{"license":"MIT","pad":"${"x".repeat(2000)}"}`, {
				status: 200,
			});
		};
		const result = await auditLicenses({
			lockDir: work,
			fetch: fetchFn,
			maxBodyBytes: 1000,
		});
		expect(result.entries.map((e) => e.veredicto)).toEqual([
			"revisar",
			"revisar",
			"revisar",
		]);
	});

	it("LIC-004 runs at most 8 requests in parallel", async () => {
		const names = Array.from({ length: 30 }, (_, i) => `p${i}`);
		await put(
			join(work, "package-lock.json"),
			packageLock(
				Object.fromEntries(
					names.map((n) => [`node_modules/${n}`, { version: "1.0.0" }]),
				),
			),
		);
		let active = 0;
		let peak = 0;
		const fetchFn: FetchLike = async () => {
			active += 1;
			peak = Math.max(peak, active);
			await new Promise((r) => setTimeout(r, 5));
			active -= 1;
			return new Response(json({ license: "MIT" }), { status: 200 });
		};
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(result.entries).toHaveLength(30);
		expect(peak).toBeLessThanOrEqual(8);
		expect(peak).toBeGreaterThan(1);
	});

	it("LIC-004 does not build a URL from a hostile package name", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({
				"node_modules/a": { version: "1.0.0", name: "../x?y#z" },
			}),
		);
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries[0]?.veredicto).toBe("revisar");
	});

	it("LIC-004 packages without lockfile (n8n community nodes) use the registry", async () => {
		const fetchFn = registryOk({
			"/n8n-nodes-demo/latest": { license: "MIT", version: "0.4.0" },
		});
		const result = await auditLicenses({
			lockDir: work,
			extra: [{ paquete: "n8n-nodes-demo", version: "latest" }],
			fetch: fetchFn,
		});
		expect(result.entries).toEqual([
			{
				paquete: "n8n-nodes-demo",
				version: "latest",
				spdx: "MIT",
				origen: "directa",
				veredicto: "ok",
			},
		]);
	});
});

describe("LIC-004 other lockfiles", () => {
	it("LIC-004 reads pnpm-lock.yaml v9 and takes the SPDX from node_modules/.pnpm", async () => {
		await put(
			join(work, "package.json"),
			json({ name: "app", dependencies: { "left-pad": "^1.0.0" } }),
		);
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: '9.0'",
				"",
				"importers:",
				"  .:",
				"    dependencies:",
				"      left-pad:",
				"        specifier: ^1.0.0",
				"        version: 1.3.0",
				"",
				"packages:",
				"",
				"  '@scope/inner@2.0.0':",
				"    resolution: {integrity: sha512-abc}",
				"",
				"  left-pad@1.3.0:",
				"    resolution: {integrity: sha512-def}",
				"",
				"snapshots:",
				"",
				"  left-pad@1.3.0(react@18.0.0): {}",
				"",
			].join("\n"),
		);
		await put(
			join(
				origin,
				"node_modules/.pnpm/@scope+inner@2.0.0/node_modules/@scope/inner/package.json",
			),
			json({ name: "@scope/inner", version: "2.0.0", license: "MPL-2.0" }),
		);
		const result = await auditLicenses({
			lockDir: work,
			originDir: origin,
			offline: true,
		});
		expect(
			result.entries.map((e) => [e.paquete, e.version, e.spdx, e.origen]),
		).toEqual([
			["@scope/inner", "2.0.0", "MPL-2.0", "transitiva"],
			["left-pad", "1.3.0", null, "directa"],
		]);
		expect(result.resumen.revisar).toBe(2);
	});

	it("LIC-004 reads a pnpm v5 lockfile with slash keys", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: 5.4",
				"dependencies:",
				"  foo: 1.0.0",
				"packages:",
				"  /foo/1.0.0:",
				"    resolution: {integrity: sha512-x}",
				"  /@a/b/2.0.0_react@18.0.0:",
				"    resolution: {integrity: sha512-y}",
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.version, e.origen])).toEqual(
			[
				["@a/b", "2.0.0", "transitiva"],
				["foo", "1.0.0", "directa"],
			],
		);
	});

	it("LIC-004 reads yarn.lock v1", async () => {
		await put(
			join(work, "package.json"),
			json({ name: "app", devDependencies: { lodash: "^4.0.0" } }),
		);
		await put(
			join(work, "yarn.lock"),
			[
				"# yarn lockfile v1",
				"",
				'"@babel/core@^7.0.0", "@babel/core@^7.1.0":',
				'  version "7.5.0"',
				'  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.5.0.tgz"',
				"",
				"lodash@^4.0.0:",
				'  version "4.17.21"',
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.version, e.origen])).toEqual(
			[
				["@babel/core", "7.5.0", "transitiva"],
				["lodash", "4.17.21", "directa"],
			],
		);
	});

	it("LIC-004 reads yarn.lock berry and skips workspace entries", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				"",
				'"lodash@npm:^4.0.0":',
				"  version: 4.17.21",
				'  resolution: "lodash@npm:4.17.21"',
				"",
				'"app@workspace:.":',
				"  version: 0.0.0-use.local",
				'  resolution: "app@workspace:."',
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.version])).toEqual([
			["lodash", "4.17.21"],
		]);
	});

	it("LIC-004 a yarn.lock block without version is an error", async () => {
		await put(
			join(work, "yarn.lock"),
			["lodash@^4.0.0:", '  resolved "x"', ""].join("\n"),
		);
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 refuses a linked lockfile", async () => {
		const real = join(root, "real-lock.json");
		await put(real, packageLock({}));
		try {
			await symlink(real, join(work, "package-lock.json"), "file");
		} catch {
			return;
		}
		await expect(auditLicenses({ lockDir: work })).rejects.toBeInstanceOf(
			MctError,
		);
	});
});

describe("LIC-003 override inside the audit", () => {
	it("LIC-003 uses licenses.allow with its motivo", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({
				"node_modules/g": { version: "1.0.0", license: "GPL-3.0" },
			}),
		);
		const result = await auditLicenses({
			lockDir: work,
			offline: true,
			allow: [{ spdx: "GPL-3.0", motivo: "herramienta de desarrollo" }],
		});
		expect(result.entries[0]).toMatchObject({
			veredicto: "ok",
			override: { motivo: "herramienta de desarrollo" },
		});
		expect(result.resumen).toMatchObject({ bloquea: 0, overrides: 1 });
	});
});

describe("LIC-004 determinism", () => {
	it("LIC-004 the same lockfile gives the same entries", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock({
				"node_modules/z": { version: "1.0.0", license: "MIT" },
				"node_modules/a": { version: "1.0.0", license: "ISC" },
			}),
		);
		const one = await auditLicenses({ lockDir: work, offline: true });
		const two = await auditLicenses({ lockDir: work, offline: true });
		expect(one).toEqual(two);
		expect(one.entries.map((e) => e.paquete)).toEqual(["a", "z"]);
		expect(await readFile(join(work, "package-lock.json"), "utf8")).toContain(
			"lockfileVersion",
		);
	});
});

describe("LIC-004 mct licenses command", () => {
	async function setup(lock: string): Promise<string> {
		const raiz = join(root, "dest", ".mct");
		await createWorkspace(raiz, {
			mctVersion: "0.0.0",
			origen: { tipo: "carpeta", ref: origin },
			adapter: "node",
		});
		await put(join(raiz, "work", "package-lock.json"), lock);
		return raiz;
	}

	function io(): { io: Io; out: string[]; err: string[] } {
		const out: string[] = [];
		const err: string[] = [];
		return {
			out,
			err,
			io: {
				out: (t) => out.push(t),
				err: (t) => err.push(t),
				env: {},
				stdinIsTTY: false,
				stderrIsTTY: false,
			},
		};
	}

	const gplLock = () =>
		packageLock({ "node_modules/g": { version: "1.0.0", license: "GPL-3.0" } });

	it("LIC-004 --offline writes license-report.json and report.html and closes the gate with 10", async () => {
		const raiz = await setup(gplLock());
		const cap = io();
		const code = await runCli(
			["--workspace", raiz, "--json", "--lang", "en", "licenses", "--offline"],
			cap.io,
			[register],
		);
		expect(code).toBe(10);
		expect(JSON.parse(cap.out.join(""))).toEqual({
			paquetes: 1,
			bloquea: 1,
			revisar: 0,
			overrides: 0,
		});
		const report = JSON.parse(
			await readFile(join(raiz, "license-report.json"), "utf8"),
		);
		expect(report).toMatchObject([{ paquete: "g", veredicto: "bloquea" }]);
		const html = await readFile(join(raiz, "report.html"), "utf8");
		expect(html).toContain("GPL-3.0");
		const state = await readState(raiz);
		expect(state.etapas.licenses.estado).toBe("bloqueada");
		expect(state.workSha256).toMatch(/^[0-9a-f]{64}$/);
	});

	it("LIC-003 licenses.allow in mct.config.json lets the gate pass", async () => {
		const raiz = await setup(gplLock());
		await put(
			join(root, "dest", "mct.config.json"),
			json({
				licenses: { allow: [{ spdx: "GPL-3.0", motivo: "solo desarrollo" }] },
			}),
		);
		const cap = io();
		const code = await runCli(
			["--workspace", raiz, "--json", "licenses", "--offline"],
			cap.io,
			[register],
		);
		expect(code).toBe(0);
		expect(JSON.parse(cap.out.join(""))).toMatchObject({ overrides: 1 });
		expect((await readState(raiz)).etapas.licenses.estado).toBe("ok");
	});

	it("LIC-004 a Node project without lockfile exits with PUERTA_BLOQUEADA", async () => {
		const raiz = await setup(gplLock());
		await rm(join(raiz, "work", "package-lock.json"));
		const cap = io();
		const code = await runCli(
			["--workspace", raiz, "--json", "licenses", "--offline"],
			cap.io,
			[register],
		);
		expect(code).toBe(10);
		expect(JSON.parse(cap.out.join(""))).toMatchObject({
			error: { codigo: "PUERTA_BLOQUEADA" },
		});
	});
});

const GPL_REGISTRY = { "/gpl-lib/1.0.0": { license: "GPL-3.0" } };

describe("LIC-004 lockfile integrity (fail closed)", () => {
	const pnpmWithGpl = [
		"lockfileVersion: '9.0'",
		"importers:",
		"  .:",
		"    dependencies:",
		"      gpl-lib:",
		"        specifier: 1.0.0",
		"        version: 1.0.0",
		"packages:",
		"  gpl-lib@1.0.0:",
		"    resolution: {integrity: sha512-abc}",
		"",
	].join("\n");

	it("LIC-004 more than one lockfile is PUERTA_BLOQUEADA", async () => {
		await put(join(work, "package-lock.json"), packageLock({}));
		await put(join(work, "pnpm-lock.yaml"), pnpmWithGpl);
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
	});

	it("LIC-004 an explicit lockfile choice audits that one", async () => {
		await put(join(work, "package-lock.json"), packageLock({}));
		await put(join(work, "pnpm-lock.yaml"), pnpmWithGpl);
		const result = await auditLicenses({
			lockDir: work,
			offline: true,
			lockfile: "pnpm-lock.yaml",
		});
		expect(result.entries.map((e) => e.paquete)).toEqual(["gpl-lib"]);
	});

	it("LIC-004 a dependency declared but missing from package-lock is blocked", async () => {
		await put(
			join(work, "package.json"),
			json({ dependencies: toDeps(["gpl-lib"]) }),
		);
		await put(join(work, "package-lock.json"), packageLock({}, ["gpl-lib"]));
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
	});

	it("LIC-004 pnpm importers without a packages section are blocked", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: '9.0'",
				"importers:",
				"  .:",
				"    dependencies:",
				"      gpl-lib:",
				"        specifier: 1.0.0",
				"        version: 1.0.0",
				"",
			].join("\n"),
		);
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
	});

	it("LIC-004 an empty yarn.lock with declared dependencies is blocked", async () => {
		await put(join(work, "yarn.lock"), "");
		await put(
			join(work, "package.json"),
			json({ dependencies: toDeps(["gpl-lib"]) }),
		);
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
	});

	it("LIC-004 an empty tree is fine when nothing is declared", async () => {
		await put(join(work, "package-lock.json"), packageLock({}));
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.resumen.paquetes).toBe(0);
	});
});

describe("LIC-004 registry only for registry-resolved entries", () => {
	const yarnBlock = (head: string, body: string[]) =>
		["# yarn lockfile v1", "", `${head}:`, ...body, ""].join("\n");

	it("LIC-004 a yarn v1 alias is audited as its real package", async () => {
		await put(
			join(work, "yarn.lock"),
			yarnBlock('"mit-lib@npm:gpl-lib@1.0.0"', [
				'  version "1.0.0"',
				'  resolved "https://registry.yarnpkg.com/gpl-lib/-/gpl-lib-1.0.0.tgz#abc"',
			]),
		);
		const result = await auditLicenses({
			lockDir: work,
			fetch: registryOk(GPL_REGISTRY),
		});
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["gpl-lib", "bloquea"],
		]);
	});

	it("LIC-004 a package-lock entry resolved from git does not use the registry", async () => {
		const fetchFn = registryOk({ "/foo/1.0.0": { license: "MIT" } });
		await put(
			join(work, "package-lock.json"),
			packageLock(
				{
					"node_modules/foo": {
						version: "1.0.0",
						resolved: "git+ssh://git@example.com/gplfork.git#abc",
					},
				},
				["foo"],
			),
		);
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(result.entries[0]?.veredicto).toBe("revisar");
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-004 a yarn v1 git descriptor does not use the registry", async () => {
		const fetchFn = registryOk({ "/foo/1.0.0": { license: "MIT" } });
		await put(
			join(work, "yarn.lock"),
			yarnBlock('"foo@git+https://example.com/gplfork.git"', [
				'  version "1.0.0"',
				'  resolved "git+https://example.com/gplfork.git#abc"',
			]),
		);
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(result.entries[0]?.veredicto).toBe("revisar");
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-004 a registry-resolved package-lock entry still uses the registry", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock(
				{
					"node_modules/foo": {
						version: "1.0.0",
						resolved: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
					},
				},
				["foo"],
			),
		);
		const result = await auditLicenses({
			lockDir: work,
			fetch: registryOk({ "/foo/1.0.0": { license: "MIT" } }),
		});
		expect(result.entries[0]?.veredicto).toBe("ok");
	});
});

describe("LIC-004 peers and local links", () => {
	it("LIC-004 an optional peer absent from package-lock does not block", async () => {
		await put(
			join(work, "package.json"),
			json({
				peerDependencies: { react: "*" },
				peerDependenciesMeta: { react: { optional: true } },
			}),
		);
		await put(join(work, "package-lock.json"), packageLock({}));
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.resumen.paquetes).toBe(0);
	});

	it("LIC-004 a peer absent from yarn v1 does not block", async () => {
		await put(
			join(work, "package.json"),
			json({ peerDependencies: { react: "*" } }),
		);
		await put(join(work, "yarn.lock"), "# yarn lockfile v1\n");
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.resumen.paquetes).toBe(0);
	});

	it("LIC-004 a required peer absent from package-lock is still blocked", async () => {
		await put(
			join(work, "package.json"),
			json({ peerDependencies: { react: "*" } }),
		);
		await put(join(work, "package-lock.json"), packageLock({}));
		await expect(
			auditLicenses({ lockDir: work, offline: true }),
		).rejects.toMatchObject({ codigo: "PUERTA_BLOQUEADA" });
	});

	it("LIC-004 a package-lock file: link to a GPL folder is audited", async () => {
		await put(
			join(work, "package.json"),
			json({ dependencies: { gpl: "file:./vendor/gpl" } }),
		);
		await put(
			join(work, "package-lock.json"),
			packageLock(
				{
					"node_modules/gpl": { resolved: "vendor/gpl", link: true },
					"vendor/gpl": { name: "gpl", version: "2.0.0", license: "GPL-3.0" },
				},
				["gpl"],
			),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(
			result.entries.map((e) => [e.paquete, e.spdx, e.veredicto, e.origen]),
		).toEqual([["gpl", "GPL-3.0", "bloquea", "directa"]]);
	});

	it("LIC-004 a link without license or target entry is revisar", async () => {
		await put(
			join(work, "package-lock.json"),
			packageLock(
				{ "node_modules/gpl": { resolved: "vendor/gpl", link: true } },
				["gpl"],
			),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["gpl", "revisar"],
		]);
	});

	it("LIC-004 a real workspace link is not reported", async () => {
		await put(
			join(work, "package-lock.json"),
			json({
				lockfileVersion: 3,
				packages: {
					"": { name: "app", workspaces: ["packages/*"] },
					"node_modules/inner": { resolved: "packages/inner", link: true },
					"packages/inner": { name: "inner", version: "1.0.0" },
				},
			}),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.resumen.paquetes).toBe(0);
	});

	it("LIC-004 a pnpm link: to a folder that is not an importer is revisar", async () => {
		await put(
			join(work, "package.json"),
			json({ dependencies: { gpl: "link:./vendor/gpl" } }),
		);
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: '9.0'",
				"importers:",
				"  .:",
				"    dependencies:",
				"      gpl:",
				"        specifier: link:./vendor/gpl",
				"        version: link:vendor/gpl",
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["gpl", "revisar"],
		]);
	});

	it("LIC-004 a pnpm link to a known importer is a workspace", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: '9.0'",
				"importers:",
				"  .:",
				"    dependencies:",
				"      inner:",
				"        specifier: workspace:*",
				"        version: link:packages/inner",
				"  packages/inner: {}",
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.resumen.paquetes).toBe(0);
	});
});

describe("LIC-004 review fixes: origin, indentation and workspaces", () => {
	const pnpmLock = (resolution: string): string =>
		[
			"lockfileVersion: '9.0'",
			"importers:",
			"  .:",
			"    dependencies:",
			"      foo:",
			"        specifier: 1.0.0",
			"        version: 1.0.0",
			"packages:",
			"  foo@1.0.0:",
			`    resolution: ${resolution}`,
			"snapshots:",
			"  foo@1.0.0: {}",
			"",
		].join("\n");

	it.each([
		"{tarball: https://internal.example/foo-1.0.0.tgz}",
		"{integrity: sha512-abc, tarball: https://internal.example/foo.tgz}",
		"{commit: abc123, repo: https://git.example/foo.git, type: git}",
		"{directory: vendor/foo, type: directory}",
	])("LIC-004 pnpm resolution %s is not a registry package", async (res) => {
		await put(join(work, "pnpm-lock.yaml"), pnpmLock(res));
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["foo", "revisar"],
		]);
	});

	it("LIC-004 pnpm registry resolution still reaches the registry", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmLock("{integrity: sha512-abc}"),
		);
		const fetchFn = registryOk({ "/foo/1.0.0": { license: "MIT" } });
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["foo", "ok"],
		]);
	});

	it("LIC-004 yarn v1 nested dependency names do not override block fields", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"# yarn lockfile v1",
				"",
				"gpl-x@^1.0.0:",
				'  version "1.0.0"',
				'  resolved "https://registry.yarnpkg.com/gpl-x/-/gpl-x-1.0.0.tgz#abc"',
				"  dependencies:",
				'    version "2.0.0"',
				'    resolved "^1.0.0"',
				"",
			].join("\n"),
		);
		const fetchFn = registryOk({
			"/gpl-x/1.0.0": { license: "GPL-3.0-only" },
			"/gpl-x/2.0.0": { license: "MIT" },
		});
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(
			result.entries.map((e) => [e.paquete, e.version, e.veredicto]),
		).toEqual([["gpl-x", "1.0.0", "bloquea"]]);
	});

	it("LIC-004 yarn berry nested dependency names do not override block fields", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 6",
				"",
				'"gpl-x@npm:^1.0.0":',
				"  version: 1.0.0",
				'  resolution: "gpl-x@npm:1.0.0"',
				"  dependencies:",
				"    version: 2.0.0",
				'    resolution: "a@workspace:b"',
				"",
			].join("\n"),
		);
		const fetchFn = registryOk({ "/gpl-x/1.0.0": { license: "GPL-3.0-only" } });
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(
			result.entries.map((e) => [e.paquete, e.version, e.veredicto]),
		).toEqual([["gpl-x", "1.0.0", "bloquea"]]);
	});

	const wsLock = (
		workspaces: string[],
		target: string,
		license = "GPL-3.0-only",
	): string =>
		json({
			lockfileVersion: 3,
			packages: {
				"": { name: "app", workspaces },
				"node_modules/legal": { resolved: target, link: true },
				[target]: { name: "legal", version: "1.0.0", license },
			},
		});

	it("LIC-004 a negated workspace pattern keeps the link audited", async () => {
		await put(
			join(work, "package-lock.json"),
			wsLock(["packages/*", "!packages/legal"], "packages/legal"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["legal", "bloquea"],
		]);
	});

	it("LIC-004 a negated pattern with ./ prefix keeps the link audited", async () => {
		await put(
			join(work, "package-lock.json"),
			wsLock(["packages/*", "!./packages/legal"], "packages/legal"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["legal", "bloquea"],
		]);
	});

	it("LIC-004 thousands of workspace patterns finish fast and audit the link", async () => {
		const patterns = Array.from({ length: 20_000 }, (_, i) => `p${i}/*/**/z`);
		await put(
			join(work, "package-lock.json"),
			wsLock(patterns, "packages/legal"),
		);
		const started = Date.now();
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(Date.now() - started).toBeLessThan(3000);
		expect(result.entries.map((e) => e.veredicto)).toEqual(["bloquea"]);
	});

	it("LIC-004 a 1 MB pnpm resolution line finishes fast and is not a registry package", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				"lockfileVersion: '9.0'",
				"importers:",
				"  .:",
				"    dependencies:",
				"      foo:",
				"        specifier: 1.0.0",
				"        version: 1.0.0",
				"packages:",
				"  foo@1.0.0:",
				`    resolution: ${"a".repeat(1_000_000)}`,
				"snapshots:",
				"  foo@1.0.0: {}",
				"",
			].join("\n"),
		);
		const fetchFn = neverCalled();
		const started = Date.now();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(Date.now() - started).toBeLessThan(3000);
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries.map((e) => e.veredicto)).toEqual(["revisar"]);
	});

	it.each([
		[["*/*"], "../legal"],
		[["**"], "../legal"],
		[["*"], ".legal"],
		[["**"], "a/../../legal"],
	])("LIC-004 wildcards %j never cover %s", async (patterns, target) => {
		await put(join(work, "package-lock.json"), wsLock(patterns, target));
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => e.paquete)).toEqual(["legal"]);
	});

	it("LIC-004 many ** patterns finish fast", async () => {
		const target = Array.from({ length: 24 }, (_, i) => `d${i}`).join("/");
		const patterns = [`${Array(66).fill("**").join("/")}/zz`];
		await put(join(work, "package-lock.json"), wsLock(patterns, target));
		const started = Date.now();
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(Date.now() - started).toBeLessThan(3000);
		expect(result.entries.map((e) => e.paquete)).toEqual(["legal"]);
	});

	it("LIC-004 a local link is not merged with a registry package of the same version", async () => {
		await put(
			join(work, "package-lock.json"),
			json({
				lockfileVersion: 3,
				packages: {
					"": { name: "app", dependencies: { a: "*", foo: "*" } },
					"node_modules/a": { version: "1.0.0", license: "MIT" },
					"node_modules/a/node_modules/foo": {
						version: "1.0.0",
						license: "MIT",
					},
					"node_modules/foo": { resolved: "vendor/foo", link: true },
					"vendor/foo": {
						name: "foo",
						version: "1.0.0",
						license: "GPL-3.0-only",
					},
				},
			}),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => e.veredicto)).toContain("bloquea");
	});

	it("LIC-004 a license-less local link never queries the registry", async () => {
		await put(
			join(work, "package-lock.json"),
			json({
				lockfileVersion: 3,
				packages: {
					"": { name: "app", dependencies: { a: "*", foo: "*" } },
					"node_modules/a": { version: "1.0.0", license: "MIT" },
					"node_modules/a/node_modules/foo": {
						version: "1.0.0",
						license: "MIT",
					},
					"node_modules/foo": { resolved: "vendor/foo", link: true },
					"vendor/foo": { name: "foo", version: "1.0.0" },
				},
			}),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => e.veredicto)).toContain("revisar");
	});
});

describe("LIC-004 yaml lockfiles: strict parsing", () => {
	const pnpmWith = (packagesBody: string[], head: string[] = []): string =>
		[
			"lockfileVersion: '9.0'",
			...head,
			"importers:",
			"  .:",
			"    dependencies:",
			"      foo:",
			"        specifier: 1.0.0",
			"        version: 1.0.0",
			"packages:",
			...packagesBody,
			"snapshots:",
			"  foo@1.0.0: {}",
			"",
		].join("\n");

	const audit = () =>
		auditLicenses({ lockDir: work, fetch: neverCalled(), offline: true });

	const verdicts = async (): Promise<unknown> => {
		const fetchFn = registryOk({ "/foo/1.0.0": { license: "MIT" } });
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		return result.entries.map((e) => [e.paquete, e.veredicto]);
	};

	it("LIC-004 pnpm duplicate keys cannot override the resolution", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    resolution: {tarball: https://internal.example/foo.tgz}",
				"  foo@1.0.0:",
				"    resolution: {integrity: sha512-abc}",
			]),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 pnpm anchors and aliases are refused", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    resolution: &r {integrity: sha512-abc}",
				"  bar@1.0.0:",
				"    resolution: *r",
			]),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 pnpm merge keys are not expanded", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    <<: {resolution: {integrity: sha512-abc}}",
			]),
		);
		// The merge key stays a literal key, so the package has no resolution of
		// its own and is never treated as a registry package.
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries.map((e) => e.veredicto)).toEqual(["revisar"]);
	});

	it("LIC-004 a billion-laughs lockfile fails fast and closed", async () => {
		const levels = Array.from({ length: 9 }, (_, i) =>
			i === 0
				? 'l0: &l0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]'
				: `l${i}: &l${i} [${Array(9)
						.fill(`*l${i - 1}`)
						.join(",")}]`,
		);
		await put(
			join(work, "pnpm-lock.yaml"),
			["lockfileVersion: '9.0'", ...levels, ""].join("\n"),
		);
		const started = Date.now();
		await expect(audit()).rejects.toBeInstanceOf(MctError);
		expect(Date.now() - started).toBeLessThan(3000);
	});

	it("LIC-004 a multi-line flow resolution is read as a whole", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    resolution: {integrity: sha512-abc,",
				"      tarball: https://internal.example/foo.tgz}",
			]),
		);
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries.map((e) => e.veredicto)).toEqual(["revisar"]);
	});

	it("LIC-004 a block-style resolution with a foreign tarball is not registry", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    resolution:",
				"      integrity: sha512-abc # comment",
				"      tarball: https://internal.example/foo.tgz",
			]),
		);
		const fetchFn = neverCalled();
		await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-004 a resolution with an unknown key is not registry", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				"  foo@1.0.0:",
				"    resolution: {integrity: sha512-abc, url: https://internal.example/x}",
			]),
		);
		const fetchFn = neverCalled();
		await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-004 a package without resolution is not registry", async () => {
		await put(join(work, "pnpm-lock.yaml"), pnpmWith(["  foo@1.0.0: {}"]));
		const fetchFn = neverCalled();
		const result = await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.entries.map((e) => e.veredicto)).toEqual(["revisar"]);
	});

	it("LIC-004 escaped and quoted keys are decoded like YAML does", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith([
				'  "fo\\u006f@1.0.0":',
				"    resolution: {integrity: sha512-abc}",
			]),
		);
		expect(await verdicts()).toEqual([["foo", "ok"]]);
	});

	it("LIC-004 tab indentation is an error", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			pnpmWith(["  foo@1.0.0:", "\tresolution: {integrity: sha512-abc}"]),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 several yaml documents are an error", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			`${pnpmWith(["  foo@1.0.0:", "    resolution: {integrity: sha512-abc}"])}---\nlockfileVersion: '9.0'\n`,
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it.each([
		["a list root", "- a\n- b\n"],
		["a scalar root", "hello\n"],
		["a scalar packages section", "lockfileVersion: '9.0'\npackages: nope\n"],
		["a list importers section", "lockfileVersion: '9.0'\nimporters:\n  - x\n"],
		["broken syntax", "lockfileVersion: '9.0'\npackages: [\n"],
		["no lockfileVersion", "packages: {}\n"],
	])("LIC-004 pnpm %s fails closed", async (_name, body) => {
		await put(join(work, "pnpm-lock.yaml"), body);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 a lockfile over the size limit is refused before parsing", async () => {
		const filler = `# ${"x".repeat(1000)}\n`.repeat(17_000);
		await put(
			join(work, "pnpm-lock.yaml"),
			`lockfileVersion: '9.0'\n${filler}`,
		);
		await expect(audit()).rejects.toMatchObject({
			message: expect.stringContaining("demasiado grande"),
		});
	});

	it("LIC-004 an unreadable lockfile (a directory) fails closed", async () => {
		await mkdir(join(work, "pnpm-lock.yaml"), { recursive: true });
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 yarn berry duplicate blocks cannot override a resolution", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				'"foo@npm:^1.0.0":',
				"  version: 1.0.0",
				'  resolution: "foo@npm:1.0.0"',
				'"foo@npm:^1.0.0":',
				"  version: 1.0.0",
				'  resolution: "foo@workspace:."',
				"",
			].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 yarn berry aliases are refused", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				'"foo@npm:^1.0.0":',
				"  version: 1.0.0",
				'  resolution: &r "foo@npm:1.0.0"',
				'"bar@npm:^1.0.0":',
				"  version: 1.0.0",
				"  resolution: *r",
				"",
			].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 yarn berry multi-descriptor keys and a non-scalar version", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				'"foo@npm:^1.0.0, foo@npm:^1.1.0":',
				"  version: 1.2.0",
				'  resolution: "foo@npm:1.2.0"',
				"",
			].join("\n"),
		);
		const result = await auditLicenses({ lockDir: work, offline: true });
		expect(result.entries.map((e) => [e.paquete, e.version])).toEqual([
			["foo", "1.2.0"],
		]);
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				'"foo@npm:^1.0.0":',
				"  version:",
				"    - 1.0.0",
				'  resolution: "foo@npm:1.0.0"',
				"",
			].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 yarn berry patch resolutions never reach the registry", async () => {
		await put(
			join(work, "yarn.lock"),
			[
				"__metadata:",
				"  version: 8",
				'"foo@patch:foo@npm%3A1.0.0#./p.patch::version=1.0.0":',
				"  version: 1.0.0",
				'  resolution: "foo@patch:foo@npm%3A1.0.0#./p.patch::version=1.0.0"',
				"",
			].join("\n"),
		);
		const fetchFn = neverCalled();
		await auditLicenses({ lockDir: work, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});
});

describe("LIC-004 global budget (workspaces and big trees)", () => {
	const manyPackages = (count: number): string => {
		const packages: Record<string, unknown> = {};
		for (let i = 0; i < count; i++) {
			packages[`node_modules/p${i}`] = { version: "1.0.0" };
		}
		return packageLock(packages);
	};

	const okFetch = (): { fn: FetchLike; calls: () => number } => {
		let n = 0;
		const fn: FetchLike = async () => {
			n++;
			return new Response(json({ license: "MIT" }), { status: 200 });
		};
		return { fn, calls: () => n };
	};

	it("LIC-004 the registry budget is global: the rest stays in revisar", async () => {
		await put(join(work, "package-lock.json"), manyPackages(20));
		const { fn, calls } = okFetch();
		const result = await auditLicenses({
			lockDir: work,
			fetch: fn,
			maxRegistryQueries: 5,
		});
		expect(calls()).toBe(5);
		expect(result.entries.filter((e) => e.veredicto === "ok")).toHaveLength(5);
		expect(
			result.entries.filter((e) => e.veredicto === "revisar"),
		).toHaveLength(15);
		expect(result.sinPresupuesto).toBe(15);
	});

	it("LIC-004 the default budget caps a 700-package tree at 500 queries", async () => {
		await put(join(work, "package-lock.json"), manyPackages(700));
		const { fn, calls } = okFetch();
		const result = await auditLicenses({ lockDir: work, fetch: fn });
		expect(calls()).toBe(500);
		expect(result.resumen.revisar).toBe(200);
	});

	it("LIC-004 never more than 8 requests in parallel, even if asked for more", async () => {
		await put(join(work, "package-lock.json"), manyPackages(40));
		let active = 0;
		let peak = 0;
		const fn: FetchLike = async () => {
			active++;
			peak = Math.max(peak, active);
			await new Promise((r) => setTimeout(r, 5));
			active--;
			return new Response(json({ license: "MIT" }), { status: 200 });
		};
		await auditLicenses({ lockDir: work, fetch: fn, concurrency: 100 });
		expect(peak).toBeLessThanOrEqual(8);
		expect(peak).toBeGreaterThan(1);
	});

	it("LIC-004 requests carry no credentials and a timeout signal", async () => {
		await put(join(work, "package-lock.json"), manyPackages(1));
		const seen: RequestInit[] = [];
		const fn: FetchLike = async (_url, init) => {
			seen.push(init ?? {});
			return new Response(json({ license: "MIT" }), { status: 200 });
		};
		await auditLicenses({ lockDir: work, fetch: fn });
		expect(seen).toHaveLength(1);
		expect(seen[0]?.credentials).toBe("omit");
		expect(JSON.stringify(seen[0]?.headers ?? {}).toLowerCase()).not.toContain(
			"authorization",
		);
		expect(seen[0]?.signal).toBeInstanceOf(AbortSignal);
	});

	it("LIC-004 --offline never spends the registry budget", async () => {
		await put(join(work, "package-lock.json"), manyPackages(10));
		const fetchFn = neverCalled();
		const result = await auditLicenses({
			lockDir: work,
			fetch: fetchFn,
			offline: true,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.resumen.revisar).toBe(10);
	});

	it("LIC-004 an exhausted time budget stops new queries", async () => {
		await put(join(work, "package-lock.json"), manyPackages(10));
		const fetchFn = neverCalled();
		const result = await auditLicenses({
			lockDir: work,
			fetch: fetchFn,
			maxTotalMs: 0,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.resumen.revisar).toBe(10);
	});

	it("LIC-004 an exhausted origin-read budget leaves packages in revisar", async () => {
		await put(join(work, "package-lock.json"), manyPackages(3));
		for (let i = 0; i < 3; i++) {
			await put(
				join(origin, `node_modules/p${i}/package.json`),
				json({ name: `p${i}`, version: "1.0.0", license: "MIT" }),
			);
		}
		const full = await auditLicenses({
			lockDir: work,
			originDir: origin,
			offline: true,
		});
		expect(full.resumen.revisar).toBe(0);
		const capped = await auditLicenses({
			lockDir: work,
			originDir: origin,
			offline: true,
			maxOriginReads: 1,
		});
		expect(capped.entries.filter((e) => e.veredicto === "ok")).toHaveLength(1);
		expect(capped.resumen.revisar).toBe(2);
	});
});

describe("LIC-004 pnpm env lockfile (two documents)", () => {
	const envDoc = (extra: string[] = []): string[] => [
		"---",
		"lockfileVersion: '9.0'",
		"",
		"importers:",
		"  .:",
		"    configDependencies: {}",
		"    packageManagerDependencies:",
		"      pnpm:",
		"        specifier: 12.18.0",
		"        version: 12.18.0",
		"",
		"packages:",
		"",
		"  '@pnpm/exe.linux-x64@12.18.0':",
		"    resolution: {integrity: sha512-abc}",
		"    cpu: [x64]",
		"    os: [linux]",
		"",
		"  pnpm@12.18.0:",
		"    resolution: {integrity: sha512-def}",
		...extra,
	];

	const mainDoc = (body: string[] = []): string[] => [
		"---",
		"lockfileVersion: '9.0'",
		"",
		"importers:",
		"  .:",
		"    dependencies:",
		"      foo:",
		"        specifier: 1.0.0",
		"        version: 1.0.0",
		"",
		"packages:",
		"  foo@1.0.0:",
		"    resolution: {integrity: sha512-abc}",
		...body,
		"",
		"snapshots:",
		"  foo@1.0.0: {}",
		"",
	];

	const audit = () => auditLicenses({ lockDir: work, offline: true });

	beforeEach(async () => {
		await put(
			join(work, "package.json"),
			json({ name: "app", dependencies: { foo: "1.0.0" } }),
		);
	});

	it("LIC-004 a valid env lockfile is read and the manager stays out of the tree", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[...envDoc(), ...mainDoc()].join("\n"),
		);
		const result = await audit();
		expect(result.entries.map((e) => e.paquete)).toEqual(["foo"]);
	});

	it("LIC-004 an env lockfile first document with extra keys is refused", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[...envDoc(["", "overrides:", "  foo: 1.0.0"]), ...mainDoc()].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 an env lockfile with a non-manager package or extra importer is refused", async () => {
		const withPkg = envDoc([
			"",
			"  evil@1.0.0:",
			"    resolution: {integrity: sha512-x}",
		]);
		await put(
			join(work, "pnpm-lock.yaml"),
			[...withPkg, ...mainDoc()].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
		const withImporter = envDoc()
			.join("\n")
			.replace(
				"packages:",
				"  packages/x:\n    configDependencies: {}\n\npackages:",
			);
		await put(
			join(work, "pnpm-lock.yaml"),
			[withImporter, ...mainDoc()].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 three documents are refused", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[...envDoc(), ...mainDoc(), ...mainDoc()].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 two documents where the first is a normal lockfile are refused", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[...mainDoc(), ...mainDoc()].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 the second document keeps the known evasions covered", async () => {
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				...envDoc(),
				...mainDoc(["  foo@1.0.0:", "    resolution: {integrity: sha512-def}"]),
			].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
		await put(
			join(work, "pnpm-lock.yaml"),
			[
				...envDoc(),
				...mainDoc([
					"  bar@1.0.0:",
					"    resolution: &r {integrity: sha512-a}",
					"  baz@1.0.0:",
					"    resolution: *r",
				]),
			].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});

	it("LIC-004 aliases cannot cross from the first document into the second", async () => {
		const first = envDoc()
			.join("\n")
			.replace("configDependencies: {}", "configDependencies: &c {}");
		await put(
			join(work, "pnpm-lock.yaml"),
			[first, ...mainDoc(["  bar@1.0.0:", "    resolution: *c"])].join("\n"),
		);
		await expect(audit()).rejects.toBeInstanceOf(MctError);
	});
});
