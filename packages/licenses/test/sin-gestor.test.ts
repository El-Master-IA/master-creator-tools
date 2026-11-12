import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { auditSinGestor } from "../src/sin-gestor.js";
import { gateExit } from "../src/verdict.js";

let dir: string;
let mct: string;
beforeEach(async () => {
	mct = await mkdtemp(join(tmpdir(), "mct-sg-"));
	dir = join(mct, "work");
	await mkdir(dir);
});
afterEach(async () => {
	await rm(mct, { recursive: true, force: true });
});

const write = (name: string, text: string) => writeFile(join(dir, name), text);
const MOTIVO = { motivo: "motivo de al menos diez" };

describe("LIC-006 sin gestor", () => {
	it("LIC-006 estatico without manifest leaves 0 packages with aviso sin-gestor", async () => {
		await write("index.html", "<html></html>");
		const r = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			mctDir: mct,
			offline: true,
		});
		expect(r.entries).toEqual([]);
		expect(r.resumen.paquetes).toBe(0);
		expect(r.avisos).toEqual(["sin-gestor"]);
		expect(gateExit(r.entries)).toBe(0);
		const file = JSON.parse(
			await readFile(join(mct, "license-avisos.json"), "utf8"),
		);
		expect(file).toEqual({ schemaVersion: 1, avisos: ["sin-gestor"] });
	});

	it("LIC-006 writes an empty avisos list when a manifest exists", async () => {
		await write("requirements.txt", "a==1.0\n");
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			mctDir: mct,
			offline: true,
			sinLock: MOTIVO,
		});
		expect(r.avisos).toEqual([]);
		const file = JSON.parse(
			await readFile(join(mct, "license-avisos.json"), "utf8"),
		);
		expect(file.avisos).toEqual([]);
	});

	it("LIC-006 estatico with package.json + lockfile audits with LIC-004", async () => {
		await write(
			"package.json",
			JSON.stringify({ name: "x", dependencies: { left: "1.0.0" } }),
		);
		await write(
			"package-lock.json",
			JSON.stringify({
				name: "x",
				lockfileVersion: 3,
				packages: {
					"": { name: "x", dependencies: { left: "1.0.0" } },
					"node_modules/left": { version: "1.0.0", license: "MIT" },
				},
			}),
		);
		const r = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			offline: true,
		});
		expect(r.entries).toHaveLength(1);
		expect(r.entries[0]).toMatchObject({
			paquete: "left",
			spdx: "MIT",
			veredicto: "ok",
		});
		expect(r.avisos).toEqual([]);
	});

	it("LIC-006 package.json without lockfile is revisar, acceptable with sinLock", async () => {
		await write("package.json", JSON.stringify({ name: "x" }));
		const closed = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			offline: true,
		});
		expect(closed.entries).toHaveLength(1);
		expect(closed.entries[0]).toMatchObject({
			paquete: "(package.json sin lockfile)",
			version: "",
			spdx: null,
			veredicto: "revisar",
		});
		expect(gateExit(closed.entries)).toBe(10);
		const open = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			offline: true,
			sinLock: MOTIVO,
		});
		expect(gateExit(open.entries)).toBe(0);
		expect(open.entries[0]?.override).toEqual({ motivo: MOTIVO.motivo });
	});

	it("LIC-006 generico with requirements.txt is audited with LIC-005", async () => {
		await write("requirements.txt", "rich==13.0.0\n");
		const fetchFn = vi.fn(
			async (_url: string, _init?: RequestInit) =>
				new Response(JSON.stringify({ info: { license: "MIT" } })),
		);
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			fetch: fetchFn,
			sinLock: MOTIVO,
		});
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(r.entries.find((e) => e.paquete === "rich")?.veredicto).toBe("ok");
		expect(gateExit(r.entries)).toBe(0);
		expect(r.avisos).toEqual([]);
	});

	it("LIC-006 generico with composer.json is revisar without and ok with gestorNoSoportado", async () => {
		await write("composer.json", "{}");
		await mkdir(join(dir, "app"));
		await writeFile(join(dir, "app", "Demo.csproj"), "<Project/>");
		const closed = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			offline: true,
		});
		expect(closed.entries.map((e) => e.paquete)).toEqual([
			"(gestor no soportado: app/Demo.csproj)",
			"(gestor no soportado: composer.json)",
		]);
		expect(closed.entries.every((e) => e.veredicto === "revisar")).toBe(true);
		expect(closed.avisos).toEqual([]);
		expect(gateExit(closed.entries)).toBe(10);
		const open = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			offline: true,
			gestorNoSoportado: MOTIVO,
		});
		expect(gateExit(open.entries)).toBe(0);
		expect(open.resumen.overrides).toBe(2);
		const wrong = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			offline: true,
			sinLock: MOTIVO,
		});
		expect(gateExit(wrong.entries)).toBe(10);
	});

	it("LIC-006 skips node_modules and refuses other adapters", async () => {
		await mkdir(join(dir, "node_modules", "x"), { recursive: true });
		await writeFile(join(dir, "node_modules", "x", "go.mod"), "module x");
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			offline: true,
		});
		expect(r.avisos).toEqual(["sin-gestor"]);
		await expect(
			auditSinGestor({ adapter: "node", workDir: dir, offline: true }),
		).rejects.toThrow();
	});
});

describe("LIC-005 LIC-006 ecosystem-aware merge", () => {
	it("LIC-006 the same name and version in npm and pypi stay separate and keep their own verdicts", async () => {
		await write(
			"package.json",
			JSON.stringify({ name: "x", dependencies: { left: "1.0.0" } }),
		);
		await write(
			"package-lock.json",
			JSON.stringify({
				name: "x",
				lockfileVersion: 3,
				packages: {
					"": { name: "x", dependencies: { left: "1.0.0" } },
					"node_modules/left": { version: "1.0.0", license: "MIT" },
				},
			}),
		);
		await write("requirements.txt", "Left==1.0.0\n");
		const fetchFn = vi.fn(
			async (_url: string, _init?: RequestInit) =>
				new Response(
					JSON.stringify({ info: { license_expression: "GPL-3.0-only" } }),
				),
		);
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			fetch: fetchFn,
			sinLock: MOTIVO,
		});
		const lefts = r.entries.filter((e) => e.paquete.toLowerCase() === "left");
		expect(lefts.map((e) => e.veredicto).sort()).toEqual(["bloquea", "ok"]);
		expect(gateExit(r.entries)).toBe(10);
	});
});

describe("LIC-006 manifests in subfolders", () => {
	it("LIC-006 package.json in a subfolder is revisar instead of sin-gestor", async () => {
		await mkdir(join(dir, "web"));
		await writeFile(join(dir, "web", "package.json"), "{}");
		const r = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			mctDir: mct,
			offline: true,
		});
		expect(r.avisos).toEqual([]);
		expect(r.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["(manifiesto en subcarpeta: web/package.json)", "revisar"],
		]);
		expect(gateExit(r.entries)).not.toBe(0);
	});

	it("LIC-006 lockfiles and python manifests up to depth 3 are found, deeper are not", async () => {
		await mkdir(join(dir, "a", "b", "c", "d"), { recursive: true });
		await writeFile(join(dir, "a", "b", "c", "yarn.lock"), "");
		await writeFile(join(dir, "a", "b", "requirements-dev.txt"), "");
		await writeFile(join(dir, "a", "b", "c", "d", "pyproject.toml"), "");
		await mkdir(join(dir, "node_modules", "x"), { recursive: true });
		await writeFile(join(dir, "node_modules", "x", "package.json"), "{}");
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			offline: true,
		});
		expect(r.entries.map((e) => e.paquete)).toEqual([
			"(manifiesto en subcarpeta: a/b/c/yarn.lock)",
			"(manifiesto en subcarpeta: a/b/requirements-dev.txt)",
		]);
	});

	it("LIC-006 the subfolder entry is accepted with sinLock", async () => {
		await mkdir(join(dir, "web"));
		await writeFile(join(dir, "web", "package.json"), "{}");
		const r = await auditSinGestor({
			adapter: "estatico",
			workDir: dir,
			offline: true,
			sinLock: MOTIVO,
		});
		expect(gateExit(r.entries)).toBe(0);
	});

	it("LIC-006 an index found outside requirements surfaces as aviso", async () => {
		await write("requirements.txt", "a==1.0\n");
		await write("pip.conf", "[global]\n");
		const r = await auditSinGestor({
			adapter: "generico",
			workDir: dir,
			sinLock: MOTIVO,
			fetch: vi.fn(async () => new Response("{}", { status: 404 })),
		});
		expect(r.avisos).toEqual(["indice-privado-fuera"]);
	});
});
