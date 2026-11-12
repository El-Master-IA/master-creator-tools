import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	checkDictionaryPerms,
	defaultDictionaryPath,
} from "../src/init-guards.js";

const statMode = (mode: number) => async () => ({ mode });
const P = "/home/ana/.mct/sensible.txt";

describe("SEC-001 permisos del diccionario (POSIX, plataforma inyectada)", () => {
	it("SEC-001 modo 0600 esta bien", async () => {
		const r = await checkDictionaryPerms({
			path: P,
			platform: "linux",
			stat: statMode(0o100600),
		});
		expect(r.estado).toBe("ok");
	});

	it.each([0o644, 0o640, 0o660, 0o666, 0o604])(
		"SEC-001 modo %o avisa con la accion",
		async (m) => {
			const r = await checkDictionaryPerms({
				path: P,
				platform: "darwin",
				stat: statMode(0o100000 | m),
			});
			expect(r.estado).toBe("aviso");
			expect(r.accion).toBe(`chmod 600 "${P}"`);
			expect(r.mensaje).toContain(P);
		},
	);

	it("SEC-001 archivo ausente no es aviso", async () => {
		const r = await checkDictionaryPerms({
			path: P,
			platform: "linux",
			stat: async () => {
				throw Object.assign(new Error("x"), { code: "ENOENT" });
			},
		});
		expect(r.estado).toBe("ausente");
	});

	it("SEC-001 si no puede determinar el estado avisa, no asume que esta bien", async () => {
		const r = await checkDictionaryPerms({
			path: P,
			platform: "linux",
			stat: async () => {
				throw Object.assign(new Error("x"), { code: "EACCES" });
			},
		});
		expect(r.estado).toBe("indeterminado");
		expect(r.accion).toBeTruthy();
	});

	it("SEC-001 el mensaje respeta --lang", async () => {
		const r = await checkDictionaryPerms({
			path: P,
			platform: "linux",
			stat: statMode(0o100644),
			lang: "en",
		});
		expect(r.mensaje).toMatch(/permissions/i);
	});

	it("SEC-001 la ruta por defecto vive en ~/.mct/sensible.txt", () => {
		expect(defaultDictionaryPath("/home/ana")).toBe(
			join("/home/ana", ".mct", "sensible.txt"),
		);
	});
});

describe("SEC-001 permisos del diccionario (Windows, icacls inyectado)", () => {
	const W = "C:\\Users\\Ana Gomez\\.mct\\sensible.txt";
	const base = {
		path: W,
		platform: "win32" as const,
		user: "Ana Gomez",
		exists: async () => true,
	};

	it("SEC-001 solo el usuario esta bien, sea cual sea el idioma del SO", async () => {
		const out = `${W} PC01\\Ana Gomez:(F)\n\nProcesado correctamente 1 archivos\n`;
		const r = await checkDictionaryPerms({ ...base, runIcacls: () => out });
		expect(r.estado).toBe("ok");
	});

	it("SEC-001 otras entradas (Usuarios, SYSTEM localizado) avisan con la accion", async () => {
		const out = `${W} PC01\\Ana Gomez:(F)\n      NT-AUTORITAT\\SYSTEM:(F)\n      VORDEFINIERT\\Benutzer:(R)\n\nok\n`;
		const r = await checkDictionaryPerms({ ...base, runIcacls: () => out });
		expect(r.estado).toBe("aviso");
		expect(r.accion).toBe(
			`icacls "${W}" /inheritance:r /grant:r "Ana Gomez:F"`,
		);
	});

	it("SEC-001 Everyone avisa", async () => {
		const out = `${W} Everyone:(F)\n       Ana Gomez:(F)\n`;
		const r = await checkDictionaryPerms({ ...base, runIcacls: () => out });
		expect(r.estado).toBe("aviso");
	});

	it("SEC-001 salida irreconocible o fallo de icacls es indeterminado", async () => {
		const a = await checkDictionaryPerms({ ...base, runIcacls: () => "???" });
		expect(a.estado).toBe("indeterminado");
		const b = await checkDictionaryPerms({
			...base,
			runIcacls: () => {
				throw new Error("no icacls");
			},
		});
		expect(b.estado).toBe("indeterminado");
	});

	it("SEC-001 ausente en Windows no es aviso", async () => {
		const r = await checkDictionaryPerms({
			...base,
			exists: async () => false,
			runIcacls: () => {
				throw new Error("no debe correr");
			},
		});
		expect(r.estado).toBe("ausente");
	});
});

describe("SEC-001 permisos reales del SO que corre", () => {
	let dir: string;
	let file: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "mct-t41p-"));
		file = join(dir, "sensible.txt");
		await writeFile(file, "# vacio\n");
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("SEC-001 detecta abierto y luego restringido", async () => {
		if (process.platform === "win32") {
			const { SystemRoot: sysroot } = process.env;
			if (!sysroot) throw new Error("SystemRoot no definido");
			const icacls = join(sysroot, "System32", "icacls.exe");
			const user = userInfo().username;
			execFileSync(icacls, [file, "/grant", "*S-1-1-0:(R)"], {
				stdio: "ignore",
			});
			expect((await checkDictionaryPerms({ path: file })).estado).toBe("aviso");
			execFileSync(
				icacls,
				[
					file,
					"/inheritance:r",
					"/remove:g",
					"*S-1-1-0",
					"/grant:r",
					`${user}:F`,
				],
				{
					stdio: "ignore",
				},
			);
			expect((await checkDictionaryPerms({ path: file })).estado).toBe("ok");
		} else {
			await chmod(file, 0o644);
			expect((await checkDictionaryPerms({ path: file })).estado).toBe("aviso");
			await chmod(file, 0o600);
			expect((await checkDictionaryPerms({ path: file })).estado).toBe("ok");
		}
	});
});
