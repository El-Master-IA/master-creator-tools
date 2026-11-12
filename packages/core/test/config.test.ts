import {
	chmod,
	mkdir,
	mkdtemp,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

let dest: string;

beforeEach(async () => {
	dest = await mkdtemp(join(tmpdir(), "mct-t43c-"));
});
afterEach(async () => {
	await rm(dest, { recursive: true, force: true });
});

async function escribe(cfg: unknown): Promise<void> {
	await writeFile(
		join(dest, "mct.config.json"),
		typeof cfg === "string" ? cfg : JSON.stringify(cfg),
	);
}

async function rechazo(p: Promise<unknown>): Promise<MctError> {
	try {
		await p;
	} catch (e) {
		if (e instanceof MctError) return e;
		throw e;
	}
	throw new Error("se esperaba un rechazo");
}

describe("CFG-001 mct.config.json", () => {
	it("CFG-001 sin archivo devuelve la configuración vacía", async () => {
		expect(await loadConfig(dest)).toEqual({});
	});

	it("CFG-001 carga una configuración completa y válida", async () => {
		const completa = {
			holder: "Alexander Cast",
			year: 2026,
			exclude: ["docs/**", "*.log"],
			licenses: { allow: [{ spdx: "GPL-3.0-only", motivo: "uso interno" }] },
			verify: { remoto: "servidor-casa", timeoutMin: 15 },
		};
		await escribe(completa);
		expect(await loadConfig(dest)).toEqual(completa);
	});

	it("CFG-001 acepta un objeto vacío y un BOM inicial", async () => {
		await escribe("﻿{}");
		expect(await loadConfig(dest)).toEqual({});
	});

	it("CFG-001 JSON ilegible sale con VALIDACION, nunca como vacío", async () => {
		for (const txt of ["{no json", "", "[]", "null", '"x"', "3"]) {
			await escribe(txt);
			const e = await rechazo(loadConfig(dest));
			expect(e.codigo).toBe("VALIDACION");
			expect(e.exit).toBe(2);
		}
	});

	it("CFG-001 un archivo ilegible (directorio o enlace) sale con VALIDACION", async () => {
		await mkdir(join(dest, "mct.config.json"));
		expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
		await rm(join(dest, "mct.config.json"), { recursive: true });
		await writeFile(join(dest, "real.json"), "{}");
		try {
			await symlink(join(dest, "real.json"), join(dest, "mct.config.json"));
		} catch {
			return;
		}
		expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
	});

	it("CFG-001 sin permiso de lectura sale con VALIDACION en POSIX", async () => {
		if (process.platform === "win32" || process.getuid?.() === 0) return;
		await escribe({});
		await chmod(join(dest, "mct.config.json"), 0o000);
		expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
	});

	it("CFG-001 rechaza claves desconocidas en cualquier nivel", async () => {
		const proto = "{" + '"__proto__": {"x": 1}' + "}";
		for (const cfg of [
			{ holder: "A", otra: 1 },
			{ licenses: { allow: [], otra: 1 } },
			{ licenses: { allow: [{ spdx: "MIT", motivo: "motivo ok", x: 1 }] } },
			{ verify: { remoto: "a", extra: true } },
			proto,
		]) {
			await escribe(cfg);
			expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
		}
	});

	it("CFG-001 rechaza tipos inválidos", async () => {
		for (const cfg of [
			{ holder: 3 },
			{ holder: "   " },
			{ holder: "a\nb" },
			{ year: "2026" },
			{ year: 2026.5 },
			{ year: 1 },
			{ exclude: "docs" },
			{ exclude: [1] },
			{ exclude: [""] },
			{ exclude: ["/abs/**"] },
			{ exclude: ["../fuera/**"] },
			{ licenses: [] },
			{ licenses: { allow: {} } },
			{ verify: [] },
			{ verify: { remoto: 3 } },
			{ verify: { remoto: "-oProxyCommand=x" } },
			{ verify: { remoto: "a b" } },
			{ verify: { timeoutMin: 0 } },
			{ verify: { timeoutMin: 1.5 } },
			{ verify: { timeoutMin: "10" } },
		]) {
			await escribe(cfg);
			expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
		}
	});

	it("LIC-003 licenses.allow exige motivo de 5 caracteres visibles", async () => {
		for (const motivo of [undefined, "", "abc", "    x    ", "a​b​c​d", 5]) {
			await escribe({ licenses: { allow: [{ spdx: "MIT", motivo }] } });
			const e = await rechazo(loadConfig(dest));
			expect(e.codigo).toBe("VALIDACION");
		}
		await escribe({
			licenses: { allow: [{ spdx: "MIT", motivo: "  válido  " }] },
		});
		const cfg = await loadConfig(dest);
		expect(cfg.licenses?.allow).toEqual([{ spdx: "MIT", motivo: "válido" }]);
	});

	it("LIC-003 licenses.allow acepta paquetes para limitar el override", async () => {
		await escribe({
			licenses: {
				allow: [
					{
						spdx: "MPL-2.0",
						motivo: "solo desarrollo",
						paquetes: ["lightningcss"],
					},
				],
			},
		});
		const cfg = await loadConfig(dest);
		expect(cfg.licenses?.allow).toEqual([
			{
				spdx: "MPL-2.0",
				motivo: "solo desarrollo",
				paquetes: ["lightningcss"],
			},
		]);
		await escribe({
			licenses: {
				allow: [{ spdx: "MPL-2.0", motivo: "solo desarrollo", paquetes: [] }],
			},
		});
		expect((await rechazo(loadConfig(dest))).codigo).toBe("VALIDACION");
	});

	it("CFG-001 el error no repite los valores del archivo", async () => {
		const secreto = `${"ghp"}_${"Zz9".repeat(12)}`;
		await escribe({ holder: 3, [secreto]: 1 });
		const e = await rechazo(loadConfig(dest));
		expect(JSON.stringify(e.toJSON())).not.toContain(secreto);
	});
});
