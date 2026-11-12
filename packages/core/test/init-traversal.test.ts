import {
	chmod,
	lstat,
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
import { initFromSource } from "../src/init.js";

let base: string;
let origen: string;
let fuera: string;
let dest: string;

const pkg = JSON.stringify({ name: "demo", version: "1.0.0", main: "i.js" });

async function put(root: string, rel: string, text: string): Promise<void> {
	const full = join(root, ...rel.split("/"));
	await mkdir(join(full, ".."), { recursive: true });
	await writeFile(full, text);
}

const exists = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

function opts(extra: Record<string, unknown> = {}) {
	return {
		origen,
		dest,
		isTTY: false,
		mctVersion: "0.0.0",
		home: join(base, "home"),
		env: {},
		...extra,
	};
}

async function expectCode(p: Promise<unknown>, codigo: string) {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	expect((err as MctError).codigo).toBe(codigo);
	return err as MctError;
}

/** Directory link that works without privileges on Windows (junction). */
const dirLink = (target: string, path: string) =>
	symlink(target, path, process.platform === "win32" ? "junction" : "dir");

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t17t-"));
	origen = join(base, "origen");
	fuera = join(base, "fuera");
	dest = join(base, "dest");
	await mkdir(dest, { recursive: true });
	await put(origen, "package.json", pkg);
	await put(origen, "src/a.js", "a\n");
	await put(fuera, "secreto.txt", "fuera\n");
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-003 symlinks y rutas fuera del árbol", () => {
	it("CLI-003 un enlace a directorio (symlink o junction) sale con VALIDACION", async () => {
		await dirLink(fuera, join(origen, "src", "enlace"));
		const err = await expectCode(initFromSource(opts()), "VALIDACION");
		expect(err.message).not.toContain(base);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-003 un enlace a archivo sale con VALIDACION", async (ctx) => {
		try {
			await symlink(join(fuera, "secreto.txt"), join(origen, "enlace.txt"));
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code === "EPERM") ctx.skip();
			throw e;
		}
		await expectCode(initFromSource(opts()), "VALIDACION");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-003 un enlace dentro de node_modules no cuenta: esa carpeta no se copia", async () => {
		await put(origen, "node_modules/x/i.js", "x\n");
		await dirLink(fuera, join(origen, "node_modules", "ln"));
		const r = await initFromSource(opts());
		expect(await exists(join(r.workspace.work, "node_modules"))).toBe(false);
	});

	it("CLI-003 un origen que es un enlace sale con VALIDACION", async () => {
		const ln = join(base, "ln");
		await dirLink(origen, ln);
		await expectCode(initFromSource(opts({ origen: ln })), "VALIDACION");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-003 un .json origen que es un enlace sale con VALIDACION", async (ctx) => {
		await put(fuera, "f.json", "{}");
		const ln = join(base, "f.json");
		try {
			await symlink(join(fuera, "f.json"), ln);
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code === "EPERM") ctx.skip();
			throw e;
		}
		await expectCode(initFromSource(opts({ origen: ln })), "VALIDACION");
	});

	it("CLI-003 un origen dentro de dest/.mct sale con VALIDACION", async () => {
		await initFromSource(opts());
		await expectCode(
			initFromSource(
				opts({
					origen: join(dest, ".mct", "work"),
					force: true,
					isTTY: true,
					confirmarForce: async () => true,
				}),
			),
			"VALIDACION",
		);
		expect(await exists(join(dest, ".mct", "work", "package.json"))).toBe(true);
	});

	it("CLI-003 un .mct enlace en dest sale con VALIDACION sin seguirlo", async () => {
		await mkdir(join(fuera, "ws"));
		await dirLink(join(fuera, "ws"), join(dest, ".mct"));
		await expectCode(initFromSource(opts()), "VALIDACION");
		expect(await exists(join(fuera, "ws", "state.json"))).toBe(false);
	});

	it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
		"CLI-003 un subárbol ilegible falla cerrado (no copia a medias)",
		async () => {
			await put(origen, "cerrado/x.txt", "x\n");
			await chmod(join(origen, "cerrado"), 0o000);
			try {
				await expectCode(initFromSource(opts()), "ORIGEN_NO_ENCONTRADO");
			} finally {
				await chmod(join(origen, "cerrado"), 0o700);
			}
			expect(await exists(join(dest, ".mct"))).toBe(false);
		},
	);
});

describe("CLI-003 globs exclude que salen del árbol", () => {
	const malos = [
		"../fuera",
		"{../fuera,src}",
		"src/{a,../../b}",
		"{/etc,src}",
		"{a,C:/x}",
		"!{../x,y}",
		"{{..,x}/y,z}",
	];
	for (const glob of malos) {
		it(`CLI-003 rechaza el glob ${glob}`, async () => {
			await writeFile(
				join(dest, "mct.config.json"),
				JSON.stringify({ exclude: [glob] }),
			);
			await expectCode(initFromSource(opts()), "VALIDACION");
			expect(await exists(join(dest, ".mct"))).toBe(false);
		});
	}

	it("CLI-003 un glob con llaves explosivo se rechaza", async () => {
		const g = Array.from({ length: 6 }, () => "{a,b,c,d,e}").join("");
		await writeFile(
			join(dest, "mct.config.json"),
			JSON.stringify({ exclude: [g] }),
		);
		await expectCode(initFromSource(opts()), "VALIDACION");
	});

	it("CLI-003 un mct.config.json inválido sale con VALIDACION", async () => {
		await writeFile(join(dest, "mct.config.json"), "{ no es json");
		await expectCode(initFromSource(opts()), "VALIDACION");
	});
});
