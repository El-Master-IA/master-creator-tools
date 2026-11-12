import { lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initFromSource } from "../src/init.js";

let base: string;
const has = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c08d-"));
	await mkdir(join(base, "origen", "sub"), { recursive: true });
	await mkdir(join(base, "dest"), { recursive: true });
	const o = join(base, "origen");
	await writeFile(
		join(o, "package.json"),
		JSON.stringify({ name: "d", main: "i.js" }),
	);
	await writeFile(join(o, "i.js"), "export {};\n");
	await writeFile(join(o, "decisiones.json"), "{}\n");
	await writeFile(join(o, "sub", "decisiones.json"), "{}\n");
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-001 exclusion de decisiones.json", () => {
	it("CLI-001 no copia decisiones.json de la raiz a work/ pero si el de una subcarpeta", async () => {
		await initFromSource({
			origen: join(base, "origen"),
			dest: join(base, "dest"),
			isTTY: false,
			mctVersion: "0.0.0",
			home: join(base, "home"),
			env: {},
		});
		const work = join(base, "dest", ".mct", "work");
		expect(await has(join(work, "decisiones.json"))).toBe(false);
		expect(await has(join(work, "sub", "decisiones.json"))).toBe(true);
		expect(await has(join(work, "i.js"))).toBe(true);
	});
});
