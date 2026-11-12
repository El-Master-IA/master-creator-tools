import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Workspace } from "@mct/contract/types";
import { afterEach } from "vitest";

const roots: string[] = [];

async function makeWs(
	zones: Partial<
		Record<"work" | "quarantine" | "dist", Record<string, string>>
	>,
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-static-"));
	roots.push(raiz);
	for (const zone of ["work", "quarantine", "dist"] as const) {
		await mkdir(join(raiz, zone), { recursive: true });
		for (const [rel, content] of Object.entries(zones[zone] ?? {})) {
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

import { MctError } from "@mct/contract/errors";
import { PYTHON_IMAGE_REFS } from "@mct/contract/pins";
import { describe, expect, it } from "vitest";
import { staticAdapter } from "../src/index.js";

describe("WEB-002 VerifySpec", () => {
	it("WEB-002 puerto 8080, cuerpoContiene <html, imagen 3.14 por digest", async () => {
		const ws = await makeWs({
			dist: {
				"site/index.html":
					'<html><link href="css/a.css"><script src="/js/b.js?v=1#x"></script></html>',
			},
			work: { "site/index.html": "<html></html>" },
		});
		const a = await staticAdapter.analyze(ws);
		const spec = staticAdapter.verifyCommand(a);
		expect(spec.imagen).toBe(PYTHON_IMAGE_REFS["3.14-slim"]);
		expect(spec.start).toEqual([
			"python",
			"-m",
			"http.server",
			"8080",
			"--bind",
			"127.0.0.1",
			"--directory",
			"site",
		]);
		expect(spec.healthcheck).toMatchObject({
			tipo: "http",
			puerto: 8080,
			cuerpoContiene: "<html",
		});
		expect(spec.healthcheck).toMatchObject({
			rutasExtra: ["/css/a.css", "/js/b.js"],
		});
	});

	it("WEB-002 ignora externos, anclas, data:, mailto: y // ; sin repetir", async () => {
		const html = `<html><a href="https://x.dev/a">a</a><a href="#top">t</a><img src="data:image/png;base64,AAA">
<a href='mailto:a@b.co'>m</a><script src="//cdn.dev/x.js"></script><a href="./p.html">p</a><a href="p.html">q</a><a href=u.css>u</a>
<a href="../fuera.css">f</a></html>`;
		const ws = await makeWs({ work: { "index.html": html } });
		const spec = staticAdapter.verifyCommand(await staticAdapter.analyze(ws));
		expect(spec.healthcheck).toMatchObject({
			rutasExtra: ["/p.html", "/u.css"],
		});
	});

	it("WEB-002 maximo 50 rutasExtra en orden de aparicion", async () => {
		const links = Array.from(
			{ length: 80 },
			(_, i) => `<a href="r${i}.html">x</a>`,
		).join("");
		const ws = await makeWs({
			work: { "index.html": `<html>${links}</html>` },
		});
		const spec = staticAdapter.verifyCommand(await staticAdapter.analyze(ws));
		const extra = (spec.healthcheck as { rutasExtra: string[] }).rutasExtra;
		expect(extra).toHaveLength(50);
		expect(extra[0]).toBe("/r0.html");
		expect(extra[49]).toBe("/r49.html");
	});

	it("WEB-002 sin index.html falla cerrado con PUERTA_BLOQUEADA", () => {
		const analysis = {
			stack: ["estatico"],
			entrypoints: [],
			envVars: [],
			deps: [],
			comandos: {},
		};
		expect(() => staticAdapter.verifyCommand(analysis)).toThrow(MctError);
	});
});
