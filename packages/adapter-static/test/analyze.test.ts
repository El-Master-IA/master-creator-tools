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

import { describe, expect, it } from "vitest";
import { staticAdapter } from "../src/index.js";

describe("WEB-001 analyze y detect", () => {
	it("DET-001 estatico da 0.4 con index.html en public/", async () => {
		const ws = await makeWs({ work: { "public/index.html": "<html></html>" } });
		expect(await staticAdapter.detect(ws.work)).toBe(0.4);
	});

	it("DET-001 estatico da 0.4 en la raiz y 0 sin index.html", async () => {
		const a = await makeWs({ work: { "index.html": "<html></html>" } });
		const b = await makeWs({ work: { "README.md": "x" } });
		expect(await staticAdapter.detect(a.work)).toBe(0.4);
		expect(await staticAdapter.detect(b.work)).toBe(0);
	});

	it("WEB-001 entrypoint, stack y lenguaje; prefiere la raiz sobre public/", async () => {
		const ws = await makeWs({
			work: {
				"index.html": "<html></html>",
				"public/index.html": "<html></html>",
			},
		});
		const a = await staticAdapter.analyze(ws);
		expect(a.entrypoints).toEqual(["index.html"]);
		expect(a.stack).toEqual(["estatico"]);
		expect(a.lenguaje).toBe("html");
	});

	it("WEB-001 solo nombres de .env* validos, nunca valores", async () => {
		const ws = await makeWs({
			work: {
				"index.html": "<html></html>",
				".env.example": "API_URL=abc123secretvalue\nlower=1\nA=2\n",
			},
			quarantine: { ".env": "export SITE_KEY=zzz\n" },
		});
		const a = await staticAdapter.analyze(ws);
		expect(a.envVars.map((v) => v.nombre).sort()).toEqual([
			"API_URL",
			"SITE_KEY",
		]);
		expect(JSON.stringify(a)).not.toContain("abc123secretvalue");
		expect(JSON.stringify(a)).not.toContain("zzz");
	});
});
