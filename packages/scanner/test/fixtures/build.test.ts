import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
	buildFixture,
	FIXTURE_NAMES,
	type Fixture,
	type Truth,
} from "./build.js";
import { AWS_ALPHABET, makeSecrets } from "./secretos.js";

const here = dirname(fileURLToPath(import.meta.url));
const built: Fixture[] = [];

afterEach(async () => {
	await Promise.all(built.splice(0).map((f) => f.cleanup()));
});

async function make(name: string): Promise<Fixture> {
	const f = await buildFixture(name);
	built.push(f);
	return f;
}

async function sourceFiles(dir: string): Promise<string[]> {
	const out: string[] = [];
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		if (entry.name === "node_modules" || entry.name === ".git") continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...(await sourceFiles(full)));
		else if (/\.(ts|json|md)$/.test(entry.name)) out.push(full);
	}
	return out;
}

describe.each(FIXTURE_NAMES)("fixture %s", (name) => {
	it("T05 escribe truth.json con cada secreto y dato personal sembrado", async () => {
		const f = await make(name);
		const truth = JSON.parse(
			await readFile(join(f.root, "truth.json"), "utf8"),
		) as Truth;
		expect(truth.fixture).toBe(name);
		expect(truth.secrets.length).toBeGreaterThanOrEqual(5);
		expect(truth.pii.length).toBeGreaterThanOrEqual(5);
		const mutations = truth.secrets.map((s) => s.mutation);
		for (const m of ["base64", "split-lines", "comment", "env-backup"]) {
			expect(mutations).toContain(m);
		}
		for (const s of truth.secrets) {
			const area = s.mutation === "env-backup" ? f.quarantine : f.work;
			const text = await readFile(join(area, s.file), "utf8");
			if (s.mutation === "split-lines") {
				expect(text).not.toContain(s.value);
			} else {
				expect(text).toContain(s.value);
			}
		}
		for (const p of truth.pii) {
			const text = await readFile(join(f.work, p.file), "utf8");
			expect(text).toContain(p.value);
		}
	});

	it("T05 ningún valor de truth.json aparece literal en los fuentes del repo", async () => {
		const f = await make(name);
		const values = [
			...f.truth.secrets.map((s) => s.value),
			...f.truth.pii.map((p) => p.value),
		];
		const repoRoot = join(here, "..", "..", "..", "..");
		const files = [
			...(await sourceFiles(join(repoRoot, "packages"))),
			...(await sourceFiles(join(repoRoot, "test"))),
		];
		expect(files.length).toBeGreaterThan(0);
		for (const file of files) {
			const text = await readFile(file, "utf8");
			for (const v of values) {
				expect(text.includes(v), `${file} contiene un valor sembrado`).toBe(
					false,
				);
			}
		}
	});
});

describe("buildFixture", () => {
	it("T05 un fixture inexistente lanza un error con su nombre", async () => {
		await expect(buildFixture("no-existe")).rejects.toThrow(/no-existe/);
	});
});

describe("makeSecrets", () => {
	const shannon = (text: string): number => {
		const counts = new Map<string, number>();
		for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
		let h = 0;
		for (const n of counts.values()) {
			const p = n / text.length;
			h -= p * Math.log2(p);
		}
		return h;
	};

	it("T05 el relleno genérico tiene entropía de Shannon mayor que 3.5", () => {
		const prefixes: Record<string, number> = {
			"github-token": 4,
			"stripe-key": 8,
			"generic-api-key": 7,
		};
		for (const s of makeSecrets()) {
			const skip = prefixes[s.kind];
			if (skip === undefined) continue;
			expect(shannon(s.value.slice(skip)), s.kind).toBeGreaterThan(3.5);
		}
	});

	it("T05 la clave AWS usa el alfabeto A-Z2-7", () => {
		const aws = makeSecrets().find((s) => s.kind === "aws-key");
		expect(aws?.value).toMatch(/^AKIA[A-Z2-7]{16}$/);
		for (const ch of (aws?.value ?? "").slice(4)) {
			expect(AWS_ALPHABET).toContain(ch);
		}
	});

	it("T05 es determinista", () => {
		expect(makeSecrets()).toEqual(makeSecrets());
	});
});
