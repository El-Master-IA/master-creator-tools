import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";
import { detectSecrets } from "../src/secrets.js";
import { buildFixture, type Fixture } from "./fixtures/build.js";
import { makeSecrets } from "./fixtures/secretos.js";

const built: Fixture[] = [];
afterEach(async () => {
	await Promise.all(built.splice(0).map((f) => f.cleanup()));
});

async function fixture(name: string): Promise<Fixture> {
	const f = await buildFixture(name);
	built.push(f);
	return f;
}

describe("secrets", () => {
	it("SCAN-001 devuelve regla y posición de una clave de proveedor", () => {
		const [aws, gh] = makeSecrets();
		const text = `// cabecera\nconst a = "${aws?.value}";\n  token = ${gh?.value}\n`;
		const found = detectSecrets(text);
		const awsHit = found.find((m) => m.value === aws?.value);
		expect(awsHit).toMatchObject({
			rule: "aws-access-key",
			line: 2,
			column: 12,
		});
		const ghHit = found.find((m) => m.value === gh?.value);
		expect(ghHit).toMatchObject({ rule: "github-token", line: 3, column: 11 });
	});

	it("SCAN-001 detecta cada secreto sembrado en texto plano y comentario", async () => {
		for (const name of ["node", "n8n"]) {
			const f = await fixture(name);
			const file = f.truth.secrets.find((s) => s.mutation === "plain")?.file;
			const text = await readFile(join(f.work, file ?? ""), "utf8");
			for (const s of f.truth.secrets.filter(
				(x) => x.mutation === "plain" || x.mutation === "comment",
			)) {
				expect(detectSecrets(text).map((m) => m.value)).toContain(s.value);
			}
		}
	});

	it("SCAN-002 detecta un secreto en base64", async () => {
		const f = await fixture("node");
		const truth = f.truth.secrets.find((s) => s.mutation === "base64");
		const text = await readFile(join(f.work, truth?.file ?? ""), "utf8");
		const hit = detectSecrets(text).find((m) => m.value === truth?.value);
		expect(hit?.rule).toBe("github-token");
		expect(hit?.line).toBe(3);
	});

	it("SCAN-002 detecta un secreto partido en dos líneas (código y JSON de n8n)", async () => {
		for (const name of ["node", "n8n"]) {
			const f = await fixture(name);
			const truth = f.truth.secrets.find((s) => s.mutation === "split-lines");
			const text = await readFile(join(f.work, truth?.file ?? ""), "utf8");
			const hits = detectSecrets(text).filter((m) => m.value === truth?.value);
			expect(hits).toHaveLength(1);
			expect(hits[0]?.rule).toBe("stripe-key");
		}
	});

	it("SCAN-002 detecta el secreto de un .env de cuarentena", async () => {
		const f = await fixture("node");
		const truth = f.truth.secrets.find((s) => s.mutation === "env-backup");
		const text = await readFile(join(f.quarantine, truth?.file ?? ""), "utf8");
		expect(detectSecrets(text).map((m) => m.value)).toContain(truth?.value);
	});

	it("SCAN-003 devuelve cero coincidencias con código normal", () => {
		const uuid = "550e8400-e29b-41d4-a716-446655440000";
		const sha1 = createHash("sha1").update("x").digest("hex");
		const text = [
			'import { readFile } from "node:fs/promises";',
			"export function computeTotalAmountForCustomerInvoice(items) {",
			"  return items.reduce((acc, item) => acc + item.price * item.qty, 0);",
			"}",
			`const id = "${uuid}"; // commit ${sha1}`,
			'const path = "packages/scanner/src/some/very/long/path/name/file.ts";',
			"const url = new URL('https://example.com/docs/getting-started');",
		].join("\n");
		expect(detectSecrets(text)).toEqual([]);
	});

	it("SCAN-004 lanza MctError si el texto supera el tamaño máximo", () => {
		const big = "a".repeat(2048);
		expect(() => detectSecrets(big, { maxBytes: 1024 })).toThrow(MctError);
		try {
			detectSecrets(big, { maxBytes: 1024 });
		} catch (e) {
			expect((e as MctError).codigo).toBe("VALIDACION");
		}
	});

	it("SCAN-005 no reporta por entropía un integrity sha512 ni un digest sha256", () => {
		const integrity = `sha512-${createHash("sha512").update(randomBytes(8)).digest("base64")}`;
		const digest = `sha256:${createHash("sha256").update(randomBytes(8)).digest("hex")}`;
		const text = [
			`"resolved": "https://registry.example/pkg/-/pkg-1.0.0.tgz",`,
			`"integrity": "${integrity}"`,
			`FROM node@${digest}`,
		].join("\n");
		expect(detectSecrets(text)).toEqual([]);
	});

	it("SCAN-005 sí reporta por entropía una cadena aleatoria suelta", () => {
		const token = `Zq8${createHash("sha256").update("semilla").digest("base64url")}`;
		const found = detectSecrets(`const x = "${token}";`);
		expect(found.map((m) => m.rule)).toEqual(["high-entropy"]);
		expect(found[0]?.value).toBe(token);
	});
});

function fill(seed: string, length: number): string {
	return createHash("sha512")
		.update(seed)
		.digest("base64url")
		.replace(/[^A-Za-z0-9]/g, "a")
		.slice(0, length);
}

function timed<T>(fn: () => T): { ms: number; out: T } {
	const t0 = performance.now();
	const out = fn();
	return { ms: performance.now() - t0, out };
}

describe("secrets · revisión", () => {
	it("SCAN-001 detecta openai-key, anthropic-key y JWT", () => {
		const openai = ["sk", "-proj-", fill("o", 40), "9"].join("");
		const anthropic = ["sk", "-ant-", "api03-", fill("an", 60)].join("");
		const jwt = [
			["ey", "J", fill("h", 20)].join(""),
			["ey", "J", fill("p", 24)].join(""),
			fill("s", 30),
		].join(".");
		const text = [`a = "${openai}"`, `b = "${anthropic}"`, `c = ${jwt}`].join(
			"\n",
		);
		const found = detectSecrets(text);
		expect(found.map((m) => [m.rule, m.value])).toEqual([
			["openai-key", openai],
			["anthropic-key", anthropic],
			["jwt", jwt],
		]);
	});

	it("SCAN-002 une una cadena partida con continuación en CRLF y LF", () => {
		const key = ["sk_", "live_", fill("k", 24)].join("");
		for (const eol of ["\r\n", "\n"]) {
			const text = `x = "${key.slice(0, 12)}\\${eol}${key.slice(12)}"`;
			const hits = detectSecrets(text).filter((m) => m.value === key);
			expect(hits).toHaveLength(1);
			expect(hits[0]?.rule).toBe("stripe-key");
		}
	});

	it("SCAN-005 reporta base64 con + o = pero no rutas largas", () => {
		const seed = createHash("sha256").update("semillab").digest("base64");
		expect(seed).toContain("+");
		const found = detectSecrets(`k = "${seed}"`);
		expect(found.map((m) => m.rule)).toEqual(["high-entropy"]);
		expect(found[0]?.value).toBe(seed);
		const path = "src/components/forms/Input2/validators/Another3Long4Path5Seg";
		expect(detectSecrets(`import x from "${path}/index.ts"`)).toEqual([]);
	});

	it("SCAN-005 reporta base64 aleatorio que solo lleva / y no una ruta con el mismo largo", () => {
		let seed = "";
		for (let i = 0; i < 4000; i++) {
			const b64 = createHash("sha512")
				.update(`slash-${i}`)
				.digest("base64")
				.slice(0, 48);
			const at = b64.indexOf("/");
			// The slash splits the token in two halves under 32 characters each.
			if (!b64.includes("+") && at >= 17 && at <= 29) {
				seed = b64;
				break;
			}
		}
		expect(seed).not.toBe("");
		const found = detectSecrets(`k = "${seed}"`);
		expect(found.map((m) => m.rule)).toEqual(["high-entropy"]);
		expect(found[0]?.value).toBe(seed);
		const path = "src/components/forms/Input2/validators/Another3Long4Path5Seg";
		expect(detectSecrets(`import x from "${path}"`)).toEqual([]);
		expect(
			detectSecrets(
				`GET https://example.com/v1/Users/Ab12Cd34Ef56Gh78Ij90Kl12`,
			),
		).toEqual([]);
	});

	it("SCAN-005 un segmento aleatorio de 32+ dentro de una ruta se evalúa por separado", () => {
		const seg = createHash("sha512")
			.update("segmento")
			.digest("base64")
			.replace(/[+/=]/g, "x")
			.slice(0, 40);
		const found = detectSecrets(`GET src/api/${seg}/index`);
		expect(found.map((m) => m.value)).toEqual([seg]);
	});

	it("SCAN-005 el propio pii.ts no dispara high-entropy (alfabetos armados por rangos)", async () => {
		const src = await readFile(
			new URL("../src/pii.ts", import.meta.url),
			"utf8",
		);
		expect(detectSecrets(src).filter((m) => m.rule === "high-entropy")).toEqual(
			[],
		);
	});

	it("SCAN-007 el orquestador no deja el valor en el Finding ni en su JSON", async () => {
		const [aws] = makeSecrets();
		const work = await mkdtemp(join(tmpdir(), "mct-val-"));
		try {
			await writeFile(
				join(work, "a.txt"),
				`k = "${aws?.value}"
`,
			);
			const result = await scan({
				work,
				quarantine: join(work, "no-existe"),
				gitleaks: {
					binary: "/usr/bin/gitleaks",
					installDir: work,
					tmpDir: join(work, "tmp"),
					run: async (_c, args) => {
						if (args.includes("--report-path")) {
							await writeFile(
								String(args[args.indexOf("--report-path") + 1]),
								"[]",
							);
						}
						return {
							code: 0,
							signal: null,
							stdout: "8.30.1\n",
							timedOut: false,
						};
					},
				},
			});
			expect(result.hallazgos.length).toBeGreaterThan(0);
			const json = JSON.stringify(result.hallazgos);
			expect(json).not.toContain(aws?.value ?? "x");
			for (const f of result.hallazgos) {
				expect(Object.keys(f)).not.toContain("value");
				expect(Object.keys(f)).not.toContain("valor");
			}
		} finally {
			await rm(work, { recursive: true, force: true });
		}
	});

	it("SCAN-005 reporta un hex de 40 o 64 con contexto y no uno suelto", () => {
		for (const algo of ["sha1", "sha256"]) {
			const hex = createHash(algo).update("ctx").digest("hex");
			const hit = detectSecrets(`api_token: "${hex}"`);
			expect(hit.map((m) => [m.rule, m.value])).toEqual([["hex-secret", hex]]);
			expect(detectSecrets(`commit ${hex}`)).toEqual([]);
		}
	});

	it("SEG-005 una comilla con 80 KB de espacios no se cuelga", () => {
		const { ms } = timed(() => detectSecrets(`"${" ".repeat(80_000)}x`));
		expect(ms).toBeLessThan(1000);
		const mixed = timed(() =>
			detectSecrets(`'${" \t".repeat(40_000)}+${" ".repeat(40_000)}`),
		);
		expect(mixed.ms).toBeLessThan(1000);
	});

	it("SEG-005 3 MB de digests se analizan en menos de 1 s", () => {
		const hex = createHash("sha256").update("d").digest("hex");
		const line = `FROM img@sha256:${hex}\n`;
		const text = line.repeat(Math.ceil((3 * 1024 * 1024) / line.length));
		const { ms, out } = timed(() => detectSecrets(text));
		expect(out).toEqual([]);
		expect(ms).toBeLessThan(1000);
	});

	it("SEG-009 un token de 10 MB no da RangeError", () => {
		const text = `k = "${"a1".repeat(5 * 1024 * 1024)}"`;
		try {
			detectSecrets(text);
		} catch (e) {
			expect(e).toBeInstanceOf(MctError);
		}
	});
});
