import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding } from "@mct/contract/types";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type StageScanOptions, stageScan } from "../src/stage-scan.js";
import {
	createWorkspace,
	readState,
	updateState,
	workspacePaths,
} from "../src/workspace.js";

// Fixture values are assembled from fragments: no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const TERM = ["zq", "client", "x9"].join("");
const NPM_USER = ["ci", "bot"].join("");
const NPM_PASS = ["p4ss", "w0rd", "Z9"].join("");

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-stage-scan-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	await mkdir(join(home, ".mct"), { recursive: true });
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

function opts(over: Partial<StageScanOptions> = {}): StageScanOptions {
	return {
		home,
		lang: "es",
		gitleaks: {
			binary: process.execPath,
			installDir: join(base, "bin"),
			tmpDir: join(raiz, "tmp"),
			run: okRunner,
		},
		...over,
	};
}

async function workspace(
	files: Record<string, string>,
	quarantine: Record<string, string> = {},
	adapter: "node" | "n8n" = "node",
) {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "x" },
		adapter,
	});
	const put = async (root: string, rel: string, text: string) => {
		const full = join(root, rel);
		await mkdir(join(full, ".."), { recursive: true });
		await writeFile(full, text);
	};
	await put(ws.work, "package.json", '{"name":"demo","version":"1.0.0"}\n');
	for (const [rel, text] of Object.entries(files)) {
		await put(ws.work, rel, text);
	}
	for (const [rel, text] of Object.entries(quarantine)) {
		await put(ws.quarantine, rel, text);
	}
	return ws;
}

async function codigoDe(p: Promise<unknown>): Promise<string> {
	try {
		await p;
	} catch (e) {
		if (e instanceof MctError) return e.codigo;
		throw e;
	}
	return "NINGUNO";
}

async function todoElTexto(): Promise<string> {
	let out = "";
	for (const f of ["findings.json", "analysis.json", "report.html"]) {
		out += await readFile(join(raiz, f), "utf8").catch(() => "");
	}
	for (const l of ["scan.jsonl"]) {
		out += await readFile(join(raiz, "logs", l), "utf8").catch(() => "");
	}
	return out;
}

describe("etapa scan", () => {
	it("SCAN-012 CUANDO corre sobre un fixture escribe los tres artefactos solo con datos enmascarados", async () => {
		await workspace({ "src/a.ts": `const t = "${TOKEN}";\n` });
		const codigo = await codigoDe(stageScan(raiz, opts()));
		expect(codigo).toBe("PUERTA_BLOQUEADA");
		const findings = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(findings.hallazgos.length).toBeGreaterThan(0);
		await stat(join(raiz, "analysis.json"));
		await stat(join(raiz, "report.html"));
		expect(await todoElTexto()).not.toContain(TOKEN);
		expect(JSON.stringify(findings)).not.toContain(TOKEN.slice(4));
	});

	it("SCAN-012 analysis.json enmascara main, dependencias con token y URLs con credenciales (host con y sin punto, IP)", async () => {
		await writeFile(join(home, ".mct", "sensible.txt"), `${TERM}\n`);
		const urls = [
			`https://${NPM_USER}:${NPM_PASS}@nexus:8081/repo/pkg-1.0.0.tgz`,
			`https://${NPM_USER}:${NPM_PASS}@10.0.0.5:8081/repo/pkg-1.0.0.tgz`,
			`git+http://${NPM_USER}:${NPM_PASS}@localhost/x.git`,
		];
		const pkg = {
			name: "demo",
			version: "1.0.0",
			main: `lib/${TERM}.js`,
			dependencies: {
				a: urls[0],
				b: urls[1],
				c: urls[2],
				d: TOKEN,
				e: "^1.2.3",
				f: "latest",
			},
		};
		await workspace({ "package.json": `${JSON.stringify(pkg)}\n` });
		const ws = workspacePaths(raiz);
		const { analyze } = (await import("@mct/adapter-node/index")).nodeAdapter;
		const raw = JSON.stringify(await analyze(ws));
		// Precondition: analyze does produce the sensitive data.
		expect(raw).toContain(NPM_PASS);
		expect(raw).toContain(TERM);
		expect(raw).toContain(TOKEN);
		const r = await stageScan(raiz, opts()).catch((e) => e);
		const salida = JSON.stringify(
			r instanceof MctError ? {} : (r as { analysis: unknown }).analysis,
		);
		const disco = await readFile(join(raiz, "analysis.json"), "utf8");
		for (const texto of [disco, salida]) {
			expect(texto).not.toContain(NPM_PASS);
			expect(texto).not.toContain(TERM);
			expect(texto).not.toContain(TOKEN);
		}
		expect(disco).toContain("^1.2.3");
		expect(disco).toContain("latest");
	});

	it("SCAN-010 sin hallazgos abiertos devuelve el resumen y marca scan ok", async () => {
		await workspace({ "src/a.ts": "export const a = 1;\n" });
		const r = await stageScan(raiz, opts());
		expect(r.hallazgos.abiertos).toBe(0);
		expect(r.gitleaksVersion).toBe("8.30.1");
		expect((await readState(raiz)).etapas.scan.estado).toBe("ok");
		const html = await readFile(join(raiz, "report.html"), "utf8");
		expect(html).toContain("default-src 'none'");
	});

	it("SCAN-010 con abiertos sale con PUERTA_BLOQUEADA (exit 10) y el detalle del conteo", async () => {
		await workspace({ "src/a.ts": `const t = "${TOKEN}";\n` });
		try {
			await stageScan(raiz, opts());
			expect.unreachable();
		} catch (e) {
			expect(e).toBeInstanceOf(MctError);
			expect((e as MctError).exit).toBe(10);
			expect((e as MctError).detalle?.abiertos).toBeGreaterThan(0);
		}
		expect((await readState(raiz)).etapas.scan.estado).toBe("bloqueada");
	});

	it("SCAN-012 CUANDO el workspace es inválido sale con WORKSPACE_INVALIDO", async () => {
		await mkdir(raiz, { recursive: true });
		expect(await codigoDe(stageScan(raiz, opts()))).toBe("WORKSPACE_INVALIDO");
		expect(await codigoDe(stageScan(join(base, "nada"), opts()))).toBe(
			"WORKSPACE_INVALIDO",
		);
	});

	it("SCAN-012 CUANDO el lockfile lleva credenciales incluye el hallazgo del adaptador", async () => {
		const url = `https://${NPM_USER}:${NPM_PASS}@registry.example.test/pkg/-/pkg-1.0.0.tgz`;
		await workspace({
			"pnpm-lock.yaml": `lockfileVersion: '9.0'\npackages:\n  pkg@1.0.0:\n    resolution: {tarball: ${url}}\n`,
		});
		await codigoDe(stageScan(raiz, opts()));
		const { hallazgos } = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(
			hallazgos.some(
				(f) => f.regla === "credenciales-en-url" && f.zona === "work",
			),
		).toBe(true);
		expect(await todoElTexto()).not.toContain(NPM_PASS);
	});

	it("SCAN-012 CUANDO el adaptador es n8n un lockfile con registro privado bloquea la puerta", async () => {
		const lock = {
			name: "demo",
			lockfileVersion: 3,
			packages: {
				"node_modules/pkg": {
					version: "1.0.0",
					resolved: "https://nexus.corp.example.test/repo/pkg/-/pkg-1.0.0.tgz",
				},
			},
		};
		await workspace(
			{
				"package-lock.json": `${JSON.stringify(lock)}
`,
			},
			{},
			"n8n",
		);
		expect(await codigoDe(stageScan(raiz, opts()))).toBe("PUERTA_BLOQUEADA");
		const { hallazgos } = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		expect(hallazgos.some((f) => f.regla === "registro-privado")).toBe(true);
	});

	it("SCAN-012 un .npmrc en cuarentena aporta su hallazgo como aislado", async () => {
		await workspace(
			{ "src/a.ts": "export const a = 1;\n" },
			{
				".npmrc": `//registry.example.test/:_authToken=${NPM_PASS}${NPM_PASS}\n`,
			},
		);
		const r = await stageScan(raiz, opts());
		expect(r.hallazgos.aislados).toBeGreaterThan(0);
		expect(await todoElTexto()).not.toContain(NPM_PASS);
	});

	it("SCAN-013 findings.json lleva schemaVersion, mctVersion, gitleaksVersion y generadoEn", async () => {
		await workspace({ "src/a.ts": "export const a = 1;\n" });
		await stageScan(raiz, opts({ now: () => "2026-11-08T10:00:00.000Z" }));
		const f = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as Record<string, unknown>;
		expect(f.schemaVersion).toBe(2);
		expect(f.mctVersion).toBe("0.0.0");
		expect(f.gitleaksVersion).toBe("8.30.1");
		expect(f.generadoEn).toBe("2026-11-08T10:00:00.000Z");
		if (process.platform !== "win32") {
			for (const n of ["findings.json", "analysis.json", "report.html"]) {
				expect((await stat(join(raiz, n))).mode & 0o077).toBe(0);
			}
		}
	});

	it("SEG-001 enmascara archivo con un término del diccionario, también el contenido bajo esa carpeta", async () => {
		await writeFile(join(home, ".mct", "sensible.txt"), `${TERM}\n`);
		await workspace({
			[`${TERM}/lib/a.ts`]: `const t = "${TOKEN}";\n`,
			[`${TERM}/notas.txt`]: "nada\n",
			[`src/${TERM}.ts`]: "export const b = 2;\n",
		});
		await codigoDe(stageScan(raiz, opts()));
		const texto = await todoElTexto();
		expect(texto).not.toContain(TERM);
		expect(texto).not.toContain(TOKEN);
		const { hallazgos } = JSON.parse(
			await readFile(join(raiz, "findings.json"), "utf8"),
		) as { hallazgos: Finding[] };
		const bajoCarpeta = hallazgos.filter((f) => f.regla === "github-token");
		expect(bajoCarpeta.length).toBeGreaterThan(0);
		for (const f of bajoCarpeta) expect(f.archivo).not.toContain(TERM);
		expect(
			JSON.stringify(await readFile(join(raiz, "analysis.json"), "utf8")),
		).not.toContain(TERM);
	});

	it("SEG-001 enmascara archivo cuya ruta contiene un secreto", async () => {
		await workspace({ [`src/${TOKEN}.ts`]: "export const c = 3;\n" });
		await codigoDe(stageScan(raiz, opts()));
		expect(await todoElTexto()).not.toContain(TOKEN);
	});

	it("STATE-001 aplica la cascada cuando cambia el hash de work", async () => {
		await workspace({ "src/a.ts": "export const a = 1;\n" });
		await updateState(raiz, (s) => ({
			...s,
			workSha256: "a".repeat(64),
			etapas: {
				...s.etapas,
				sanitize: { estado: "ok", ts: s.etapas.sanitize.ts },
			},
		}));
		await stageScan(raiz, opts());
		const s = await readState(raiz);
		expect(s.workSha256).toMatch(/^[0-9a-f]{64}$/);
		expect(s.workSha256).not.toBe("a".repeat(64));
		expect(s.etapas.sanitize.estado).toBe("pendiente");
	});

	it("SCAN-009 un re-scan concilia con findings.json previo y conserva la decisión", async () => {
		await workspace({ "src/a.ts": `const t = "${TOKEN}";\n` });
		await codigoDe(stageScan(raiz, opts()));
		const path = join(raiz, "findings.json");
		const f = JSON.parse(await readFile(path, "utf8")) as {
			hallazgos: Finding[];
		};
		f.hallazgos = f.hallazgos.map((h) => ({
			...h,
			estado: "falso-positivo" as const,
			motivo: "fixture",
		}));
		await writeFile(path, JSON.stringify(f));
		const r = await stageScan(raiz, opts());
		expect(r.hallazgos.abiertos).toBe(0);
	});

	it("SCAN-005 falla cerrado si work cambia durante el scan", async () => {
		const ws = await workspace({ "src/a.ts": "export const a = 1;\n" });
		const mutante: Runner = async (c, args, o) => {
			if (!args.includes("version")) {
				await writeFile(
					join(ws.work, "src", "nuevo.ts"),
					"export const z = 1;\n",
				);
			}
			return okRunner(c, args, o);
		};
		expect(
			await codigoDe(
				stageScan(
					raiz,
					opts({ gitleaks: { ...opts().gitleaks, run: mutante } }),
				),
			),
		).toBe("WORKSPACE_INVALIDO");
		expect((await readState(raiz)).etapas.scan.estado).not.toBe("ok");
		expect(
			await readFile(join(raiz, "report.html"), "utf8").catch(() => ""),
		).toBe("");
	});

	it("SCAN-002 si un motor cae no queda scan válido ni reporte limpio", async () => {
		await workspace({ "src/a.ts": "export const a = 1;\n" });
		await stageScan(raiz, opts());
		expect((await readState(raiz)).etapas.scan.estado).toBe("ok");
		const caido: Runner = async () => ({
			code: 1,
			signal: null,
			stdout: "",
			timedOut: false,
		});
		expect(
			await codigoDe(
				stageScan(raiz, opts({ gitleaks: { ...opts().gitleaks, run: caido } })),
			),
		).toBe("MOTOR_NO_DISPONIBLE");
		expect((await readState(raiz)).etapas.scan.estado).toBe("pendiente");
		expect(
			await readFile(join(raiz, "report.html"), "utf8").catch(() => ""),
		).toBe("");
		expect(workspacePaths(raiz).raiz).toBe(raiz);
	});

	it("SCAN-002 no deja el lock tomado tras un fallo", async () => {
		await workspace({});
		const caido: Runner = async () => ({
			code: 1,
			signal: null,
			stdout: "",
			timedOut: false,
		});
		await codigoDe(
			stageScan(raiz, opts({ gitleaks: { ...opts().gitleaks, run: caido } })),
		);
		expect(await readFile(join(raiz, "lock"), "utf8").catch(() => "")).toBe("");
	});
});
