import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding } from "@mct/contract/types";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signApproval } from "../src/approval.js";
import { stagePackage } from "../src/package.js";
import { stageScan } from "../src/stage-scan.js";
import { createWorkspace, updateState } from "../src/workspace.js";

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pkg-adapter-"));
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
	await writeFile(args[args.indexOf("--report-path") + 1] as string, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};
const gitleaks = () => ({
	binary: process.execPath,
	installDir: join(base, "bin"),
	tmpDir: join(raiz, "tmp"),
	run: okRunner,
});

async function packaged(adapter: string, files: Record<string, string>) {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "demo-app" },
		// stage-scan only knows node/n8n today: scan as node, package as `adapter`.
		adapter: "node",
	});
	for (const [rel, data] of Object.entries(files)) {
		const full = join(ws.work, rel);
		await mkdir(join(full, ".."), { recursive: true });
		await writeFile(full, data);
	}
	await stageScan(raiz, { home, gitleaks: gitleaks() }).catch((e: unknown) => {
		if (!(e instanceof MctError) || e.codigo !== "PUERTA_BLOQUEADA") throw e;
	});
	const doc = JSON.parse(
		await readFile(join(raiz, "findings.json"), "utf8"),
	) as { hallazgos: Finding[] };
	await updateState(raiz, (s) => ({
		...s,
		adapter,
		etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
	}));
	await signApproval({
		raiz,
		hallazgos: doc.hallazgos,
		gitleaksVersion: "8.30.1",
		mctVersion: "0.0.0",
	});
	const r = await stagePackage(raiz, {
		holder: "Acme Labs",
		year: 2026,
		home,
		gitleaks: gitleaks(),
	});
	return (rel: string) => readFile(join(r.dist, rel), "utf8");
}

describe("PKG-006 / VER-007 package por adaptador", () => {
	it("PKG-006 un workspace python genera ci.yml con setup-python y pytest", async () => {
		const read = await packaged("python", {
			"pyproject.toml":
				'[project]\nname = "demo"\nversion = "1.0.0"\nrequires-python = ">=3.13"\n',
			"main.py": "print('hola')\n",
			"tests/test_main.py": "def test_ok():\n    assert True\n",
		});
		const ci = await read(".github/workflows/ci.yml");
		expect(ci).toContain("actions/setup-python@v5");
		expect(ci).toContain("python -m compileall -q .");
		expect(ci).toContain("pytest");
		expect(ci).toContain("pip install .");
	});

	it("VER-007 un workspace genérico trae la sección de verificación en el README", async () => {
		const read = await packaged("generico", { "run.sh": "echo hola\n" });
		expect(await read("README.md")).toContain("## Verification status");
		expect(await read("README.es.md")).toContain(
			"## Estado de la verificación",
		);
		const ci = await read(".github/workflows/ci.yml");
		expect(ci).toContain("gitleaks");
		expect(ci).not.toContain("setup-");
	});
});
