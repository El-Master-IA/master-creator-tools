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
import { signApproval } from "../src/approval.js";
import { type StagePackageOptions, stagePackage } from "../src/package.js";
import { type StageScanOptions, stageScan } from "../src/stage-scan.js";
import { createWorkspace, readState, updateState } from "../src/workspace.js";

let base = "";
let raiz = "";
let home = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-package-"));
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

function gitleaks(): StageScanOptions["gitleaks"] {
	return {
		binary: process.execPath,
		installDir: join(base, "bin"),
		tmpDir: join(raiz, "tmp"),
		run: okRunner,
	};
}

function opts(): StagePackageOptions {
	return { holder: "Acme Labs", year: 2026, home, gitleaks: gitleaks() };
}

/** Workspace with the scan done and a signed approval. */
async function approved() {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "demo-app" },
		adapter: "node",
	});
	await writeFile(
		join(ws.work, "package.json"),
		'{"name":"demo","version":"1.0.0"}\n',
	);
	await stageScan(raiz, { home, gitleaks: gitleaks() });
	const doc = JSON.parse(
		await readFile(join(raiz, "findings.json"), "utf8"),
	) as { hallazgos: Finding[] };
	await updateState(raiz, (s) => ({
		...s,
		etapas: { ...s.etapas, sanitize: { estado: "ok", ts: s.etapas.init.ts } },
	}));
	await signApproval({
		raiz,
		hallazgos: doc.hallazgos,
		gitleaksVersion: "8.30.1",
		mctVersion: "0.0.0",
	});
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

describe("etapa package: aprobación", { timeout: 60_000 }, () => {
	it("PKG-001 CUANDO work cambió tras firmar EL SISTEMA DEBE salir con APROBACION_DESACTUALIZADA y no tocar dist", async () => {
		const ws = await approved();
		await writeFile(join(ws.dist, "previo.txt"), "intacto\n");
		await writeFile(join(ws.work, "nuevo.txt"), "cambio posterior\n");
		expect(await codigoDe(stagePackage(raiz, opts()))).toBe(
			"APROBACION_DESACTUALIZADA",
		);
		expect(await readFile(join(ws.dist, "previo.txt"), "utf8")).toBe(
			"intacto\n",
		);
		await expect(stat(join(raiz, "dist.new"))).rejects.toThrow();
		expect((await readState(raiz)).etapas.package.estado).toBe("pendiente");
	});

	it("PKG-001 CUANDO falta approval.json EL SISTEMA DEBE salir con APROBACION_DESACTUALIZADA", async () => {
		await approved();
		await rm(join(raiz, "approval.json"));
		expect(await codigoDe(stagePackage(raiz, opts()))).toBe(
			"APROBACION_DESACTUALIZADA",
		);
	});

	it("PKG-001 CUANDO sanitize no está ok EL SISTEMA DEBE salir con APROBACION_DESACTUALIZADA", async () => {
		await approved();
		await updateState(raiz, (s) => ({
			...s,
			etapas: { ...s.etapas, sanitize: { estado: "pendiente", ts: "x" } },
		}));
		expect(await codigoDe(stagePackage(raiz, opts()))).toBe(
			"APROBACION_DESACTUALIZADA",
		);
	});

	it("PKG-001 CUANDO la aprobación vale EL SISTEMA DEBE generar dist", async () => {
		const ws = await approved();
		const r = await stagePackage(raiz, opts());
		expect(r.dist).toBe(ws.dist);
		expect(r.distSha256).toMatch(/^[0-9a-f]{64}$/);
		expect(await readFile(join(ws.dist, "package.json"), "utf8")).toContain(
			"demo",
		);
	});
});
