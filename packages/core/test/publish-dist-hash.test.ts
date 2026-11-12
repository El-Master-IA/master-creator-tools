import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GithubClient } from "../src/github.js";
import { hashTree } from "../src/hash.js";
import { runPublishChecks } from "../src/publish-gates.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

let base: string;
let raiz: string;
let calls: string[];

function fakeClient(): GithubClient {
	return {
		tokenSource: "GITHUB_TOKEN",
		rateRemaining: undefined,
		request: async (route) => {
			calls.push(route);
			throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
		},
		checkPermissions: async () => {
			calls.push("permissions");
		},
	};
}

async function build(): Promise<void> {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "node",
	});
	await writeFile(join(ws.work, "a.txt"), "hola work\n");
	await writeFile(join(ws.dist, "b.txt"), "hola dist\n");
	const work = await hashTree(ws.work);
	const dist = await hashTree(ws.dist);
	const state = await readState(raiz);
	for (const e of Object.keys(state.etapas) as Array<
		keyof typeof state.etapas
	>) {
		if (e !== "publish") state.etapas[e].estado = "ok";
	}
	state.workSha256 = work;
	state.distSha256 = dist;
	state.verificado = {
		distSha256: dist,
		destino: "local",
		ts: "2026-11-08T00:00:00Z",
	};
	await writeState(raiz, state);
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({ schemaVersion: 1, hallazgos: [] }),
	);
	await writeFile(join(raiz, "license-report.json"), "[]");
	await writeFile(
		join(raiz, "approval.json"),
		JSON.stringify({ schemaVersion: 1, arbolSha256: work }),
	);
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pubhash-"));
	raiz = join(base, ".mct");
	calls = [];
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("PUB-010 distSha256", () => {
	it("PUB-010 a matching distSha256 lets the checks continue to GitHub reads", async () => {
		await build();
		await runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" });
		expect(calls).toEqual(["permissions", "GET /repos/{owner}/{repo}"]);
	});

	it("PUB-010 a changed dist/ is APROBACION_DESACTUALIZADA without calling GitHub", async () => {
		await build();
		await writeFile(join(raiz, "dist", "b.txt"), "cambiado\n");
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(calls).toEqual([]);
	});

	it("PUB-010 a new file in dist/ is APROBACION_DESACTUALIZADA", async () => {
		await build();
		await writeFile(join(raiz, "dist", "extra.txt"), "x\n");
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
	});

	it("PUB-010 a verificado.distSha256 that differs is APROBACION_DESACTUALIZADA", async () => {
		await build();
		const state = await readState(raiz);
		if (state.verificado === null) throw new Error("fixture");
		state.verificado.distSha256 = "0".repeat(64);
		await writeState(raiz, state);
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(calls).toEqual([]);
	});

	it("PUB-010 a changed work/ since the approval is APROBACION_DESACTUALIZADA", async () => {
		await build();
		await writeFile(join(raiz, "work", "a.txt"), "otro\n");
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(calls).toEqual([]);
	});

	it("PUB-010 a malformed hash in approval.json fails closed", async () => {
		await build();
		await writeFile(
			join(raiz, "approval.json"),
			JSON.stringify({ schemaVersion: 1, arbolSha256: "xyz" }),
		);
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("PUB-010 a missing approval.json is PUERTA_BLOQUEADA", async () => {
		await build();
		await rm(join(raiz, "approval.json"));
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(calls).toEqual([]);
	});
});
