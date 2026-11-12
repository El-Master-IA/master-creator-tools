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
let routes: string[];

function readOnlyClient(): GithubClient {
	return {
		tokenSource: "GITHUB_TOKEN",
		rateRemaining: undefined,
		request: async (route) => {
			routes.push(route);
			if (!route.startsWith("GET ")) throw new Error("write attempted");
			throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
		},
		checkPermissions: async () => {
			routes.push("GET /user");
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

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pubdry-"));
	raiz = join(base, ".mct");
	routes = [];
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("PUB-006 dry-run", () => {
	it("PUB-006 --dry-run completes every check with GitHub reads only", async () => {
		await build();
		const res = await runPublishChecks(readOnlyClient(), {
			raiz,
			repo: "dueno/proyecto",
			dryRun: true,
		});
		expect(res).toEqual({
			repo: "dueno/proyecto",
			dryRun: true,
			modo: "nuevo",
		});
		expect(routes.length).toBeGreaterThan(0);
		expect(routes.every((r) => r.startsWith("GET "))).toBe(true);
	});

	it("PUB-006 --dry-run leaves the workspace byte for byte unchanged", async () => {
		await build();
		const antes = await hashTree(raiz);
		await runPublishChecks(readOnlyClient(), {
			raiz,
			repo: "dueno/proyecto",
			dryRun: true,
		});
		expect(await hashTree(raiz)).toBe(antes);
	});

	it("PUB-006 --dry-run still refuses when a gate is closed", async () => {
		await build();
		await writeFile(
			join(raiz, "findings.json"),
			JSON.stringify({ schemaVersion: 1, hallazgos: [{ estado: "abierto" }] }),
		);
		const err = await runPublishChecks(readOnlyClient(), {
			raiz,
			repo: "dueno/proyecto",
			dryRun: true,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect(routes).toEqual([]);
	});

	it("PUB-006 --dry-run reports an existing repo as VALIDACION", async () => {
		await build();
		const client: GithubClient = {
			...readOnlyClient(),
			request: async (route) => {
				routes.push(route);
				return { status: 200, headers: {}, data: { id: 9 } };
			},
		};
		const err = await runPublishChecks(client, {
			raiz,
			repo: "dueno/proyecto",
			dryRun: true,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect((err as MctError).codigo).toBe("VALIDACION");
	});
});
