import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Etapa } from "@mct/contract/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GithubClient } from "../src/github.js";
import { hashTree } from "../src/hash.js";
import { runPublishChecks } from "../src/publish-gates.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

let base: string;
let raiz: string;
let calls: string[];

const ETAPAS_PREVIAS: Etapa[] = [
	"init",
	"scan",
	"sanitize",
	"licenses",
	"package",
	"verify",
];

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

async function build(
	opts: {
		hallazgos?: Array<{ estado: string }>;
		licencias?: unknown[];
		etapaPendiente?: Etapa;
		sinVerificado?: boolean;
	} = {},
): Promise<void> {
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
	for (const e of ETAPAS_PREVIAS) state.etapas[e].estado = "ok";
	if (opts.etapaPendiente !== undefined) {
		state.etapas[opts.etapaPendiente].estado = "pendiente";
	}
	state.workSha256 = work;
	state.distSha256 = dist;
	state.verificado = opts.sinVerificado
		? null
		: { distSha256: dist, destino: "local", ts: "2026-11-08T00:00:00Z" };
	await writeState(raiz, state);
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({
			schemaVersion: 1,
			hallazgos: opts.hallazgos ?? [
				{ estado: "aislado" },
				{ estado: "resuelto" },
			],
		}),
	);
	await writeFile(
		join(raiz, "license-report.json"),
		JSON.stringify(opts.licencias ?? [{ veredicto: "ok" }]),
	);
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
	base = await mkdtemp(join(tmpdir(), "mct-pubgates-"));
	raiz = join(base, ".mct");
	calls = [];
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("PUB-001 publish gates", () => {
	it("PUB-001 an open finding is PUERTA_BLOQUEADA and GitHub is not called", async () => {
		await build({ hallazgos: [{ estado: "abierto" }] });
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle?.abiertos).toBe(1);
		expect(calls).toEqual([]);
	});

	it("PUB-001 aislado findings do not count as open", async () => {
		await build({ hallazgos: [{ estado: "aislado" }] });
		const res = await runPublishChecks(fakeClient(), {
			raiz,
			repo: "dueno/proyecto",
		});
		expect(res.modo).toBe("nuevo");
	});

	it("PUB-001 a pending stage is PUERTA_BLOQUEADA without calling GitHub", async () => {
		await build({ etapaPendiente: "licenses" });
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(calls).toEqual([]);
	});

	it("PUB-001 a blocking license without override is PUERTA_BLOQUEADA", async () => {
		await build({ licencias: [{ veredicto: "bloquea" }] });
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(calls).toEqual([]);
	});

	it("PUB-001 revisar or bloquea with an override still closes the gate", async () => {
		for (const veredicto of ["revisar", "bloquea"]) {
			calls.length = 0;
			await build({
				licencias: [{ veredicto, override: { motivo: "uso interno" } }],
			});
			const err = await errOf(
				runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
			);
			expect(err.codigo).toBe("PUERTA_BLOQUEADA");
			expect(calls).toEqual([]);
		}
	});

	it("PUB-001 a license with ok verdict and a written override passes", async () => {
		await build({
			licencias: [{ veredicto: "ok", override: { motivo: "uso interno" } }],
		});
		await expect(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		).resolves.toMatchObject({ modo: "nuevo" });
	});

	it("PUB-001 verify not passed is PUERTA_BLOQUEADA", async () => {
		await build({ sinVerificado: true });
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(calls).toEqual([]);
	});

	it("PUB-001 an unreadable findings.json fails closed, never zero findings", async () => {
		await build();
		await writeFile(join(raiz, "findings.json"), "{ no es json");
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
		expect(calls).toEqual([]);
	});

	it("PUB-001 a missing findings.json is PUERTA_BLOQUEADA", async () => {
		await build();
		await rm(join(raiz, "findings.json"));
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
	});

	it("PUB-001 an unknown finding state fails closed", async () => {
		await build({ hallazgos: [{ estado: "raro" }] });
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "dueno/proyecto" }),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("PUB-001 a bad repo name is VALIDACION before anything else", async () => {
		await build();
		const err = await errOf(
			runPublishChecks(fakeClient(), { raiz, repo: "sin-barra" }),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(calls).toEqual([]);
	});
});
