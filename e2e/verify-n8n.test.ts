import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
import type { Runner } from "../packages/core/src/clone.js";
import { loadConfig } from "../packages/core/src/config.js";
import {
	type DockerTarget,
	resolveDocker,
} from "../packages/core/src/docker.js";
import { hashTree } from "../packages/core/src/hash.js";
import { stageVerify } from "../packages/core/src/verify.js";
import {
	createWorkspace,
	readState,
	writeState,
} from "../packages/core/src/workspace.js";

// Real Docker: the one in DOCKER_HOST (ssh://servidor-casa) or the local daemon. No fallback: if
// there is none, resolveDocker fails closed and the suite fails.
let target: DockerTarget;
let base = "";
let raiz = "";

beforeAll(async () => {
	target = await resolveDocker({ env: process.env });
}, 60_000);

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t30e-"));
	raiz = join(base, ".mct");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** A workspace whose work/ and dist/ hold the same files, with package already passed. */
async function build(
	adapter: "node" | "n8n",
	files: Record<string, string>,
	config?: unknown,
): Promise<void> {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter,
	});
	for (const root of [ws.work, ws.dist]) {
		for (const [name, content] of Object.entries(files)) {
			await mkdir(dirname(join(root, name)), { recursive: true });
			await writeFile(join(root, name), content);
		}
	}
	if (config !== undefined) {
		await writeFile(join(base, "mct.config.json"), JSON.stringify(config));
	}
	const state = await readState(raiz);
	state.workSha256 = await hashTree(ws.work);
	state.distSha256 = await hashTree(ws.dist);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
}

async function verify(extra: { run?: Runner } = {}) {
	const config = await loadConfig(base);
	return stageVerify(raiz, {
		target,
		...(config.verify?.timeoutMin !== undefined && {
			configTimeoutMin: config.verify.timeoutMin,
		}),
		...extra,
	});
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

const E2E_MS = 300_000;

const NODE_ID = ["11111111", "1111", "4111", "8111", "111111111111"].join("-");

function workflow(name: string, connections: unknown = {}): string {
	return JSON.stringify({
		name,
		nodes: [
			{
				parameters: {},
				id: NODE_ID,
				name: "Start",
				type: "n8n-nodes-base.manualTrigger",
				typeVersion: 1,
				position: [0, 0],
			},
		],
		connections,
	});
}

describe("VER-004 n8n import against real Docker", () => {
	it(
		"VER-004 valid workflows pass only because n8n import:workflow exits 0",
		async () => {
			await build("n8n", {
				"workflows/uno.json": workflow("uno"),
				"workflows/dos.json": workflow("dos"),
			});
			const dist = await hashTree(join(raiz, "dist"));
			const result = await verify();
			expect(result.healthcheck.tipo).toBe("n8n-import");
			expect(result.distSha256).toBe(dist);
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
			expect(state.verificado?.distSha256).toBe(dist);
		},
		E2E_MS,
	);

	it(
		"VER-004 a workflow n8n refuses to import blocks the gate",
		async () => {
			await build("n8n", {
				"workflows/ok.json": workflow("ok"),
				"workflows/roto.json": workflow("roto", {
					Ghost: { main: [[{ node: "Nowhere", type: "main", index: 0 }]] },
				}),
			});
			const err = await errOf(verify());
			expect(err.codigo).toBe("PUERTA_BLOQUEADA");
			expect(err.detalle?.motivo).toBe("arranque");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("bloqueada");
			expect(state.verificado).toBeNull();
		},
		E2E_MS,
	);
});
