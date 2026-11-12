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

const pkg = (start: string) =>
	JSON.stringify({ name: "fx", version: "1.0.0", scripts: { start } });

const E2E_MS = 240_000;

const SERVER = [
	'const http = require("node:http");',
	'http.createServer((_req, res) => res.end("ok")).listen(3111);',
	"",
].join("\n");

describe("VER-005 node healthcheck against real Docker", () => {
	it(
		"VER-005 a server that answers 2xx from inside the container passes with no network",
		async () => {
			await build("node", {
				"package.json": pkg("node server.js"),
				"server.js": SERVER,
			});
			const result = await verify();
			expect(result.healthcheck.tipo).toBe("http");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
			expect(state.verificado?.distSha256).toBe(
				await hashTree(join(raiz, "dist")),
			);
		},
		E2E_MS,
	);

	it(
		"VER-005 without a port, a start that exits 0 is enough",
		async () => {
			await build("node", {
				"package.json": pkg("node index.js"),
				"index.js": 'process.stdout.write("listo\\n");\n',
			});
			const result = await verify();
			expect(result.healthcheck.tipo).toBe("salida-cero");
		},
		E2E_MS,
	);

	it(
		"VER-005 a server that dies before answering blocks the gate",
		async () => {
			await build("node", {
				"package.json": pkg("node server.js"),
				"server.js": [
					"// .listen(3111) keeps the port detectable",
					"if (process.argv.length > 0) process.exit(4);",
					'require("node:http").createServer().listen(3111);',
					"",
				].join("\n"),
			});
			const err = await errOf(verify());
			expect(err.codigo).toBe("PUERTA_BLOQUEADA");
			expect(err.detalle?.motivo).toBe("arranque");
		},
		E2E_MS,
	);
});
