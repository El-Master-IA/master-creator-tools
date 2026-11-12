import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
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

// Real Docker (DOCKER_HOST=ssh://servidor-casa). No fallback: without Docker the suite fails.
let target: DockerTarget;
let base = "";
let raiz = "";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

beforeAll(async () => {
	target = await resolveDocker({ env: process.env });
}, 60_000);

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c13p-"));
	raiz = join(base, ".mct");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** A python workspace: work/ and dist/ copy a fixture folder, with package already passed. */
async function build(
	fixture: string,
	extra: Record<string, string> = {},
): Promise<void> {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "python",
	});
	for (const root of [ws.work, ws.dist]) {
		await cp(join(FIXTURES, fixture), root, { recursive: true });
		for (const [name, content] of Object.entries(extra)) {
			await mkdir(root, { recursive: true });
			await writeFile(join(root, name), content);
		}
	}
	const state = await readState(raiz);
	state.workSha256 = await hashTree(ws.work);
	state.distSha256 = await hashTree(ws.dist);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
}

async function verify() {
	const config = await loadConfig(base);
	return stageVerify(raiz, {
		target,
		...(config.verify?.timeoutMin !== undefined && {
			configTimeoutMin: config.verify.timeoutMin,
		}),
	});
}

const E2E_MS = 420_000;

describe("PY-003 python verify against real Docker", () => {
	it(
		"PY-003 a FastAPI app that answers on its port passes (install with network, start without)",
		async () => {
			await build("python-fastapi");
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
		"PY-003 a script without a port passes with compileall + pip check",
		async () => {
			await build("python-script");
			const result = await verify();
			expect(result.healthcheck.tipo).toBe("salida-cero");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
		},
		E2E_MS,
	);

	it(
		"PY-003 an impossible requires-python blocks with version-python",
		async () => {
			await build("python-script", {
				"pyproject.toml": [
					"[project]",
					'name = "fx"',
					'version = "1.0.0"',
					'requires-python = ">=3.99"',
					"",
				].join("\n"),
			});
			const err = await verify().then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(MctError);
			expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
			expect((err as MctError).detalle?.motivo).toBe("version-python");
		},
		E2E_MS,
	);
});
