import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
import { type Runner, spawnRunner } from "../packages/core/src/clone.js";
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

/** Runner that remembers the name of the container that ran the start phase. */
function spy(): { run: Runner; startName: () => string | undefined } {
	let name: string | undefined;
	const run: Runner = (file, args, options) => {
		if (args[0] === "run") {
			const at = args.indexOf("--name");
			if (at >= 0) name = args[at + 1];
		}
		return spawnRunner(file, args, options);
	};
	return { run, startName: () => name };
}

async function containerExists(name: string): Promise<boolean> {
	const r = await spawnRunner(
		target.dockerPath,
		["ps", "-aq", "--filter", `name=^${name}$`],
		{
			env: target.env,
			cwd: process.cwd(),
			signal: new AbortController().signal,
		},
	);
	return r.stdout.trim() !== "";
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

describe("VER-002 verify against real Docker", () => {
	it(
		"VER-002 a start that exits 0 passes the gate and saves the verified distSha256",
		async () => {
			await build("node", {
				"package.json": pkg("node index.js"),
				"index.js": 'process.stdout.write("listo\\n");\n',
			});
			const dist = await hashTree(join(raiz, "dist"));
			const result = await verify();
			expect(result.distSha256).toBe(dist);
			expect(result.healthcheck.tipo).toBe("salida-cero");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
			expect(state.verificado?.distSha256).toBe(dist);
			expect(state.verificado?.destino).toBe(
				target.kind === "remote" ? target.alias : "local",
			);
		},
		E2E_MS,
	);

	it(
		"VER-002 a start that exits non-zero blocks the gate with PUERTA_BLOQUEADA",
		async () => {
			await build("node", {
				"package.json": pkg("node fail.js"),
				"fail.js": "process.exit(2);\n",
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

	it(
		"VER-002 when the config time limit expires the container is stopped and the gate blocks",
		async () => {
			await build(
				"node",
				{
					"package.json": pkg("node hang.js"),
					"hang.js": "setInterval(() => {}, 1000);\n",
				},
				{ verify: { timeoutMin: 1 } },
			);
			const probe = spy();
			const err = await errOf(verify({ run: probe.run }));
			expect(err.codigo).toBe("PUERTA_BLOQUEADA");
			expect(err.exit).toBe(10);
			expect(err.detalle?.motivo).toBe("timeout");
			const name = probe.startName();
			expect(name).toMatch(/^mct-start-/);
			expect(await containerExists(name as string)).toBe(false);
			expect((await readState(raiz)).verificado).toBeNull();
		},
		E2E_MS + 60_000,
	);
});
