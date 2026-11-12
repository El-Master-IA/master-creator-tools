import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Adapter, VerifySpec } from "@mct/contract/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import type { DockerTarget } from "../src/docker.js";
import { hashTree } from "../src/hash.js";
import { argvToShell, resolveTimeoutMin, stageVerify } from "../src/verify.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

let base: string;
let raiz: string;

const target: DockerTarget = {
	kind: "local",
	dockerPath: "/usr/bin/docker",
	env: { PATH: "/usr/bin" },
};

const SPEC: VerifySpec = {
	imagen: "node:22-slim",
	start: ["node", "index.js"],
	healthcheck: { tipo: "salida-cero" },
	timeoutMin: 10,
};

function stub(spec: VerifySpec = SPEC): Adapter {
	return {
		id: "stub",
		analyze: async () => ({
			stack: [],
			entrypoints: [],
			envVars: [],
			deps: [],
			comandos: {},
		}),
		verifyCommand: () => spec,
	} as unknown as Adapter;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t30-"));
	raiz = join(base, ".mct");
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "stub",
	});
	await mkdir(join(ws.dist, "src"), { recursive: true });
	await writeFile(join(ws.dist, "index.js"), "console.info(1);\n");
	const state = await readState(raiz);
	state.distSha256 = await hashTree(ws.dist);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

function recorder(codes: Record<string, number> = {}) {
	const calls: string[][] = [];
	const run: Runner = async (_file, args) => {
		calls.push([...args]);
		return { code: codes[args[0] ?? ""] ?? 0, stdout: "", stderr: "" };
	};
	return { calls, run };
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

/** `docker run` hangs until its signal aborts; everything else succeeds. */
function hangingRun(calls: string[][], onRun?: () => void): Runner {
	return (_file, args, options) => {
		calls.push([...args]);
		if (args[0] === "run") {
			onRun?.();
			return new Promise((resolve) => {
				const done = () => resolve({ code: null, stdout: "", stderr: "" });
				if (options.signal.aborted) done();
				else options.signal.addEventListener("abort", done);
			});
		}
		return Promise.resolve({ code: 0, stdout: "", stderr: "" });
	};
}

describe("VER-002 timeout precedence", () => {
	it("VER-002 config beats the adapter and the adapter beats 10 minutes", () => {
		expect(resolveTimeoutMin(3, { timeoutMin: 7 })).toBe(3);
		expect(resolveTimeoutMin(undefined, { timeoutMin: 7 })).toBe(7);
		expect(resolveTimeoutMin(undefined, { timeoutMin: 0 })).toBe(10);
		expect(
			resolveTimeoutMin(undefined, {} as unknown as { timeoutMin: number }),
		).toBe(10);
	});
});

describe("VER-002 stage", () => {
	it("VER-002 a start that exits 0 passes the gate and saves the verified distSha256", async () => {
		const { run, calls } = recorder();
		const result = await stageVerify(raiz, {
			target,
			run,
			adapters: [stub()],
			now: () => "2026-11-10T00:00:00.000Z",
		});
		const state = await readState(raiz);
		const dist = await hashTree(join(raiz, "dist"));
		expect(result.distSha256).toBe(dist);
		expect(state.verificado).toEqual({
			distSha256: dist,
			destino: "local",
			ts: "2026-11-10T00:00:00.000Z",
		});
		expect(state.etapas.verify.estado).toBe("ok");
		expect(
			await readFile(join(raiz, "logs", "verify.jsonl"), "utf8"),
		).toContain("verify.ok");
		expect(await readFile(join(raiz, "report.html"), "utf8")).toContain(
			"verify",
		);
		const start = calls.find((c) => c[0] === "run") ?? [];
		expect(start).toContain("none");
	});

	it("VER-002 a start that exits non-zero blocks the gate and clears verificado", async () => {
		const { run } = recorder({ run: 3 });
		const err = await errOf(
			stageVerify(raiz, { target, run, adapters: [stub()] }),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle?.motivo).toBe("arranque");
		const state = await readState(raiz);
		expect(state.etapas.verify.estado).toBe("bloqueada");
		expect(state.verificado).toBeNull();
	});

	it("VER-002 the time limit stops the container and exits PUERTA_BLOQUEADA timeout", async () => {
		const calls: string[][] = [];
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: hangingRun(calls),
				adapters: [stub()],
				timeoutMs: 50,
			}),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.exit).toBe(10);
		expect(err.detalle?.motivo).toBe("timeout");
		expect(calls.some((c) => c[0] === "rm" && c[1] === "--force")).toBe(true);
		const state = await readState(raiz);
		expect(state.etapas.verify.estado).toBe("bloqueada");
		expect(state.verificado).toBeNull();
	});

	it("VER-002 Ctrl+C is INTERRUMPIDO, not a timeout, and leaves the state as it was", async () => {
		const ctrl = new AbortController();
		const before = await readState(raiz);
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: hangingRun([], () => ctrl.abort()),
				adapters: [stub()],
				signal: ctrl.signal,
				timeoutMs: 60_000,
			}),
		);
		expect(err.codigo).toBe("INTERRUMPIDO");
		expect(await readState(raiz)).toEqual(before);
	});

	it("VER-002 a dist/ that changes while verifying does not pass", async () => {
		const run: Runner = async (_file, args) => {
			if (args[0] === "run") {
				await writeFile(join(raiz, "dist", "index.js"), "console.info(2);\n");
			}
			return { code: 0, stdout: "", stderr: "" };
		};
		const err = await errOf(
			stageVerify(raiz, { target, run, adapters: [stub()] }),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
		expect((await readState(raiz)).verificado).toBeNull();
	});

	it("VER-002 a dist/ that is not the one package produced is refused before Docker", async () => {
		await writeFile(join(raiz, "dist", "extra.js"), "x\n");
		const { run, calls } = recorder();
		const err = await errOf(
			stageVerify(raiz, { target, run, adapters: [stub()] }),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
		expect(calls).toHaveLength(0);
	});

	it("VER-002 an install that fails blocks the gate", async () => {
		const { run } = recorder({ start: 1 });
		const err = await errOf(
			stageVerify(raiz, { target, run, adapters: [stub()] }),
		);
		expect(err.detalle?.motivo).toBe("instalacion");
	});
});

describe("VER-004 command lines", () => {
	it("VER-004 the n8n import quotes every word and never interpolates a path", () => {
		const evil = "a b'; echo x #.json";
		const line = argvToShell([
			"sh",
			"-c",
			'for f in "$@"; do n8n import:workflow --input="$f" || exit 1; done',
			"sh",
			"wf/ok.json",
			evil,
		]);
		expect(line).toContain(String.raw`'a b'\''; echo x #.json'`);
		expect(line).toContain("wf/ok.json");
		expect(line.startsWith("sh -c 'for f in")).toBe(true);
	});

	it("VER-004 a plain adapter command line is restored with spaces", () => {
		expect(argvToShell(["npm", "ci", "&&", "npm", "start"])).toBe(
			"npm ci && npm start",
		);
	});

	it("VER-004 the n8n spec is passed to the container as quoted argv", async () => {
		const spec: VerifySpec = {
			imagen: "n8nio/n8n:1.0.0",
			start: ["sh", "-c", 'echo "$1"', "sh", "w f.json"],
			healthcheck: { tipo: "n8n-import" },
			timeoutMin: 10,
		};
		const { run, calls } = recorder();
		await stageVerify(raiz, { target, run, adapters: [stub(spec)] });
		const start = calls.find((c) => c[0] === "run") ?? [];
		expect(start.at(-1)).toContain("sh -c 'echo \"$1\"' sh 'w f.json'");
	});
});
