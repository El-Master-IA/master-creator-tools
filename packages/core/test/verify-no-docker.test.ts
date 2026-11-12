import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { resolveDocker } from "../src/docker.js";

let empty: string;

beforeEach(async () => {
	empty = await mkdtemp(join(tmpdir(), "mct-t28n-"));
});

afterEach(async () => {
	await rm(empty, { recursive: true, force: true });
});

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

describe("VER-003 no Docker", () => {
	it("VER-003 no docker executable on PATH exits DOCKER_NO_DISPONIBLE", async () => {
		const err = await errOf(resolveDocker({ env: { PATH: empty } }));
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
		expect(err.exit).toBe(13);
	});

	it("VER-003 a daemon that does not answer exits DOCKER_NO_DISPONIBLE", async () => {
		const run: Runner = async () => ({
			code: 1,
			stdout: "",
			stderr: "failed to connect to the docker API: the daemon is not running",
		});
		const err = await errOf(
			resolveDocker({ dockerPath: "/usr/bin/docker", run, env: {} }),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
		expect(err.detalle?.motivo).toBe("sin-docker");
	});

	it("VER-003 a runner that throws is also DOCKER_NO_DISPONIBLE", async () => {
		const run: Runner = async () => {
			throw new Error("spawn failed");
		};
		const err = await errOf(
			resolveDocker({ dockerPath: "/usr/bin/docker", run, env: {} }),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
	});

	it("VER-003 a working local daemon is used", async () => {
		const run: Runner = async () => ({ code: 0, stdout: "27.0.1", stderr: "" });
		const t = await resolveDocker({
			dockerPath: "/usr/bin/docker",
			run,
			env: {},
		});
		expect(t.kind).toBe("local");
	});

	it("VER-003 --local never tries the configured remote", async () => {
		const files: string[] = [];
		const run: Runner = async (file) => {
			files.push(file);
			return { code: 0, stdout: "27.0.1", stderr: "" };
		};
		await resolveDocker({
			local: true,
			configRemote: "servidor-casa",
			dockerPath: "/usr/bin/docker",
			sshPath: "/usr/bin/ssh",
			run,
			env: {},
		});
		expect(files).toEqual(["/usr/bin/docker"]);
	});
});

describe("VER-003 env and missing ssh", () => {
	it("VER-003 DOCKER_HOST and context vars reach the probe and the target", async () => {
		const seen: Record<string, string>[] = [];
		const run: Runner = async (_f, _a, o) => {
			seen.push({ ...(o?.env ?? {}) });
			return { code: 0, stdout: "27.0.1", stderr: "" };
		};
		const host = ["unix", ":///run/user/1000/docker.sock"].join("");
		const t = await resolveDocker({
			dockerPath: "/usr/bin/docker",
			run,
			env: {
				DOCKER_HOST: host,
				DOCKER_CONTEXT: "colima",
				XDG_RUNTIME_DIR: "/run/user/1000",
			},
		});
		expect(seen[0]?.DOCKER_HOST).toBe(host);
		expect(t.env.DOCKER_HOST).toBe(host);
		expect(t.env.DOCKER_CONTEXT).toBe("colima");
		expect(t.env.XDG_RUNTIME_DIR).toBe("/run/user/1000");
	});

	it("TMO-003 no ssh with a config alias and no Docker is DOCKER_NO_DISPONIBLE", async () => {
		const err = await errOf(
			resolveDocker({ configRemote: "servidor-casa", env: { PATH: empty } }),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
	});

	it("TMO-003 no ssh with a config alias falls back to local Docker", async () => {
		const run: Runner = async () => ({ code: 0, stdout: "27.0.1", stderr: "" });
		const t = await resolveDocker({
			configRemote: "servidor-casa",
			dockerPath: "/usr/bin/docker",
			run,
			env: { PATH: empty },
		});
		expect(t.kind).toBe("local");
	});

	it("TMO-003 no ssh with --remote is DOCKER_NO_DISPONIBLE sin-ssh", async () => {
		const run: Runner = async () => ({ code: 0, stdout: "27.0.1", stderr: "" });
		const err = await errOf(
			resolveDocker({
				remote: "servidor-casa",
				dockerPath: "/usr/bin/docker",
				run,
				env: { PATH: empty },
			}),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
		expect(err.detalle?.motivo).toBe("sin-ssh");
	});
});
