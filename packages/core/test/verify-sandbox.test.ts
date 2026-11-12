import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import {
	type DockerTarget,
	installCreateArgs,
	runSandbox,
	sshWrapperScript,
	startRunArgs,
} from "../src/docker.js";

let base: string;
let dist: string;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t28s-"));
	dist = join(base, "dist");
	await mkdir(dist);
	await writeFile(join(dist, "index.js"), "console.info(1);\n");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const target: DockerTarget = {
	kind: "local",
	dockerPath: "/usr/bin/docker",
	env: { PATH: "/usr/bin" },
};

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

describe("VER-001 sandbox arguments", () => {
	it("VER-001 every container drops all caps, is not root and is capped", () => {
		for (const args of [
			installCreateArgs("a", "node:22", "npm ci"),
			startRunArgs("b", "img:1", "npm start"),
		]) {
			expect(args).toContain("--cap-drop=ALL");
			expect(args).toContain("no-new-privileges");
			expect(args[args.indexOf("--user") + 1]).toBe("1000:1000");
			expect(args).toContain("--memory");
			expect(args).toContain("--cpus");
			expect(args).toContain("--pids-limit");
			expect(args).not.toContain("--privileged");
		}
	});

	it("VER-001 the start phase uses --network none and install does not", () => {
		const start = startRunArgs("b", "img:1", "npm start");
		expect(start[start.indexOf("--network") + 1]).toBe("none");
		expect(installCreateArgs("a", "node:22", "npm ci")).not.toContain(
			"--network",
		);
	});

	it("VER-001 installs with network, copies dist with docker cp and starts with --network none", async () => {
		const { calls, run } = recorder();
		const out = await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		expect(out.install.code).toBe(0);
		expect(out.start?.code).toBe(0);
		expect(calls.map((c) => c[0]).slice(0, 5)).toEqual([
			"create",
			"cp",
			"start",
			"commit",
			"run",
		]);
		const started = calls.find((c) => c[0] === "run") as string[];
		expect(started[started.indexOf("--network") + 1]).toBe("none");
		expect(started).toContain("--cap-drop=ALL");
		const create = calls.find((c) => c[0] === "create") as string[];
		expect(create).not.toContain("--network");
	});

	it("VER-001 no bind mount, no socket, no host env", async () => {
		const { calls, run } = recorder();
		await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		const all = calls.flat();
		for (const bad of ["-v", "--volume", "--mount", "--env-file", "-e"]) {
			expect(all).not.toContain(bad);
		}
		expect(all.join(" ")).not.toContain("docker.sock");
		const create = calls.find((c) => c[0] === "create") as string[];
		const envs = create.filter((_, i) => create[i - 1] === "--env");
		expect(envs).toEqual(["HOME=/tmp"]);
	});

	it("VER-001 a failing install does not start anything and cleans up", async () => {
		const { calls, run } = recorder({ start: 1 });
		const out = await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		expect(out.start).toBeNull();
		expect(calls.some((c) => c[0] === "run")).toBe(false);
		expect(calls.filter((c) => c[0] === "rm").length).toBe(2);
	});

	it("VER-001 a failing docker step is an error, never a pass", async () => {
		const { run } = recorder({ create: 1 });
		const err = await errOf(
			runSandbox({
				target,
				image: "node:22",
				distDir: dist,
				installCommand: "npm ci",
				startCommand: "npm start",
				run,
			}),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
	});

	it("VER-001 rejects a bad image name and a linked dist", async () => {
		const { run } = recorder();
		const common = {
			target,
			distDir: dist,
			installCommand: "x",
			startCommand: "y",
			run,
		};
		const bad = await errOf(runSandbox({ ...common, image: "--privileged" }));
		expect(bad.codigo).toBe("VALIDACION");
		const link = join(base, "link");
		await symlink(dist, link, "junction");
		const linked = await errOf(
			runSandbox({ ...common, image: "node:22", distDir: link }),
		);
		expect(linked.codigo).toBe("VALIDACION");
	});
});

describe("VER-001 sandbox ownership and entrypoint", () => {
	it("VER-001 overrides the image entrypoint with sh before the image", () => {
		for (const args of [
			installCreateArgs("a", "n8nio/n8n:1", "echo hi"),
			startRunArgs("b", "img:1", "echo hi"),
		]) {
			const e = args.indexOf("--entrypoint");
			const img = args.findIndex((a) => a === "n8nio/n8n:1" || a === "img:1");
			expect(e).toBeGreaterThan(-1);
			expect(args[e + 1]).toBe("sh");
			expect(e).toBeLessThan(img);
			expect(args.slice(img + 1, img + 2)).toEqual(["-c"]);
			expect(args).toHaveLength(img + 3);
		}
	});

	it("VER-001 the workdir is not the root-owned copy target; uid 1000 builds its own app dir", () => {
		const create = installCreateArgs("a", "node:22", "npm ci");
		expect(create[create.indexOf("--workdir") + 1]).toBe("/tmp");
		const cmd = create[create.length - 1] as string;
		expect(cmd).toContain("mkdir -p /tmp/app");
		expect(cmd).toContain("cp -R /tmp/dist/. /tmp/app");
		expect(cmd.endsWith("npm ci")).toBe(true);
		const start = startRunArgs("b", "img:1", "npm start");
		expect(start[start.indexOf("--workdir") + 1]).toBe("/tmp");
		expect(start[start.length - 1]).toBe("cd /tmp/app && npm start");
	});

	it("VER-001 docker cp targets /tmp/dist, never the workdir", async () => {
		const { calls, run } = recorder();
		await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		const cp = calls.find((c) => c[0] === "cp") as string[];
		expect(cp[cp.length - 1]).toMatch(/^mct-install-[0-9a-f]+:\/tmp\/dist$/);
	});

	it("VER-001 docker cp sends a normalized copy without --archive, readable by uid 1000 under a private parent", async () => {
		await chmod(dist, 0o700);
		await writeFile(join(dist, "run.sh"), "#!/bin/sh\n", { mode: 0o700 });
		let staged = "";
		let seen: string[] = [];
		const run: Runner = async (_f, args) => {
			if (args[0] === "cp") {
				seen = [...args];
				staged = (args[args.length - 2] ?? "").slice(0, -2);
				if (process.platform !== "win32") {
					expect((await stat(staged)).mode & 0o777).toBe(0o755);
					// Other local users cannot reach the 0755 copy through its private parent.
					expect((await stat(dirname(staged))).mode & 0o777).toBe(0o700);
					expect((await stat(join(staged, "index.js"))).mode & 0o777).toBe(
						0o644,
					);
					expect((await stat(join(staged, "run.sh"))).mode & 0o777).toBe(0o755);
				}
				expect(
					(await readFile(join(staged, "index.js"), "utf8")).length,
				).toBeGreaterThan(0);
			}
			return { code: 0, stdout: "", stderr: "" };
		};
		await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		expect(seen).not.toContain("--archive");
		expect(staged).not.toBe(dist);
		await expect(stat(staged)).rejects.toThrow();
		await expect(stat(dirname(staged))).rejects.toThrow();
	});

	it("VER-001 a symlink inside dist is refused and the stage is removed", async () => {
		await mkdir(join(base, "other"));
		await symlink(join(base, "other"), join(dist, "link"), "junction");
		const { run } = recorder();
		const err = await errOf(
			runSandbox({
				target,
				image: "node:22",
				distDir: dist,
				installCommand: "npm ci",
				startCommand: "npm start",
				run,
			}),
		);
		expect(err.codigo).toBe("VALIDACION");
	});
});

describe("VER-006 ssh used by the Docker client", () => {
	it("VER-006 a remote sandbox puts a strict ssh wrapper first on PATH", async () => {
		const remote: DockerTarget = {
			kind: "remote",
			alias: "servidor-casa",
			dockerPath: "/usr/bin/docker",
			sshPath: "/usr/bin/ssh",
			env: { PATH: "/usr/bin", DOCKER_HOST: "ssh://servidor-casa" },
		};
		let wrapperDir = "";
		let wrapper = "";
		const run: Runner = async (_f, _a, o) => {
			const path = o?.env?.PATH ?? "";
			expect(o?.env?.DOCKER_HOST).toBe("ssh://servidor-casa");
			if (wrapperDir === "") {
				wrapperDir = path.split(delimiter)[0] ?? "";
				const name = process.platform === "win32" ? "ssh.cmd" : "ssh";
				wrapper = await readFile(join(wrapperDir, name), "utf8");
			}
			return { code: 0, stdout: "", stderr: "" };
		};
		await runSandbox({
			target: remote,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		expect(wrapper).toContain("StrictHostKeyChecking=yes");
		expect(wrapper).toContain("BatchMode=yes");
		expect(wrapper).toContain("/usr/bin/ssh");
		expect(wrapper).not.toMatch(/StrictHostKeyChecking=no|accept-new/);
		await expect(readFile(join(wrapperDir, "ssh"))).rejects.toThrow();
	});

	it("VER-006 the wrapper script injects the options before Docker's argv", () => {
		const sh = sshWrapperScript("/usr/bin/ssh", false);
		expect(sh).toContain(
			"exec '/usr/bin/ssh' -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15 \"$@\"",
		);
		expect(sshWrapperScript("/o'dd/ssh", false)).toContain(
			String.raw`exec '/o'\''dd/ssh' `,
		);
		const cmd = sshWrapperScript("C:/Windows/ssh.exe", true);
		expect(cmd).toContain(
			"-o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15 %*",
		);
	});

	it("VER-006 a local sandbox keeps its PATH untouched", async () => {
		const paths: (string | undefined)[] = [];
		const run: Runner = async (_f, _a, o) => {
			paths.push(o?.env?.PATH);
			return { code: 0, stdout: "", stderr: "" };
		};
		await runSandbox({
			target,
			image: "node:22",
			distDir: dist,
			installCommand: "npm ci",
			startCommand: "npm start",
			run,
		});
		expect(new Set(paths)).toEqual(new Set(["/usr/bin"]));
	});
});
