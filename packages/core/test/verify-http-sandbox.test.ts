import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { type DockerTarget, runSandbox } from "../src/docker.js";

let base: string;
let dist: string;

const target: DockerTarget = {
	kind: "local",
	dockerPath: "/usr/bin/docker",
	env: { PATH: "/usr/bin" },
};

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t30h-"));
	dist = join(base, "dist");
	await mkdir(dist);
	await writeFile(join(dist, "index.js"), "console.info(1);\n");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** Scripted daemon: `inspect` answers come from `states`, `exec` from `probes`. */
function daemon(states: string[], probes: number[]) {
	const calls: string[][] = [];
	const run: Runner = async (_file, args) => {
		calls.push([...args]);
		if (args[0] === "inspect") {
			return {
				code: 0,
				stdout: `${states.shift() ?? "running 0"}\n`,
				stderr: "",
			};
		}
		if (args[0] === "exec") {
			return { code: probes.shift() ?? 1, stdout: "", stderr: "" };
		}
		return { code: 0, stdout: "", stderr: "" };
	};
	return { calls, run };
}

const common = () => ({
	target,
	image: "node:22-slim",
	distDir: dist,
	installCommand: "true",
	startCommand: "node index.js",
});

async function errOf(p: Promise<unknown>): Promise<unknown> {
	return p.then(
		() => undefined,
		(e: unknown) => e,
	);
}

describe("VER-005 http healthcheck in the sandbox", () => {
	it("VER-005 a 2xx from inside the container passes, with --network none", async () => {
		const { run, calls } = daemon([], [1, 1, 0]);
		const out = await runSandbox({
			...common(),
			run,
			http: { port: 8080, intervalMs: 1 },
		});
		expect(out.via).toBe("http");
		expect(out.start?.code).toBe(0);
		const start = calls.find((c) => c[0] === "run") ?? [];
		expect(start).toContain("--detach");
		expect(start.join(" ")).toContain("--network none");
		const probe = calls.filter((c) => c[0] === "exec");
		expect(probe).toHaveLength(3);
		expect(probe[0]?.join(" ")).toContain("http://127.0.0.1:8080/");
		expect(calls.some((c) => c[0] === "rm" && c.includes("--force"))).toBe(
			true,
		);
	});

	it("VER-005 a server that exits 0 before answering also passes", async () => {
		const { run } = daemon(["running 0", "exited 0"], [1]);
		const out = await runSandbox({
			...common(),
			run,
			http: { port: 3000, intervalMs: 1 },
		});
		expect(out.via).toBe("salida");
		expect(out.start?.code).toBe(0);
	});

	it("VER-005 a server that crashes reports its exit code", async () => {
		const { run } = daemon(["exited 3"], []);
		const out = await runSandbox({
			...common(),
			run,
			http: { port: 3000, intervalMs: 1 },
		});
		expect(out.start?.code).toBe(3);
	});

	it("VER-005 a port outside 1..65535 is refused before touching Docker", async () => {
		const { run, calls } = daemon([], []);
		const err = await errOf(
			runSandbox({ ...common(), run, http: { port: 70000 } }),
		);
		expect(err).toBeInstanceOf(MctError);
		expect(calls).toHaveLength(0);
	});

	it("VER-005 a cancelled wait is INTERRUMPIDO", async () => {
		const ctrl = new AbortController();
		const { run } = daemon([], []);
		const slow: Runner = async (f, a, o) => {
			if (a[0] === "exec") ctrl.abort();
			return run(f, a, o);
		};
		const err = await errOf(
			runSandbox({
				...common(),
				run: slow,
				signal: ctrl.signal,
				http: { port: 3000, intervalMs: 1 },
			}),
		);
		expect((err as MctError).codigo).toBe("INTERRUMPIDO");
	});
});
