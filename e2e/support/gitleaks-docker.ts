import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Runner } from "../../packages/scanner/src/gitleaks.js";

/** Official image pinned by tag (same digest as the GitHub release 8.30.1). */
export const GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1";

interface Out {
	readonly code: number | null;
	readonly stdout: string;
}

function docker(args: readonly string[], cwd?: string): Promise<Out> {
	return new Promise((resolvePromise) => {
		let stdout = "";
		const child = spawn("docker", [...args], {
			...(cwd === undefined ? {} : { cwd }),
			env: process.env,
			stdio: ["ignore", "pipe", "ignore"],
			windowsHide: true,
		});
		child.stdout.on("data", (c: Buffer) => {
			stdout += c.toString("utf8");
		});
		child.on("error", () => resolvePromise({ code: null, stdout }));
		child.on("close", (code) => resolvePromise({ code, stdout }));
	});
}

function value(args: readonly string[], flag: string): string {
	const i = args.indexOf(flag);
	return i < 0 ? "" : String(args[i + 1]);
}

/**
 * Runner that executes the real gitleaks image on the Docker of `DOCKER_HOST`
 * (ssh://servidor-casa). Nothing is mounted: the target and the config are
 * copied into a created container with `docker cp`, and the report comes back
 * the same way, with its paths rewritten to the local target.
 */
export const dockerGitleaksRunner: Runner = async (_command, args) => {
	if (args.includes("version")) {
		const r = await docker(["run", "--rm", GITLEAKS_IMAGE, "version"]);
		return { code: r.code, signal: null, stdout: r.stdout, timedOut: false };
	}
	const target = value(args, "dir");
	const config = value(args, "--config");
	const ignoreDir = value(args, "--gitleaks-ignore-path");
	const reportPath = value(args, "--report-path");
	const stage = await mkdtemp(join(tmpdir(), "mct-gl-"));
	let id = "";
	try {
		await cp(target, join(stage, "t"), { recursive: true });
		await mkdir(join(stage, "c"), { recursive: true });
		await cp(config, join(stage, "c", "gitleaks.toml"));
		const mapped = [...args].map((a) => {
			if (a === target) return "/t";
			if (a === config) return "/c/gitleaks.toml";
			if (a === ignoreDir) return "/c";
			if (a === reportPath) return "/r.json";
			return a;
		});
		const created = await docker(["create", GITLEAKS_IMAGE, ...mapped]);
		if (created.code !== 0) return fail();
		id = created.stdout.trim();
		const copied = await docker(["cp", ".", `${id}:/`], stage);
		if (copied.code !== 0) return fail();
		const ran = await docker(["start", "-a", id]);
		const back = await docker(["cp", `${id}:/r.json`, "r.json"], stage);
		if (back.code === 0) {
			const raw = JSON.parse(await readFile(join(stage, "r.json"), "utf8")) as {
				File?: string;
			}[];
			for (const f of raw) {
				if (typeof f.File === "string" && f.File.startsWith("/t/")) {
					f.File = join(target, f.File.slice(3));
				}
			}
			await writeFile(reportPath, JSON.stringify(raw));
		}
		return {
			code: ran.code,
			signal: null,
			stdout: ran.stdout,
			timedOut: false,
		};
	} finally {
		if (id !== "") await docker(["rm", "-f", id]);
		await rm(stage, { recursive: true, force: true });
	}
};

function fail() {
	return { code: null, signal: null, stdout: "", timedOut: false } as const;
}
