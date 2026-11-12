import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { hashTree } from "../src/hash.js";
import { createGitPort } from "../src/publish.js";

// Fixture token assembled from fragments: no literal secret lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);

interface Call {
	file: string;
	args: string[];
	env: Record<string, string>;
	helperExisted: boolean;
	helperBody: string;
}

let base = "";
let calls: Call[] = [];

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pub-token-"));
	calls = [];
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

function recorder(code = 0, stderr = ""): Runner {
	return async (file, args, options) => {
		const helper = options.env.GIT_ASKPASS;
		const existed = helper !== undefined && existsSync(helper);
		calls.push({
			file,
			args: [...args],
			env: { ...options.env },
			helperExisted: existed,
			helperBody: existed ? await readFile(helper as string, "utf8") : "",
		});
		// A clone creates its target folder, like git does.
		if (args.includes("clone") && code === 0) {
			const dir = args[args.length - 1] as string;
			await mkdir(join(dir, ".git"), { recursive: true });
			await writeFile(join(dir, "a.txt"), "x\n");
		}
		return { code, stdout: "", stderr };
	};
}

const { PATH, SystemRoot } = process.env;
const env = { PATH, SystemRoot };

describe("CLI-009 publish clone and push credentials", () => {
	it("CLI-009 the remote clone passes the token through an ephemeral GIT_ASKPASS, never argv or URL", async () => {
		const port = createGitPort({
			run: recorder(),
			gitPath: process.execPath,
			env,
		});
		const dir = join(base, "remote-scan");
		await port.cloneRemote({ repo: "dueno/proyecto", token: TOKEN, dir });
		expect(calls).toHaveLength(1);
		const c = calls[0] as Call;
		expect(c.args.join(" ")).not.toContain(TOKEN);
		expect(c.args.join(" ")).not.toMatch(/@github\.com|x-access-token/);
		expect(c.args).toContain("https://github.com/dueno/proyecto");
		expect(c.helperExisted).toBe(true);
		expect(c.helperBody).not.toContain(TOKEN);
		const helper = c.env.GIT_ASKPASS as string;
		expect(existsSync(helper)).toBe(false);
		expect(existsSync(join(dir, ".git"))).toBe(false);
	});

	it("CLI-009 the push passes the token through an ephemeral GIT_ASKPASS and makes one commit", async () => {
		const port = createGitPort({
			run: recorder(),
			gitPath: process.execPath,
			env,
		});
		const dist = join(base, "dist");
		await mkdir(dist, { recursive: true });
		await port.pushInitial({
			dist,
			repo: "dueno/proyecto",
			token: TOKEN,
			tmpDir: join(base, "tmp"),
			distSha256: await hashTree(dist),
		});
		const all = calls.map((c) => c.args.join(" "));
		expect(all.join("\n")).not.toContain(TOKEN);
		expect(all.join("\n")).not.toMatch(/x-access-token|\/\/[^/\s]*@/);
		const verbs = calls.map((c) =>
			c.args.find((a) => ["init", "add", "commit", "push"].includes(a)),
		);
		expect(verbs).toEqual(["init", "add", "commit", "push"]);
		const push = calls[3] as Call;
		expect(push.args).toContain("https://github.com/dueno/proyecto.git");
		expect(push.helperExisted).toBe(true);
		expect(push.helperBody).not.toContain(TOKEN);
		expect(
			calls.slice(0, 3).every((c) => c.env.GIT_ASKPASS === undefined),
		).toBe(true);
		expect(existsSync(push.env.GIT_ASKPASS as string)).toBe(false);
	});

	it("CLI-009 a failing git redacts the token from message and detail", async () => {
		const dist = join(base, "dist");
		await mkdir(dist, { recursive: true });
		const leak = `fatal: unable to access with ${TOKEN} refused`;
		const port = createGitPort({
			run: recorder(128, leak),
			gitPath: process.execPath,
			env,
		});
		const err = await port
			.pushInitial({
				dist,
				repo: "dueno/proyecto",
				token: TOKEN,
				tmpDir: join(base, "tmp"),
				distSha256: await hashTree(dist),
			})
			.then(
				() => undefined,
				(e: unknown) => e,
			);
		expect(err).toBeInstanceOf(MctError);
		const text =
			JSON.stringify((err as MctError).toJSON?.() ?? err) + String(err);
		expect(text).not.toContain(TOKEN);
		expect((err as MctError).message).not.toContain(TOKEN);
	});

	it("CLI-009 a token with an invalid shape is refused before any process starts", async () => {
		const port = createGitPort({
			run: recorder(),
			gitPath: process.execPath,
			env,
		});
		const err = await port
			.cloneRemote({
				repo: "dueno/proyecto",
				token: "a b;c",
				dir: join(base, "x"),
			})
			.then(
				() => undefined,
				(e: unknown) => e,
			);
		expect((err as MctError).codigo).toBe("VALIDACION");
		expect(calls).toHaveLength(0);
	});
});
