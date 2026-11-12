import {
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseGithubUrl, type Runner } from "../src/clone.js";
import { initFromSource } from "../src/init.js";

let base: string;
let dest: string;
let calls: { file: string; args: readonly string[] }[];

const exists = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

/** Fake git: writes a small repo (with .git) into the last argv entry. */
const fakeGit: Runner = async (file, args) => {
	calls.push({ file, args });
	// gh puts the folder in args[3]; git puts it last.
	const dir = (args[0] === "repo" ? args[3] : args[args.length - 1]) as string;
	await mkdir(join(dir, ".git"), { recursive: true });
	await writeFile(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
	await writeFile(
		join(dir, "package.json"),
		JSON.stringify({ name: "demo", version: "1.0.0", main: "i.js" }),
	);
	await writeFile(join(dir, "i.js"), "module.exports = 1;\n");
	return { code: 0, stdout: "", stderr: "" };
};

function opts(extra: Record<string, unknown> = {}) {
	return {
		origen: "https://github.com/octo/demo",
		dest,
		isTTY: false,
		mctVersion: "0.0.0",
		home: join(base, "home"),
		env: {},
		clon: { run: fakeGit, gitPath: join(base, "git-fake") },
		...extra,
	};
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t21-"));
	dest = join(base, "dest");
	await mkdir(dest, { recursive: true });
	calls = [];
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-002 init from a GitHub URL", () => {
	it("CLI-002 rejects every URL that is not https://github.com/<owner>/<repo>", async () => {
		const bad = [
			"http://github.com/octo/demo",
			"https://gitlab.com/octo/demo",
			"https://github.com.evil.io/octo/demo",
			"https://evil.io/github.com/octo/demo",
			"https://user@github.com/octo/demo",
			"https://github.com:444/octo/demo",
			"https://github.com/octo",
			"https://github.com/octo/demo/tree/main",
			"https://github.com/octo/demo?x=1",
			"https://github.com/octo/..",
			"https://github.com/-octo/demo",
			"git@github.com:octo/demo.git",
			"ssh://git@github.com/octo/demo",
			"file:///etc/passwd",
			`https://github.com/octo/${"a".repeat(101)}`,
		];
		for (const origen of bad) {
			const err = await errOf(initFromSource(opts({ origen })));
			expect(err.codigo, origen).toBe("VALIDACION");
		}
		expect(calls).toHaveLength(0);
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-002 accepts the canonical URL, with .git or a trailing slash", () => {
		for (const u of [
			"https://github.com/octo/demo",
			"https://github.com/octo/demo.git",
			"https://github.com/octo/demo/",
		]) {
			expect(parseGithubUrl(u)).toEqual({
				owner: "octo",
				repo: "demo",
				url: "https://github.com/octo/demo",
			});
		}
	});

	it("CLI-002 parses a pathological URL in linear time", () => {
		const t0 = Date.now();
		expect(() =>
			parseGithubUrl(`https://github.com/octo/${"a.".repeat(40_000)}!`),
		).toThrow(MctError);
		expect(Date.now() - t0).toBeLessThan(500);
	});

	it("CLI-002 clones shallow, without hooks, submodules or LFS", async () => {
		await initFromSource(opts());
		expect(calls).toHaveLength(1);
		const args = calls[0]?.args ?? [];
		const line = args.join(" ");
		expect(args).toContain("clone");
		expect(line).toContain("--depth 1");
		expect(line).toContain("--no-recurse-submodules");
		expect(line).toContain("core.hooksPath=/dev/null");
		expect(line).toContain("filter.lfs.required=false");
		expect(line).toContain("protocol.file.allow=never");
		expect(args).toContain("https://github.com/octo/demo");
	});

	it("CLI-002 leaves work/ without .git and records origen github", async () => {
		const res = await initFromSource(opts());
		expect(res.adapter).toBe("node");
		expect(await exists(join(res.workspace.work, "package.json"))).toBe(true);
		expect(await exists(join(res.workspace.work, ".git"))).toBe(false);
		const state = JSON.parse(
			await readFile(join(dest, ".mct", "state.json"), "utf8"),
		) as { origen: { tipo: string; ref: string } };
		expect(state.origen).toEqual({
			tipo: "github",
			ref: "https://github.com/octo/demo",
		});
	});

	it("CLI-002 deletes the temp clone folder after init", async () => {
		const res = await initFromSource(opts());
		const cloned = dirname(calls[0]?.args.at(-1) as string);
		expect(await exists(cloned)).toBe(false);
		expect(res.archivos).toBeGreaterThan(0);
	});

	it("CLI-002 fails closed when git exits non-zero and leaves no workspace", async () => {
		const failing: Runner = async () => ({
			code: 128,
			stdout: "",
			stderr: "fatal: repository not found",
		});
		const err = await errOf(
			initFromSource(
				opts({ clon: { run: failing, gitPath: join(base, "g") } }),
			),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-002 fails closed when the runner throws", async () => {
		const boom: Runner = async () => {
			throw new Error("spawn failed");
		};
		const err = await errOf(
			initFromSource(opts({ clon: { run: boom, gitPath: join(base, "g") } })),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("CLI-002 falls back to gh only without a token and when git fails", async () => {
		const seen: string[] = [];
		const run: Runner = async (file, args, o) => {
			seen.push(file);
			if (file.endsWith("git-fake")) {
				return { code: 128, stdout: "", stderr: "denied" };
			}
			return fakeGit(file, args, o);
		};
		const res = await initFromSource(
			opts({
				clon: {
					run,
					gitPath: join(base, "git-fake"),
					ghPath: join(base, "gh-fake"),
				},
			}),
		);
		expect(seen).toEqual([join(base, "git-fake"), join(base, "gh-fake")]);
		expect(res.adapter).toBe("node");
		expect(calls[0]?.args.slice(0, 3)).toEqual(["repo", "clone", "octo/demo"]);
	});
});
