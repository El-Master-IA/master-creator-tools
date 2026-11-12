import {
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cloneGithub, type Runner } from "../src/clone.js";
import { initFromSource } from "../src/init.js";

// Fixture built from fragments so no literal token sits in the repo (T05).
const TOKEN = ["gh", "p_", "Ab1Cd2Ef3Gh4", "Ij5Kl6Mn7Op8Qr9St0Uv1"].join("");

let base: string;
let dest: string;

const exists = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

interface Seen {
	file: string;
	args: readonly string[];
	env: Record<string, string>;
	helper?: string;
	helperExisted?: boolean;
	helperBody?: string;
}
let seen: Seen[];

const recorder =
	(code = 0, stderr = ""): Runner =>
	async (file, args, o) => {
		const entry: Seen = { file, args, env: o.env };
		const helper = o.env.GIT_ASKPASS;
		if (helper !== undefined) {
			entry.helper = helper;
			entry.helperExisted = await exists(helper);
			entry.helperBody = await readFile(helper, "utf8");
		}
		seen.push(entry);
		const dir = args[args.length - 1] as string;
		await mkdir(dir, { recursive: true });
		await writeFile(
			join(dir, "package.json"),
			JSON.stringify({ name: "demo", version: "1.0.0", main: "i.js" }),
		);
		await writeFile(join(dir, "i.js"), "module.exports = 1;\n");
		return { code, stdout: "", stderr };
	};

function opts(run: Runner, env: Record<string, string>) {
	return {
		origen: "https://github.com/octo/private-demo",
		dest,
		isTTY: false,
		mctVersion: "0.0.0",
		home: join(base, "home"),
		env,
		clon: { run, gitPath: join(base, "git-fake") },
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
	base = await mkdtemp(join(tmpdir(), "mct-t21t-"));
	dest = join(base, "dest");
	await mkdir(dest, { recursive: true });
	seen = [];
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("CLI-009 ephemeral credential", () => {
	for (const name of ["GITHUB_TOKEN", "GH_TOKEN"]) {
		it(`CLI-009 keeps the ${name} out of argv and the URL, and uses GIT_ASKPASS`, async () => {
			await initFromSource(opts(recorder(), { [name]: TOKEN }));
			const s = seen[0] as Seen;
			expect(s.args.join("\n")).not.toContain(TOKEN);
			expect(s.file).not.toContain(TOKEN);
			expect(s.args.some((a) => a.includes("@github.com"))).toBe(false);
			expect(s.helper).toBeDefined();
			expect(s.helperExisted).toBe(true);
			// The helper reads the token from its env; the script never holds it.
			expect(s.helperBody).not.toContain(TOKEN);
			expect(s.env.GITHUB_TOKEN).toBeUndefined();
			expect(s.env.GH_TOKEN).toBeUndefined();
			expect(s.env.GIT_TERMINAL_PROMPT).toBe("0");
		});
	}

	it("CLI-009 deletes the helper when the clone ends, also if it fails", async () => {
		await initFromSource(opts(recorder(), { GITHUB_TOKEN: TOKEN }));
		expect(await exists((seen[0] as Seen).helper as string)).toBe(false);

		seen = [];
		await errOf(
			initFromSource(opts(recorder(128, "fatal"), { GITHUB_TOKEN: TOKEN })),
		);
		expect(await exists((seen[0] as Seen).helper as string)).toBe(false);
	});

	it("CLI-009 does not use gh when a token is present", async () => {
		await initFromSource(opts(recorder(), { GITHUB_TOKEN: TOKEN }));
		expect(seen).toHaveLength(1);
	});

	it("CLI-009 redacts the credential from the error message and detail", async () => {
		const leak = `fatal: Authentication failed https://x:${TOKEN}@github.com/ token ${TOKEN}`;
		const err = await errOf(
			initFromSource(opts(recorder(128, leak), { GITHUB_TOKEN: TOKEN })),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		const text = JSON.stringify(err.toJSON()) + err.message + String(err.stack);
		expect(text).not.toContain(TOKEN);
	});

	it("CLI-009 redacts a custom-shaped token that redactTokens does not know", async () => {
		const odd = ["tok", "-", "plain", "value", "12345"].join("");
		const err = await errOf(
			cloneGithub({
				url: "https://github.com/octo/demo",
				dir: join(base, "c"),
				env: { GITHUB_TOKEN: odd },
				run: recorder(128, `bad ${odd} here`),
				gitPath: join(base, "g"),
			}),
		);
		expect(JSON.stringify(err.toJSON())).not.toContain(odd);
	});

	it("CLI-009 refuses a token with unexpected characters without echoing it", async () => {
		const weird = `${TOKEN} && calc`;
		const err = await errOf(
			initFromSource(opts(recorder(), { GITHUB_TOKEN: weird })),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(err.message).not.toContain(TOKEN);
		expect(seen).toHaveLength(0);
	});

	it("CLI-009 does not persist the token in the workspace", async () => {
		const res = await initFromSource(opts(recorder(), { GITHUB_TOKEN: TOKEN }));
		const state = await readFile(join(dest, ".mct", "state.json"), "utf8");
		expect(state).not.toContain(TOKEN);
		expect(await exists(res.workspace.work)).toBe(true);
	});
});
