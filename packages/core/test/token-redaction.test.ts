import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import { createGithubClient } from "../src/github.js";

// Fixture built from fragments so no literal token sits in the repo (T05).
const TOKEN = ["gh", "p_", "Ab1Cd2Ef3Gh4", "Ij5Kl6Mn7Op8Qr9St0Uv1"].join("");
const ENV = { GITHUB_TOKEN: TOKEN };

const reply = (
	status: number,
	headers: Record<string, string> = {},
	body: unknown = {},
) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8", ...headers },
	});

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

describe("PUB-005 token redaction", () => {
	it("PUB-005 an Octokit error never carries the token", async () => {
		const fetchFn = async () =>
			reply(422, {}, { message: `bad credentials ${TOKEN}` });
		const client = await createGithubClient({ env: ENV, fetch: fetchFn });
		const err = await errOf(client.request("GET /user"));
		expect(err.codigo).toBe("INTERNO");
		expect(JSON.stringify(err.toJSON())).not.toContain(TOKEN);
		expect(err.message).not.toContain(TOKEN);
	});

	it("PUB-005 a network error that echoes the token is redacted", async () => {
		const fetchFn = async () => {
			throw new Error(`connect failed for ${TOKEN}`);
		};
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: async () => undefined,
		});
		const err = await errOf(client.request("GET /user"));
		expect(JSON.stringify(err.toJSON())).not.toContain(TOKEN);
		expect(String(err.stack)).not.toContain(TOKEN);
	});

	it("PUB-005 reads GITHUB_TOKEN, then GH_TOKEN, then gh auth", async () => {
		const seen: string[] = [];
		const fetchFn = async (_u: unknown, init?: RequestInit) => {
			seen.push(new Headers(init?.headers).get("authorization") ?? "");
			return reply(200);
		};
		const a = await createGithubClient({ env: ENV, fetch: fetchFn });
		await a.request("GET /user");
		expect(a.tokenSource).toBe("GITHUB_TOKEN");
		expect(seen[0]).toContain(TOKEN);
		const b = await createGithubClient({
			env: { GH_TOKEN: TOKEN },
			fetch: fetchFn,
		});
		expect(b.tokenSource).toBe("GH_TOKEN");
		const c = await createGithubClient({
			env: { PATH: "C:/fake" },
			ghPath: "C:/fake/gh.exe",
			run: async (_f, args) => ({
				code: 0,
				stdout: args.join(" ") === "auth token" ? `${TOKEN}\n` : "",
				stderr: "",
			}),
			fetch: fetchFn,
		});
		expect(c.tokenSource).toBe("gh");
	});

	it("PUB-005 gh auth token gets its config variables and nothing else", async () => {
		let seenEnv: Record<string, string | undefined> = {};
		await createGithubClient({
			env: {
				PATH: "C:/fake",
				HOME: "C:/home",
				APPDATA: "C:/appdata",
				GH_CONFIG_DIR: "C:/ghcfg",
				SystemRoot: "C:/Windows",
				UNRELATED_VAR: "x",
			},
			ghPath: "C:/fake/gh.exe",
			run: async (_f, _a, options) => {
				seenEnv = options.env;
				return {
					code: 0,
					stdout: `${TOKEN}
`,
					stderr: "",
				};
			},
		});
		expect(seenEnv.HOME).toBe("C:/home");
		expect(seenEnv.APPDATA).toBe("C:/appdata");
		expect(seenEnv.GH_CONFIG_DIR).toBe("C:/ghcfg");
		expect(seenEnv.SystemRoot).toBe("C:/Windows");
		expect(seenEnv.UNRELATED_VAR).toBeUndefined();
	});

	it("PUB-005 no credential is SIN_CREDENCIAL, and a malformed one is refused", async () => {
		const none = await errOf(
			createGithubClient({
				env: {},
				ghPath: "C:/fake/gh.exe",
				run: async () => ({ code: 1, stdout: "", stderr: "" }),
			}),
		);
		expect(none.codigo).toBe("SIN_CREDENCIAL");
		const bad = await errOf(
			createGithubClient({ env: { GITHUB_TOKEN: "no good\nvalue" } }),
		);
		expect(bad.codigo).toBe("SIN_CREDENCIAL");
		expect(JSON.stringify(bad.toJSON())).not.toContain("no good");
	});
});
