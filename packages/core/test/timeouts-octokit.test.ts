import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import {
	createGithubClient,
	GITHUB_CALL_TIMEOUT_MS,
	GITHUB_MAX_RETRIES,
} from "../src/github.js";

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

describe("TMO-001 octokit timeouts", () => {
	it("TMO-001 a call that hangs is cut and retried 3 times with growing backoff", async () => {
		let calls = 0;
		const fetchFn = (_u: unknown, init?: RequestInit) => {
			calls++;
			return new Promise<Response>((_, reject) => {
				init?.signal?.addEventListener("abort", () =>
					reject(new Error("aborted")),
				);
			});
		};
		const waits: number[] = [];
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn as typeof fetch,
			timeoutMs: 20,
			sleep: async (ms) => {
				waits.push(ms);
			},
		});
		const err = await errOf(client.request("GET /user"));
		expect(calls).toBe(4);
		expect(waits).toEqual([1000, 2000, 4000]);
		expect(err.codigo).toBe("INTERNO");
	});

	it("TMO-001 the limits are 30 s and 3 retries", () => {
		expect(GITHUB_CALL_TIMEOUT_MS).toBe(30_000);
		expect(GITHUB_MAX_RETRIES).toBe(3);
	});

	it("TMO-001 a 5xx is retried and a later success returns", async () => {
		let n = 0;
		const fetchFn = async () =>
			++n < 3 ? reply(502) : reply(200, {}, { ok: true });
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: async () => undefined,
		});
		const res = await client.request("GET /user");
		expect(res.status).toBe(200);
		expect(n).toBe(3);
	});
});
