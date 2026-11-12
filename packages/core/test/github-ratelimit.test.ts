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

const noSleep =
	(log: number[] = []) =>
	async (ms: number) => {
		log.push(ms);
	};

describe("PUB-007 rate limit", () => {
	it("PUB-007 429 on every attempt: 4 calls, 3 waits, then LIMITE_GITHUB", async () => {
		let calls = 0;
		const waits: number[] = [];
		const fetchFn = async () => {
			calls++;
			return reply(
				429,
				{ "retry-after": "2", "x-ratelimit-remaining": "0" },
				{ message: "rate limit" },
			);
		};
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: noSleep(waits),
		});
		const err = await errOf(client.request("GET /user"));
		expect(err.codigo).toBe("LIMITE_GITHUB");
		expect(err.exit).toBe(15);
		expect(calls).toBe(4);
		expect(waits).toEqual([2000, 2000, 2000]);
		expect(client.rateRemaining).toBe(0);
	});

	it("PUB-007 secondary 403 with retry-after is retried, then succeeds", async () => {
		let calls = 0;
		const fetchFn = async () => {
			calls++;
			return calls < 3
				? reply(
						403,
						{ "retry-after": "1" },
						{ message: "You have exceeded a secondary rate limit" },
					)
				: reply(200, { "x-ratelimit-remaining": "4999" }, { login: "x" });
		};
		const waits: number[] = [];
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: noSleep(waits),
		});
		const res = await client.request("GET /user");
		expect(res.status).toBe(200);
		expect(waits).toEqual([1000, 1000]);
		expect(client.rateRemaining).toBe(4999);
	});

	it("PUB-007 a plain 403 is a permission failure and is not retried", async () => {
		let calls = 0;
		const fetchFn = async () => {
			calls++;
			return reply(
				403,
				{},
				{ message: "Resource not accessible by personal access token" },
			);
		};
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: noSleep(),
		});
		const err = await errOf(client.request("GET /user"));
		expect(err.codigo).toBe("PERMISO_INSUFICIENTE");
		expect(calls).toBe(1);
	});

	it("PUB-007 a retry-after above the cap fails closed without waiting", async () => {
		const waits: number[] = [];
		const fetchFn = async () =>
			reply(429, { "retry-after": "3600" }, { message: "rate limit" });
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: noSleep(waits),
		});
		const err = await errOf(client.request("GET /user"));
		expect(err.codigo).toBe("LIMITE_GITHUB");
		expect(waits).toEqual([]);
	});

	it("PUB-007 without retry-after it uses x-ratelimit-reset, else exponential backoff", async () => {
		const waits: number[] = [];
		let n = 0;
		const fetchFn = async () => {
			n++;
			if (n === 1) {
				return reply(
					403,
					{ "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1010" },
					{ message: "API rate limit exceeded" },
				);
			}
			return n === 2 ? reply(429) : reply(200);
		};
		const client = await createGithubClient({
			env: ENV,
			fetch: fetchFn,
			sleep: noSleep(waits),
			now: () => 1_000_000,
		});
		await client.request("GET /user");
		expect(waits).toEqual([10_000, 2000]);
	});
});
