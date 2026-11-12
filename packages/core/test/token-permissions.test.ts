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

describe("PUB-009 token permissions", () => {
	it("PUB-009 a classic token without repo scope is PERMISO_INSUFICIENTE and only reads", async () => {
		const methods: string[] = [];
		const fetchFn = async (_u: unknown, init?: RequestInit) => {
			methods.push(init?.method ?? "GET");
			return reply(
				200,
				{ "x-oauth-scopes": "read:user, gist" },
				{ login: "x" },
			);
		};
		const client = await createGithubClient({ env: ENV, fetch: fetchFn });
		const err = await errOf(client.checkPermissions());
		expect(err.codigo).toBe("PERMISO_INSUFICIENTE");
		expect(err.exit).toBe(16);
		expect(err.detalle?.faltan).toEqual([
			"Administration: write",
			"Contents: write",
		]);
		expect(methods).toEqual(["GET"]);
	});

	it("PUB-009 a token with the repo scope passes", async () => {
		const fetchFn = async () =>
			reply(200, { "x-oauth-scopes": "repo, read:org" }, { login: "x" });
		const client = await createGithubClient({ env: ENV, fetch: fetchFn });
		await expect(client.checkPermissions()).resolves.toBeUndefined();
	});

	it("PUB-009 permissions that cannot be read fail closed", async () => {
		const fetchFn = async () => reply(200, {}, { login: "x" });
		const client = await createGithubClient({ env: ENV, fetch: fetchFn });
		const err = await errOf(client.checkPermissions());
		expect(err.codigo).toBe("PERMISO_INSUFICIENTE");
		expect(err.detalle?.motivo).toBe("no-verificable");
	});

	it("PUB-009 a fine-grained token fails closed as no-verificable and only reads", async () => {
		const fg = ["github", "_pat_", "Ab1Cd2Ef3Gh4", "Ij5Kl6Mn7Op8Qr9St0"].join(
			"",
		);
		const methods: string[] = [];
		const fetchFn = async (_u: unknown, init?: RequestInit) => {
			methods.push(init?.method ?? "GET");
			return reply(200, {}, { login: "x" });
		};
		const client = await createGithubClient({
			env: { GITHUB_TOKEN: fg },
			fetch: fetchFn,
		});
		const err = await errOf(client.checkPermissions());
		expect(err.codigo).toBe("PERMISO_INSUFICIENTE");
		expect(err.detalle?.motivo).toBe("no-verificable");
		expect(methods).toEqual(["GET"]);
	});

	it("PUB-009 a fine-grained token rejected on the probe is still refused", async () => {
		const fg = ["github", "_pat_", "Ab1Cd2Ef3Gh4", "Ij5Kl6Mn7Op8Qr9St0"].join(
			"",
		);
		const fetchFn = async () => reply(403, {}, { message: "Forbidden" });
		const client = await createGithubClient({
			env: { GITHUB_TOKEN: fg },
			fetch: fetchFn,
		});
		const err = await errOf(client.checkPermissions());
		expect(err.codigo).toBe("PERMISO_INSUFICIENTE");
	});

	it("PUB-009 a 401 on the probe is SIN_CREDENCIAL", async () => {
		const fetchFn = async () => reply(401, {}, { message: "Bad credentials" });
		const client = await createGithubClient({ env: ENV, fetch: fetchFn });
		const err = await errOf(client.checkPermissions());
		expect(err.codigo).toBe("SIN_CREDENCIAL");
	});
});
