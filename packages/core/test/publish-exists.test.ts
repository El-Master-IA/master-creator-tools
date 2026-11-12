import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import type { GithubClient } from "../src/github.js";
import { checkRepoAbsent } from "../src/publish-gates.js";

function clientWith(
	handler: (
		route: string,
		params?: Record<string, unknown>,
	) => Promise<{ status: number; data: unknown }>,
	log: Array<{ route: string; params?: Record<string, unknown> }>,
): GithubClient {
	return {
		tokenSource: "GITHUB_TOKEN",
		rateRemaining: undefined,
		request: async (route, params) => {
			log.push({ route, ...(params !== undefined && { params }) });
			const res = await handler(route, params);
			return { status: res.status, headers: {}, data: res.data };
		},
		checkPermissions: async () => undefined,
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

describe("PUB-004 repo exists", () => {
	it("PUB-004 an existing repo aborts with VALIDACION and only reads", async () => {
		const log: Array<{ route: string }> = [];
		const client = clientWith(
			async () => ({ status: 200, data: { id: 42 } }),
			log,
		);
		const err = await errOf(
			checkRepoAbsent(client, "dueno/proyecto", undefined),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(log.map((l) => l.route)).toEqual(["GET /repos/{owner}/{repo}"]);
	});

	it("PUB-004 a 404 means the repo is free", async () => {
		const log: Array<{ route: string }> = [];
		const client = clientWith(async () => {
			throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
		}, log);
		await expect(
			checkRepoAbsent(client, "dueno/proyecto", undefined),
		).resolves.toBe("nuevo");
	});

	it("PUB-004 --resume on our own repo (same repoId) is allowed", async () => {
		const client = clientWith(
			async () => ({ status: 200, data: { id: 42 } }),
			[],
		);
		await expect(checkRepoAbsent(client, "dueno/proyecto", 42)).resolves.toBe(
			"reanudar",
		);
	});

	it("PUB-004 --resume on a repo with another id aborts", async () => {
		const client = clientWith(
			async () => ({ status: 200, data: { id: 7 } }),
			[],
		);
		const err = await errOf(checkRepoAbsent(client, "dueno/proyecto", 42));
		expect(err.codigo).toBe("VALIDACION");
	});

	it("PUB-004 any other failure propagates, never read as absent", async () => {
		const client = clientWith(async () => {
			throw new MctError("LIMITE_GITHUB", "limite");
		}, []);
		const err = await errOf(
			checkRepoAbsent(client, "dueno/proyecto", undefined),
		);
		expect(err.codigo).toBe("LIMITE_GITHUB");
	});

	it("PUB-004 a 500 error is not read as absent", async () => {
		const client = clientWith(async () => {
			throw new MctError("INTERNO", "fallo", { detalle: { estado: 500 } });
		}, []);
		const err = await errOf(
			checkRepoAbsent(client, "dueno/proyecto", undefined),
		);
		expect(err.codigo).toBe("INTERNO");
	});

	it("PUB-004 owner and name go as parameters, not in the route", async () => {
		const log: Array<{ route: string; params?: Record<string, unknown> }> = [];
		const client = clientWith(async () => {
			throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
		}, log);
		await checkRepoAbsent(client, "dueno/proyecto", undefined);
		expect(log[0]?.params).toEqual({ owner: "dueno", repo: "proyecto" });
	});
});
