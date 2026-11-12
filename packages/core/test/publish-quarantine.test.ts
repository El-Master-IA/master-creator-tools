import { lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Runner } from "@mct/scanner/gitleaks";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GithubClient } from "../src/github.js";
import { hashTree } from "../src/hash.js";
import {
	type PublishGit,
	type PublishOptions,
	publish,
} from "../src/publish.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

// Fixture values are assembled from fragments: no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const TERM = ["zq", "client", "x9"].join("");
const SHA = "b".repeat(40);

let base = "";
let raiz = "";
let home = "";
let calls: Array<{ route: string; params?: Record<string, unknown> }> = [];
let cloneBody = "hola\n";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pub-quar-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	await mkdir(join(home, ".mct"), { recursive: true });
	calls = [];
	cloneBody = "hola\n";
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

async function build(): Promise<void> {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "node",
	});
	await writeFile(join(ws.work, "a.txt"), "hola work\n");
	await writeFile(join(ws.dist, "b.txt"), "hola dist\n");
	await mkdir(ws.quarantine, { recursive: true });
	await writeFile(join(ws.quarantine, ".env"), "NOMBRE=valor\n");
	const work = await hashTree(ws.work);
	const dist = await hashTree(ws.dist);
	const state = await readState(raiz);
	for (const e of Object.keys(state.etapas) as Array<
		keyof typeof state.etapas
	>) {
		if (e !== "publish") state.etapas[e].estado = "ok";
	}
	state.workSha256 = work;
	state.distSha256 = dist;
	state.verificado = {
		distSha256: dist,
		destino: "local",
		ts: "2026-11-08T00:00:00Z",
	};
	await writeState(raiz, state);
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({ schemaVersion: 1, hallazgos: [] }),
	);
	await writeFile(join(raiz, "license-report.json"), "[]");
	await writeFile(
		join(raiz, "approval.json"),
		JSON.stringify({ schemaVersion: 1, arbolSha256: work }),
	);
}

function fakeClient(): GithubClient {
	let created = false;
	return {
		tokenSource: "GITHUB_TOKEN",
		rateRemaining: undefined,
		request: async (route, params) => {
			calls.push({ route, ...(params !== undefined && { params }) });
			const ok = (data: unknown) => ({ status: 200, headers: {}, data });
			switch (route) {
				case "GET /user":
					return ok({ login: "dueno" });
				case "GET /repos/{owner}/{repo}":
					if (!created) {
						throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
					}
					return ok({ id: 9, private: true });
				case "POST /user/repos":
					created = true;
					return ok({ id: 9, private: params?.private === true });
				case "GET /repos/{owner}/{repo}/commits/{ref}":
					return ok({ sha: SHA });
				default:
					return ok({});
			}
		},
		checkPermissions: async () => {
			calls.push({ route: "permissions" });
		},
	};
}

const fakeGit: PublishGit = {
	pushInitial: async () => undefined,
	cloneRemote: async ({ dir }) => {
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "b.txt"), cloneBody);
	},
};

function opts(over: Partial<PublishOptions> = {}): PublishOptions {
	return {
		raiz,
		repo: "dueno/proyecto",
		client: fakeClient(),
		git: fakeGit,
		token: TOKEN,
		home,
		lang: "es",
		confirmarPublico: async () => true,
		gitleaks: {
			binary: process.execPath,
			installDir: join(base, "bin"),
			run: okRunner,
		},
		...over,
	};
}

const exists = (p: string): Promise<boolean> =>
	lstat(p).then(
		() => true,
		() => false,
	);

describe("SAN-005 publish deletes quarantine", () => {
	it("SAN-005 a finished publish deletes quarantine/ and marks the stage ok", async () => {
		await build();
		expect(await exists(join(raiz, "quarantine", ".env"))).toBe(true);
		const res = await publish(opts());
		expect(res.visibilidad).toBe("publico");
		expect(await exists(join(raiz, "quarantine"))).toBe(false);
		expect((await readState(raiz)).etapas.publish.estado).toBe("ok");
		expect(await exists(join(raiz, "remote-scan"))).toBe(false);
	});

	it("SAN-005 --private also finishes publish and deletes quarantine/, leaving the repo private", async () => {
		await build();
		const res = await publish(opts({ privado: true }));
		expect(res.visibilidad).toBe("privado");
		expect(calls.map((c) => c.route)).not.toContain(
			"PATCH /repos/{owner}/{repo}",
		);
		expect(await exists(join(raiz, "quarantine"))).toBe(false);
	});

	it("SAN-005 quarantine/ stays when publish does not finish (remote findings)", async () => {
		await build();
		await writeFile(join(home, ".mct", "sensible.txt"), `${TERM}\n`);
		cloneBody = `nota de ${TERM}\n`;
		const err = await publish(opts()).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
		expect(await exists(join(raiz, "quarantine", ".env"))).toBe(true);
		expect(await exists(join(raiz, "remote-scan"))).toBe(false);
		expect((await readState(raiz)).etapas.publish.estado).not.toBe("ok");
	});

	it("SAN-005 quarantine/ stays when the second confirmation is refused, and the repo stays private", async () => {
		await build();
		const err = await publish(
			opts({ confirmarPublico: async () => false }),
		).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect((err as MctError).codigo).toBe("CANCELADO");
		expect(await exists(join(raiz, "quarantine", ".env"))).toBe(true);
		expect(calls.map((c) => c.route)).not.toContain(
			"PATCH /repos/{owner}/{repo}",
		);
	});

	it("SAN-005 --dry-run writes nothing and keeps quarantine/", async () => {
		await build();
		const res = await publish(opts({ dryRun: true }));
		expect(res.dryRun).toBe(true);
		expect(await exists(join(raiz, "quarantine", ".env"))).toBe(true);
		expect(await exists(join(raiz, "publish-state.json"))).toBe(false);
		expect(calls.map((c) => c.route)).not.toContain("POST /user/repos");
	});

	it("PUB-003 the repo is created private, and the scan happens before it is made public", async () => {
		await build();
		await publish(opts());
		const create = calls.find((c) => c.route === "POST /user/repos");
		expect(create?.params?.private).toBe(true);
		expect(create?.params?.auto_init).toBe(false);
		const routes = calls.map((c) => c.route);
		expect(routes.indexOf("POST /user/repos")).toBeLessThan(
			routes.indexOf("PATCH /repos/{owner}/{repo}"),
		);
	});
});
