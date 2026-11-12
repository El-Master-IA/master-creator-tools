import { execFileSync } from "node:child_process";
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
import { resolveExecutable, spawnRunner } from "../packages/core/src/clone.js";
import { createGithubClient } from "../packages/core/src/github.js";
import { hashTree } from "../packages/core/src/hash.js";
import {
	createGitPort,
	type PublishGit,
	type PublishStateFile,
	publish,
} from "../packages/core/src/publish.js";
import {
	createWorkspace,
	readState,
	writeState,
} from "../packages/core/src/workspace.js";
import type { Runner as GitleaksRunner } from "../packages/scanner/src/gitleaks.js";

// Fixture values are assembled from fragments: no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const TERM = ["zq", "client", "x9"].join("");
const SHA = "c".repeat(40);
const PUSH_URL = "https://github.com/dueno/proyecto.git";

let base = "";
let raiz = "";
let home = "";
let bare = "";
let gitExe = "";
let requests: Array<{ method: string; path: string; body: unknown }> = [];
let gitleaksTargets: string[] = [];
let tamper: (dir: string) => Promise<void> = async () => undefined;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pub-e2e-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	bare = join(base, "remote.git");
	await mkdir(join(home, ".mct"), { recursive: true });
	requests = [];
	gitleaksTargets = [];
	tamper = async () => undefined;
	gitExe = (await resolveExecutable("git", process.env)) as string;
	execFileSync(gitExe, ["init", "--quiet", "--bare", "-b", "main", bare]);
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

const gitleaksRunner: GitleaksRunner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	gitleaksTargets.push(args[args.indexOf("dir") + 1] as string);
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
	await mkdir(join(ws.dist, "src"), { recursive: true });
	await writeFile(join(ws.dist, "README.md"), "# proyecto\n");
	await writeFile(join(ws.dist, "src", "index.js"), "export const x = 1;\n");
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

/** Simulated GitHub REST API behind the real Octokit client. */
function mockFetch(): typeof fetch {
	let created = false;
	let isPrivate = true;
	return async (input, init) => {
		const url = new URL(typeof input === "string" ? input : String(input));
		const method = (init?.method ?? "GET").toUpperCase();
		const raw = init?.body;
		const body = typeof raw === "string" ? JSON.parse(raw) : undefined;
		requests.push({ method, path: url.pathname, body });
		const reply = (status: number, data: unknown): Response =>
			new Response(JSON.stringify(data), {
				status,
				headers: {
					"content-type": "application/json",
					"x-oauth-scopes": "repo",
					"x-ratelimit-remaining": "4999",
				},
			});
		const key = `${method} ${url.pathname}`;
		switch (key) {
			case "GET /user":
				return reply(200, { login: "dueno" });
			case "GET /repos/dueno/proyecto":
				return created
					? reply(200, { id: 77, private: isPrivate })
					: reply(404, { message: "Not Found" });
			case "POST /user/repos":
				created = true;
				isPrivate = body?.private === true;
				return reply(201, { id: 77, private: isPrivate });
			case "PATCH /repos/dueno/proyecto":
				isPrivate = body?.private === true;
				return reply(200, { id: 77, private: isPrivate });
			case "GET /repos/dueno/proyecto/commits/main":
				return reply(200, { sha: SHA });
			case "POST /repos/dueno/proyecto/git/refs":
				return reply(201, { ref: body?.ref });
			case "POST /repos/dueno/proyecto/releases":
				return reply(201, { id: 1 });
			case "PUT /repos/dueno/proyecto/topics":
				return reply(200, { names: body?.names });
			default:
				return reply(404, { message: "Not Found" });
		}
	};
}

/** Real git; the push goes to a local bare repo instead of github.com. */
function realGit(): PublishGit {
	const rewrite: typeof spawnRunner = (file, args, options) =>
		spawnRunner(
			file,
			args.map((a) => (a === PUSH_URL ? bare : a)),
			options,
		);
	const real = createGitPort({ run: rewrite, env: process.env });
	return {
		pushInitial: real.pushInitial,
		cloneRemote: async ({ dir }) => {
			execFileSync(gitExe, ["clone", "--quiet", bare, dir]);
			await rm(join(dir, ".git"), { recursive: true, force: true });
			await tamper(dir);
		},
	};
}

async function client() {
	return createGithubClient({
		env: { GITHUB_TOKEN: TOKEN },
		fetch: mockFetch(),
		sleep: async () => undefined,
	});
}

async function everyText(dir: string): Promise<string> {
	let out = "";
	for (const e of await readdir(dir, { withFileTypes: true })) {
		const p = join(dir, e.name);
		if (e.isDirectory()) {
			if (e.name === "work" || e.name === "dist") continue;
			out += await everyText(p);
		} else out += await readFile(p, "utf8").catch(() => "");
	}
	return out;
}

describe("PUB-003 / PUB-010 publish against a simulated GitHub", () => {
	it("PUB-003 creates the repo private with one commit, scans the remote clone, asks twice and publishes", async () => {
		await build();
		const order: string[] = [];
		const res = await publish({
			raiz,
			repo: "dueno/proyecto",
			client: await client(),
			git: realGit(),
			token: TOKEN,
			home,
			lang: "es",
			confirmarPublico: async () => {
				order.push("segunda-confirmacion");
				return true;
			},
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				run: gitleaksRunner,
			},
		});
		expect(res).toEqual({
			url: "https://github.com/dueno/proyecto",
			visibilidad: "publico",
			tag: "v0.1.0",
		});
		const create = requests.find((r) => r.path === "/user/repos");
		expect((create?.body as { private?: boolean } | undefined)?.private).toBe(
			true,
		);
		// Exactly one commit on main, with the contents of dist/.
		const count = execFileSync(
			gitExe,
			["--git-dir", bare, "rev-list", "--count", "main"],
			{ encoding: "utf8" },
		).trim();
		expect(count).toBe("1");
		const files = execFileSync(
			gitExe,
			["--git-dir", bare, "ls-tree", "-r", "--name-only", "main"],
			{ encoding: "utf8" },
		)
			.trim()
			.split("\n")
			.sort();
		expect(files).toEqual(["README.md", "src/index.js"]);
		// Order: create -> (push, scan) -> public -> tag -> release -> topics.
		const seq = requests.map((r) => `${r.method} ${r.path}`);
		const at = (k: string) => seq.indexOf(k);
		expect(at("POST /user/repos")).toBeLessThan(
			at("PATCH /repos/dueno/proyecto"),
		);
		expect(at("PATCH /repos/dueno/proyecto")).toBeLessThan(
			at("POST /repos/dueno/proyecto/git/refs"),
		);
		expect(at("POST /repos/dueno/proyecto/git/refs")).toBeLessThan(
			at("POST /repos/dueno/proyecto/releases"),
		);
		expect(at("POST /repos/dueno/proyecto/releases")).toBeLessThan(
			at("PUT /repos/dueno/proyecto/topics"),
		);
		expect(order).toEqual(["segunda-confirmacion"]);
		const saved = JSON.parse(
			await readFile(join(raiz, "publish-state.json"), "utf8"),
		) as PublishStateFile;
		expect(saved.repoId).toBe(77);
		expect(Object.values(saved.pasos).every((v) => v === "ok")).toBe(true);
		// The credential is nowhere in the workspace.
		expect(await everyText(raiz)).not.toContain(TOKEN);
	});

	it("PUB-010 the remote scan uses both engines: gitleaks on the clone and the own engine with the dictionary", async () => {
		await build();
		await publish({
			raiz,
			repo: "dueno/proyecto",
			client: await client(),
			git: realGit(),
			token: TOKEN,
			home,
			confirmarPublico: async () => true,
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				run: gitleaksRunner,
			},
		});
		expect(gitleaksTargets).toHaveLength(1);
		expect(gitleaksTargets[0]).toMatch(/remote-scan$/);
	});

	it("PUB-010 / PUB-008 a dictionary term in the remote clone leaves the repo private and exits with 10", async () => {
		await build();
		await writeFile(join(home, ".mct", "sensible.txt"), `${TERM}\n`);
		tamper = async (dir) => {
			await writeFile(join(dir, "NOTAS.txt"), `cliente ${TERM}\n`);
		};
		let asked = false;
		const err = await publish({
			raiz,
			repo: "dueno/proyecto",
			client: await client(),
			git: realGit(),
			token: TOKEN,
			home,
			confirmarPublico: async () => {
				asked = true;
				return true;
			},
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				run: gitleaksRunner,
			},
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).exit).toBe(10);
		expect((err as MctError).accion).toContain("gh repo delete dueno/proyecto");
		expect(asked).toBe(false);
		expect(requests.some((r) => r.method === "PATCH")).toBe(false);
		const out =
			JSON.stringify((err as MctError).toJSON()) + (await everyText(raiz));
		expect(out).not.toContain(TERM);
		expect(out).not.toContain(TOKEN);
	});
});
