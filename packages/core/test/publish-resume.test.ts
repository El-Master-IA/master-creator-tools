import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeAdapter } from "@mct/adapter-node/index";
import { MctError } from "@mct/contract/errors";
import type { Adapter } from "@mct/contract/types";
import { loadDictionary } from "@mct/scanner/dictionary";
import type { Runner } from "@mct/scanner/gitleaks";
import { scan } from "@mct/scanner/scan";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GithubClient } from "../src/github.js";
import { hashTree } from "../src/hash.js";
import {
	createGitPort,
	type PublishGit,
	type PublishOptions,
	type PublishStateFile,
	publish,
} from "../src/publish.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

// Fixture values are assembled from fragments: no literal secret or PII lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);
const TERM = ["zq", "client", "x9"].join("");
const SHA = "a".repeat(40);

let base = "";
let raiz = "";
let home = "";
let calls: string[] = [];
let pushes = 0;
let clones = 0;
let cloneBody = "hola\n";
let distHash = "";

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-pub-resume-"));
	raiz = join(base, ".mct");
	home = join(base, "home");
	await mkdir(join(home, ".mct"), { recursive: true });
	calls = [];
	pushes = 0;
	clones = 0;
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
	const work = await hashTree(ws.work);
	const dist = await hashTree(ws.dist);
	distHash = dist;
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

/** In-memory GitHub: one repo with the given id/visibility, or none. */
function fakeClient(
	repo: { id: number; private: boolean } | null,
): GithubClient {
	return {
		tokenSource: "GITHUB_TOKEN",
		rateRemaining: undefined,
		request: async (route) => {
			calls.push(route);
			const ok = (data: unknown) => ({ status: 200, headers: {}, data });
			switch (route) {
				case "GET /user":
					return ok({ login: "dueno" });
				case "GET /repos/{owner}/{repo}":
					if (repo === null) {
						throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
					}
					return ok({ id: repo.id, private: repo.private });
				case "POST /user/repos":
					repo = { id: 4242, private: true };
					return ok({ id: 4242, private: true });
				case "PATCH /repos/{owner}/{repo}":
					if (repo !== null) repo.private = false;
					return ok({});
				case "GET /repos/{owner}/{repo}/commits/{ref}":
					return ok({ sha: SHA });
				default:
					return ok({});
			}
		},
		checkPermissions: async () => {
			calls.push("permissions");
		},
	};
}

const fakeGit: PublishGit = {
	pushInitial: async () => {
		pushes++;
	},
	cloneRemote: async ({ dir }) => {
		clones++;
		await mkdir(dir, { recursive: true });
		await writeFile(join(dir, "b.txt"), cloneBody);
	},
};

function opts(
	client: GithubClient,
	over: Partial<PublishOptions> = {},
): PublishOptions {
	return {
		raiz,
		repo: "dueno/proyecto",
		client,
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

function savedState(
	pasos: Partial<PublishStateFile["pasos"]>,
	repoId = 4242,
): PublishStateFile {
	return {
		schemaVersion: 1,
		repo: "dueno/proyecto",
		repoId,
		creadoPorWorkspace: true,
		distSha256: distHash,
		pasos: {
			crear: "ok",
			commit: "ok",
			escaneoRemoto: "pendiente",
			publico: "pendiente",
			tag: "pendiente",
			release: "pendiente",
			topics: "pendiente",
			...pasos,
		},
		ts: "2026-11-08T00:00:00Z",
	};
}

async function put(state: PublishStateFile): Promise<void> {
	await writeFile(join(raiz, "publish-state.json"), JSON.stringify(state));
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

const WRITES = [
	"POST /user/repos",
	"POST /orgs/{org}/repos",
	"PATCH /repos/{owner}/{repo}",
	"POST /repos/{owner}/{repo}/git/refs",
	"POST /repos/{owner}/{repo}/releases",
	"PUT /repos/{owner}/{repo}/topics",
];

describe("PUB-008 publish-state and --resume", () => {
	it("PUB-008 --resume with another repoId exits with VALIDACION and touches nothing", async () => {
		await build();
		await put(savedState({}, 42));
		const err = await errOf(
			publish(opts(fakeClient({ id: 7, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(err.exit).toBe(2);
		expect(calls.filter((c) => WRITES.includes(c))).toEqual([]);
		expect(pushes).toBe(0);
		expect(clones).toBe(0);
	});

	it("PUB-008 --resume without a saved publish-state is VALIDACION", async () => {
		await build();
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("VALIDACION");
	});

	it("PUB-008 --resume where the repo is gone is VALIDACION", async () => {
		await build();
		await put(savedState({}));
		const err = await errOf(publish(opts(fakeClient(null), { resume: true })));
		expect(err.codigo).toBe("VALIDACION");
		expect(calls.filter((c) => WRITES.includes(c))).toEqual([]);
	});

	it("PUB-008 a malformed publish-state is WORKSPACE_INVALIDO", async () => {
		await build();
		await writeFile(join(raiz, "publish-state.json"), "{ no json");
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("PUB-008 a private repo resumes at the first pending step without redoing commit or creation", async () => {
		await build();
		await put(savedState({}));
		const res = await publish(
			opts(fakeClient({ id: 4242, private: true }), { resume: true }),
		);
		expect(res).toEqual({
			url: "https://github.com/dueno/proyecto",
			visibilidad: "publico",
			tag: "v0.1.0",
		});
		expect(pushes).toBe(0);
		expect(clones).toBe(1);
		expect(calls).not.toContain("POST /user/repos");
		expect(calls).toContain("PATCH /repos/{owner}/{repo}");
		const saved = JSON.parse(
			await readFile(join(raiz, "publish-state.json"), "utf8"),
		) as PublishStateFile;
		expect(Object.values(saved.pasos).every((v) => v === "ok")).toBe(true);
	});

	it("PUB-008 a public repo with publico=ok only completes tag, release and topics", async () => {
		await build();
		await put(savedState({ escaneoRemoto: "ok", publico: "ok", tag: "ok" }));
		const res = await publish(
			opts(fakeClient({ id: 4242, private: false }), { resume: true }),
		);
		expect(res.visibilidad).toBe("publico");
		expect(pushes).toBe(0);
		expect(clones).toBe(0);
		expect(calls).not.toContain("PATCH /repos/{owner}/{repo}");
		expect(calls).not.toContain("POST /repos/{owner}/{repo}/git/refs");
		expect(calls).toContain("POST /repos/{owner}/{repo}/releases");
		expect(calls).toContain("PUT /repos/{owner}/{repo}/topics");
	});

	it("PUB-008 a public repo without publico=ok is refused", async () => {
		await build();
		await put(savedState({ escaneoRemoto: "ok" }));
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: false }), { resume: true })),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(calls.filter((c) => WRITES.includes(c))).toEqual([]);
	});

	it("PUB-008 a remote scan with findings leaves the repo private and shows the deletion guide", async () => {
		await build();
		await writeFile(join(home, ".mct", "sensible.txt"), `${TERM}\n`);
		cloneBody = `contrato de ${TERM}\n`;
		await put(savedState({}));
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.exit).toBe(10);
		expect(err.accion).toContain("gh repo delete dueno/proyecto");
		expect(err.accion).toContain("Danger zone");
		expect(calls).not.toContain("PATCH /repos/{owner}/{repo}");
		const saved = JSON.parse(
			await readFile(join(raiz, "publish-state.json"), "utf8"),
		) as PublishStateFile;
		expect(saved.pasos.escaneoRemoto).toBe("fallo");
		expect(saved.pasos.publico).toBe("pendiente");
		const everything = JSON.stringify(err.toJSON()) + JSON.stringify(saved);
		expect(everything).not.toContain(TERM);
		expect(everything).not.toContain(TOKEN);
	});
	it("PUB-003 a remote finding accepted in sanitize does not block; a changed one does", async () => {
		await build();
		await writeFile(
			join(home, ".mct", "sensible.txt"),
			`${TERM}
`,
		);
		const adapter: Adapter = nodeAdapter;
		const probe = join(base, "probe");
		await mkdir(probe, { recursive: true });
		cloneBody = `contrato de ${TERM}
`;
		await writeFile(join(probe, "b.txt"), cloneBody);
		const tmp = join(base, "probe-tmp");
		await mkdir(tmp, { recursive: true });
		const res = await scan({
			work: probe,
			quarantine: join(tmp, "sin-cuarentena"),
			rules: adapter.rules(),
			dictionary: await loadDictionary(join(home, ".mct", "sensible.txt")),
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				tmpDir: tmp,
				run: okRunner,
			},
		});
		expect(res.hallazgos.length).toBeGreaterThan(0);
		await writeFile(
			join(raiz, "findings.json"),
			JSON.stringify({
				schemaVersion: 1,
				hallazgos: res.hallazgos.map((h) => ({
					...h,
					estado: "aceptado",
					motivo: "revisado",
				})),
			}),
		);
		await put(savedState({}));
		const ok = await publish(
			opts(fakeClient({ id: 4242, private: true }), { resume: true }),
		);
		expect(ok.visibilidad).toBe("publico");

		cloneBody = `linea previa
contrato de ${TERM}
`;
		await put(savedState({}));
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
	});

	it("PUB-010 --resume with a dist that changed after the push is APROBACION_DESACTUALIZADA", async () => {
		await build();
		await put(savedState({}));
		const dist = join(raiz, "dist");
		await writeFile(join(dist, "b.txt"), "hola dist v2 cambiado");
		const nuevo = await hashTree(dist);
		const state = await readState(raiz);
		state.distSha256 = nuevo;
		state.verificado = {
			distSha256: nuevo,
			destino: "local",
			ts: "2026-11-08T00:00:00Z",
		};
		await writeState(raiz, state);
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(calls.filter((c) => WRITES.includes(c))).toEqual([]);
		expect(pushes).toBe(0);
	});

	it("PUB-010 a publish-state without distSha256 is WORKSPACE_INVALIDO", async () => {
		await build();
		const { distSha256: _omit, ...sin } = savedState({});
		await writeFile(join(raiz, "publish-state.json"), JSON.stringify(sin));
		const err = await errOf(
			publish(opts(fakeClient({ id: 4242, private: true }), { resume: true })),
		);
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("PUB-010 dist mutated while the repo is created is not pushed", async () => {
		await build();
		const inner = fakeClient(null);
		const client: GithubClient = {
			...inner,
			request: async (route, params) => {
				if (route === "POST /user/repos") {
					await writeFile(join(raiz, "dist", "b.txt"), "MUTADO");
				}
				return inner.request(route, params);
			},
		};
		const err = await errOf(publish(opts(client)));
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(pushes).toBe(0);
		expect(calls).not.toContain("PATCH /repos/{owner}/{repo}");
	});

	it("PUB-010 the git port refuses to push a tree that is not the verified one", async () => {
		await build();
		const dist = join(raiz, "dist");
		const seen: string[] = [];
		const port = createGitPort({
			gitPath: "git",
			env: {},
			run: async (_c, args) => {
				const op = args.find((a) =>
					["init", "add", "commit", "push"].includes(a),
				) as string;
				seen.push(op);
				if (op === "add") await writeFile(join(dist, "b.txt"), "MUTADO");
				return {
					code: 0,
					signal: null,
					stdout: "",
					stderr: "",
					timedOut: false,
				};
			},
		});
		const err = await errOf(
			port.pushInitial({
				dist,
				repo: "dueno/proyecto",
				token: TOKEN,
				tmpDir: join(raiz, "tmp"),
				distSha256: distHash,
			}),
		);
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(seen).not.toContain("push");
	});
});

describe("PUB-012 reintento ante 404 justo después de hacer público el repo", () => {
	it("PUB-012 un 404 pasajero en release y topics se reintenta con espera y termina ok", async () => {
		await build();
		await put(savedState({ escaneoRemoto: "ok", publico: "ok", tag: "ok" }));
		const base = fakeClient({ id: 4242, private: false });
		const fallos: Record<string, number> = {
			"POST /repos/{owner}/{repo}/releases": 2,
			"PUT /repos/{owner}/{repo}/topics": 1,
		};
		const client: GithubClient = {
			...base,
			request: async (route, params) => {
				if ((fallos[route] ?? 0) > 0) {
					fallos[route] = (fallos[route] ?? 0) - 1;
					calls.push(route);
					throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
				}
				return base.request(route, params);
			},
		};
		const esperas: number[] = [];
		const res = await publish(
			opts(client, {
				resume: true,
				esperar: async (ms) => {
					esperas.push(ms);
				},
			}),
		);
		expect(res.visibilidad).toBe("publico");
		expect(esperas).toEqual([2000, 4000, 2000]);
		const saved = JSON.parse(
			await readFile(join(raiz, "publish-state.json"), "utf8"),
		) as PublishStateFile;
		expect(saved.pasos.release).toBe("ok");
		expect(saved.pasos.topics).toBe("ok");
	});

	it("PUB-012 un 404 que no se va termina en error sin marcar el release", async () => {
		await build();
		await put(savedState({ escaneoRemoto: "ok", publico: "ok", tag: "ok" }));
		const base = fakeClient({ id: 4242, private: false });
		const client: GithubClient = {
			...base,
			request: async (route, params) => {
				if (route === "POST /repos/{owner}/{repo}/releases") {
					throw new MctError("INTERNO", "no", { detalle: { estado: 404 } });
				}
				return base.request(route, params);
			},
		};
		const err = await errOf(
			publish(opts(client, { resume: true, esperar: async () => undefined })),
		);
		expect(err.codigo).toBe("INTERNO");
		const saved = JSON.parse(
			await readFile(join(raiz, "publish-state.json"), "utf8"),
		) as PublishStateFile;
		expect(saved.pasos.release).not.toBe("ok");
	});
});
