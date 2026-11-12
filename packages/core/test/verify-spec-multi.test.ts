import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Adapter, Analysis, VerifySpec } from "@mct/contract/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { staticAdapter } from "../../adapter-static/src/index.js";
import { runCli } from "../../cli/src/main.js";
import type { Io } from "../../cli/src/output.js";
import type { Runner } from "../src/clone.js";
import type { DockerTarget } from "../src/docker.js";
import { hashTree } from "../src/hash.js";
import {
	buildStartScript,
	readMarkers,
	readSteps,
	stageVerify,
} from "../src/verify.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

const NONCE = "abc123";
const PY_IMAGE = "python:3.14-slim@sha256:abc";
let base: string;
let raiz: string;

const target: DockerTarget = {
	kind: "local",
	dockerPath: "/usr/bin/docker",
	env: { PATH: "/usr/bin" },
};

const ANALYSIS: Analysis = {
	stack: ["python"],
	entrypoints: ["app.py"],
	envVars: [],
	deps: [],
	comandos: {},
	lenguaje: "python",
	gestor: "pip",
};

const NOOP_SPEC: VerifySpec = {
	imagen: "x",
	start: ["x"],
	healthcheck: { tipo: "salida-cero" },
	timeoutMin: 1,
};

function stub(
	id: string,
	spec: VerifySpec,
	analysis: Analysis = ANALYSIS,
): Adapter {
	return {
		id,
		analyze: async () => analysis,
		verifyCommand: () => spec,
	} as unknown as Adapter;
}

async function setup(adapter: string, files: Record<string, string> = {}) {
	raiz = join(base, ".mct");
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter,
	});
	await writeFile(join(ws.dist, "app.py"), "print(1)\n");
	for (const [name, text] of Object.entries(files)) {
		await writeFile(join(ws.dist, name), text);
	}
	const state = await readState(raiz);
	state.distSha256 = await hashTree(ws.dist);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c09m-"));
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

interface Fake {
	calls: string[][];
	run: Runner;
	/** The `sh -c` script of the start container. */
	script(): string;
}

function fake(start: { code?: number; stdout?: string } = {}): Fake {
	const calls: string[][] = [];
	const run: Runner = async (_file, args) => {
		calls.push([...args]);
		if (args[0] === "run") {
			return {
				code: start.code ?? 0,
				stdout: start.stdout ?? "",
				stderr: "",
			};
		}
		return { code: 0, stdout: "", stderr: "" };
	};
	return {
		calls,
		run,
		script: () => {
			const c = calls.find((x) => x[0] === "run") ?? [];
			return c[c.length - 1] ?? "";
		},
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

describe("PY-003 start as a sequence", () => {
	it("PY-003 steps run in order in one container with --network none, strict ones exit on failure", async () => {
		await setup("stub");
		const spec: VerifySpec = {
			imagen: PY_IMAGE,
			start: [
				["python", "-m", "compileall", "-q", "."],
				["pip", "check"],
			],
			healthcheck: { tipo: "salida-cero" },
			timeoutMin: 5,
		};
		const f = fake();
		const result = await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [stub("stub", spec)],
			nonce: NONCE,
		});
		const script = f.script();
		const first = script.indexOf("python -m compileall -q . >&2 || exit $?");
		const second = script.indexOf("pip check >&2 || exit $?");
		expect(first).toBeGreaterThan(-1);
		expect(second).toBeGreaterThan(first);
		expect(f.calls.filter((c) => c[0] === "run")).toHaveLength(1);
		expect(f.calls.find((c) => c[0] === "run")).toContain("none");
		expect(result.avisos).toEqual([]);
		expect(result.healthcheck).toMatchObject({
			tipo: "salida-cero",
			resultado: "ok",
		});
	});

	it("PY-003 a step that must pass and exits non-zero blocks with the arranque reason", async () => {
		await setup("stub");
		const spec: VerifySpec = {
			imagen: PY_IMAGE,
			start: [
				["python", "-m", "compileall", "."],
				["pip", "check"],
			],
			healthcheck: { tipo: "salida-cero" },
			timeoutMin: 5,
		};
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: fake({ code: 3 }).run,
				adapters: [stub("stub", spec)],
				nonce: NONCE,
			}),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle).toMatchObject({ motivo: "arranque", codigo: 3 });
		expect((await readState(raiz)).verificado).toBeNull();
	});

	it("PY-003 a step with avisoSiFalla that fails does not block and the notice reaches the output and the log", async () => {
		await setup("stub");
		const spec: VerifySpec = {
			imagen: PY_IMAGE,
			start: [{ argv: ["pip", "check"], avisoSiFalla: "verify.pipCheck" }],
			avisos: ["verify.poetrySinLock"],
			healthcheck: { tipo: "salida-cero" },
			timeoutMin: 5,
		};
		const f = fake({ stdout: `MCT_AVISO:${NONCE}:verify.pipCheck\n` });
		const result = await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [stub("stub", spec)],
			nonce: NONCE,
		});
		expect(f.script()).toContain(
			`pip check >&2 || echo MCT_AVISO:${NONCE}:verify.pipCheck`,
		);
		expect(result.avisos).toEqual(["verify.poetrySinLock", "verify.pipCheck"]);
		expect((await readState(raiz)).etapas.verify.estado).toBe("ok");
	});

	it("PY-003 markers with another nonce or an unknown key are ignored", () => {
		const known = new Set(["verify.pipCheck"]);
		const out = readMarkers(
			[
				"MCT_AVISO:otro:verify.pipCheck",
				`MCT_AVISO:${NONCE}:verify.inventado`,
				'MCT_ROUTE:otro:"/x"',
				`MCT_AVISO:${NONCE}:verify.pipCheck`,
			].join("\n"),
			NONCE,
			known,
		);
		expect(out).toEqual({ avisos: ["verify.pipCheck"] });
	});

	it("PY-003 the python adapter gets the venv on PATH and verify.modo and verify.ignorar reach buildVerifySpec", async () => {
		await setup("python");
		const f = fake({ stdout: `MCT_AVISO:${NONCE}:verify.pipCheck\n` });
		const result = await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [stub("python", NOOP_SPEC, { ...ANALYSIS, puerto: 8000 })],
			configModo: "compilar",
			configIgnorar: ["tests/fixtures"],
			nonce: NONCE,
		});
		const script = f.script();
		expect(script).toContain('export PATH="/tmp/venv/bin:$PATH"');
		expect(script).toContain("-x");
		expect(script).toContain("tests/fixtures");
		// compilar mode: no server even with a port, and pip check only warns.
		expect(script).not.toContain("mct_pid");
		expect(script).toContain("MCT_AVISO");
		expect(result.avisos).toEqual(["verify.pipCheck"]);
	});

	it("PY-003 requires-python that no pinned image satisfies blocks with version-python and starts no container", async () => {
		await setup("python");
		const f = fake();
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: f.run,
				adapters: [
					stub("python", NOOP_SPEC, { ...ANALYSIS, requiresPython: ">=3.16" }),
				],
			}),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle).toEqual({ motivo: "version-python" });
		expect(f.calls).toHaveLength(0);
		expect((await readState(raiz)).etapas.verify.estado).toBe("bloqueada");
	});

	it("PY-003 with a port the server step runs in the background and the python probe waits up to 30 s", async () => {
		await setup("python");
		const f = fake();
		await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [stub("python", NOOP_SPEC, { ...ANALYSIS, puerto: 8000 })],
			nonce: NONCE,
		});
		const run = f.calls.find((c) => c[0] === "run") ?? [];
		expect(run).not.toContain("--detach");
		const script = f.script();
		expect(script).toContain("python app.py >/tmp/mct-server.log 2>&1 &");
		expect(script).toContain("-lt 30 ]");
		expect(script).toContain("python -c ");
		expect(script).toContain('"p":8000');
		expect(script).toContain('"a":["2xx","3xx",404]');
		expect(script.indexOf("pip check")).toBeLessThan(script.indexOf("mct_pid"));
	});
});

describe("WEB-002 http healthcheck with route, accepted codes, body and extra routes", () => {
	const html = (links: string) =>
		`<!doctype html><html><head>${links}</head><body>hola</body></html>`;

	it("WEB-002 the static spec probes / and every local href/src from inside the python container", async () => {
		await setup("estatico", {
			"index.html": html('<link href="style.css"><img src="img/logo.png">'),
		});
		const f = fake();
		await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [staticAdapter as unknown as Adapter],
			nonce: NONCE,
		});
		const script = f.script();
		expect(script).toContain("python -m http.server 8080 --bind 127.0.0.1");
		expect(script).toContain('"x":["/style.css","/img/logo.png"]');
		expect(script).toContain('"b":"<html"');
		expect(script).toContain('"a":["2xx"]');
		const create = f.calls.find((c) => c[0] === "create") ?? [];
		expect(create.join(" ")).toContain("python:3.14-slim");
		expect(f.calls.find((c) => c[0] === "run")).toContain("none");
	});

	it("WEB-002 a broken local resource gives PUERTA_BLOQUEADA recurso-roto with the route", async () => {
		await setup("estatico", {
			"index.html": html('<link href="style.css">'),
		});
		const f = fake({
			code: 2,
			stdout: `MCT_ROUTE:${NONCE}:${JSON.stringify("/style.css")}\n`,
		});
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: f.run,
				adapters: [staticAdapter as unknown as Adapter],
				nonce: NONCE,
			}),
		);
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle).toEqual({
			motivo: "recurso-roto",
			ruta: "/style.css",
		});
		const state = await readState(raiz);
		expect(state.etapas.verify.estado).toBe("bloqueada");
		expect(state.verificado).toBeNull();
	});

	it("WEB-002 a route marker from another run is not a broken resource", async () => {
		await setup("estatico", { "index.html": html("") });
		const f = fake({ code: 1, stdout: 'MCT_ROUTE:otro:"/x"\n' });
		const err = await errOf(
			stageVerify(raiz, {
				target,
				run: f.run,
				adapters: [staticAdapter as unknown as Adapter],
				nonce: NONCE,
			}),
		);
		expect(err.detalle).toMatchObject({ motivo: "arranque", codigo: 1 });
	});

	it("WEB-002 a node image uses the node probe and plain 0.1.x http specs keep the detached path", async () => {
		await setup("stub");
		const rich: VerifySpec = {
			imagen: "node:22-slim",
			start: ["node", "server.js"],
			healthcheck: {
				tipo: "http",
				puerto: 3000,
				ruta: "/salud",
				aceptar: [200, "3xx"],
				cuerpoContiene: "OK",
			},
			timeoutMin: 5,
		};
		const f = fake();
		await stageVerify(raiz, {
			target,
			run: f.run,
			adapters: [stub("stub", rich)],
			nonce: NONCE,
		});
		expect(f.script()).toContain("node -e ");
		expect(f.script()).toContain('"r":"/salud"');
		expect(f.script()).toContain('"a":[200,"3xx"]');

		const plain: VerifySpec = {
			...rich,
			healthcheck: { tipo: "http", puerto: 3000 },
		};
		const g = fake();
		await stageVerify(raiz, {
			target,
			run: g.run,
			adapters: [stub("stub", plain)],
			pollMs: 1,
		});
		expect(g.calls.find((c) => c[0] === "run")).toContain("--detach");
	});

	it("WEB-002 a route that does not start with / or a port out of range is refused before Docker", async () => {
		await setup("stub");
		const checks: VerifySpec["healthcheck"][] = [
			{ tipo: "http", puerto: 8080, rutasExtra: ["style.css"] },
			{ tipo: "http", puerto: 0 },
			{ tipo: "http", puerto: 8080, rutasExtra: Array(51).fill("/a") },
		];
		for (const hc of checks) {
			const f = fake();
			const err = await errOf(
				stageVerify(raiz, {
					target,
					run: f.run,
					adapters: [
						stub("stub", {
							imagen: PY_IMAGE,
							start: ["python", "-m", "http.server"],
							healthcheck: hc,
							timeoutMin: 1,
						}),
					],
				}),
			);
			expect(err.codigo).toBe("WORKSPACE_INVALIDO");
			expect(f.calls).toHaveLength(0);
		}
	});
});

describe("VerifySpec.start shapes", () => {
	it("PY-003 readSteps tells one argv from a sequence and rejects malformed steps", () => {
		expect(readSteps(["node", "a.js"])).toEqual({
			flat: true,
			steps: [{ argv: ["node", "a.js"] }],
		});
		expect(readSteps([["a"], { argv: ["b"], avisoSiFalla: "k" }])).toEqual({
			flat: false,
			steps: [{ argv: ["a"] }, { argv: ["b"], aviso: "k" }],
		});
		expect(readSteps([])).toBeNull();
		expect(readSteps([[]])).toBeNull();
		expect(
			readSteps([{ argv: ["b"] }] as unknown as VerifySpec["start"]),
		).toBeNull();
	});

	it("PY-003 every word of a step is quoted so a regex argument cannot become shell syntax", () => {
		const spec: VerifySpec = {
			imagen: PY_IMAGE,
			start: [
				["python", "-m", "compileall", "-q", "-x", "(?:^|/)a(?:/|$)", "."],
			],
			healthcheck: { tipo: "salida-cero" },
			timeoutMin: 1,
		};
		const steps = readSteps(spec.start)?.steps ?? [];
		const script = buildStartScript(spec, steps, NONCE, false);
		expect(script).toContain("-x '(?:^|/)a(?:/|$)' . >&2 || exit $?");
	});
});

describe("LIC-006 licenses stage routed by adapter", () => {
	async function licenses(adapter: string, files: Record<string, string>) {
		raiz = join(base, ".mct");
		const ws = await createWorkspace(raiz, {
			mctVersion: "0.0.0",
			origen: { tipo: "carpeta", ref: "origen" },
			adapter,
		});
		for (const [name, text] of Object.entries(files)) {
			await writeFile(join(ws.work, name), text);
		}
		const out: string[] = [];
		const err: string[] = [];
		const io: Io = {
			out: (t) => out.push(t),
			err: (t) => err.push(t),
			env: { LANG: "es_CO.UTF-8" },
			stdinIsTTY: false,
			stderrIsTTY: false,
		};
		const code = await runCli(
			["--json", "licenses", "--offline", "--workspace", raiz],
			io,
		);
		return {
			code,
			json: JSON.parse(out.join("")) as Record<string, unknown>,
			err: err.join(""),
		};
	}

	it("LIC-006 a generic project with no manifest passes with the sin-gestor notice in the output, the file and the terminal", async () => {
		const r = await licenses("generico", { "index.php": "<?php echo 1;" });
		expect(r.code).toBe(0);
		expect(r.json).toMatchObject({ paquetes: 0, avisos: ["sin-gestor"] });
		expect(r.err).toContain("Sin gestor de dependencias reconocido");
		expect(await readFile(join(raiz, "license-avisos.json"), "utf8")).toContain(
			"sin-gestor",
		);
		expect((await readState(raiz)).etapas.licenses.estado).toBe("ok");
	});

	it("LIC-006 an unsupported manager is revisar and blocks until gestorNoSoportado accepts it", async () => {
		const r = await licenses("estatico", { "composer.json": "{}" });
		expect(r.code).toBe(10);
		expect(r.json).toMatchObject({ revisar: 1, avisos: [] });
		expect((await readState(raiz)).etapas.licenses.estado).toBe("bloqueada");
	});

	it("LIC-005 a python project with exact pins is audited by the python path (offline leaves them in revisar)", async () => {
		const r = await licenses("python", {
			"requirements.txt": "requests==2.32.3",
		});
		expect(r.code).toBe(10);
		expect(r.json.paquetes).toBeGreaterThanOrEqual(1);
		expect(r.json.avisos).toEqual([]);
	});

	it("LIC-004 node and n8n keep their audit and report an empty avisos list", async () => {
		const r = await licenses("node", {
			"package.json": '{"name":"a","version":"1.0.0"}',
			"package-lock.json":
				'{"name":"a","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"a","version":"1.0.0"}}}',
		});
		expect(r.json.avisos).toEqual([]);
	});
});
