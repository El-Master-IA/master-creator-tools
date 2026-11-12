import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { humanSummary } from "../../cli/src/commands/verify.js";
import type { Runner } from "../src/clone.js";
import type { DockerTarget } from "../src/docker.js";
import { hashTree } from "../src/hash.js";
import { checkHashes } from "../src/publish-gates.js";
import { stageVerify } from "../src/verify.js";
import { createWorkspace, readState, writeState } from "../src/workspace.js";

let base: string;
let raiz: string;

const target: DockerTarget = {
	kind: "local",
	dockerPath: "/usr/bin/docker",
	env: { PATH: "/usr/bin" },
};

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c09g-"));
	raiz = join(base, ".mct");
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "generico",
	});
	await mkdir(join(ws.dist, "src"), { recursive: true });
	await writeFile(join(ws.dist, "src", "index.php"), "<?php echo 1;\n");
	await writeFile(join(ws.work, "index.php"), "<?php echo 1;\n");
	const state = await readState(raiz);
	state.distSha256 = await hashTree(ws.dist);
	state.workSha256 = await hashTree(ws.work);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

/** A Docker that must never be touched. */
function forbidden() {
	const calls: string[][] = [];
	const run: Runner = async (_file, args) => {
		calls.push([...args]);
		return { code: 0, stdout: "", stderr: "" };
	};
	let resolved = 0;
	const thunk = async (): Promise<DockerTarget> => {
		resolved++;
		return target;
	};
	return { calls, run, thunk, resolved: () => resolved };
}

describe("VER-007 generic adapter: verify omitido", () => {
	it("VER-007 generico marks verify ok with destino (omitido), saves distSha256 and starts no container", async () => {
		const d = forbidden();
		const result = await stageVerify(raiz, {
			target: d.thunk,
			run: d.run,
			now: () => "2026-11-12T00:00:00.000Z",
		});
		const dist = await hashTree(join(raiz, "dist"));
		expect(result).toEqual({
			destino: "(omitido)",
			healthcheck: { tipo: "omitido" },
			distSha256: dist,
			avisos: ["verify.omitido"],
		});
		const state = await readState(raiz);
		expect(state.verificado).toEqual({
			distSha256: dist,
			destino: "(omitido)",
			ts: "2026-11-12T00:00:00.000Z",
		});
		expect(state.etapas.verify.estado).toBe("ok");
		expect(d.calls).toHaveLength(0);
		expect(d.resolved()).toBe(0);
		const log = await readFile(join(raiz, "logs", "verify.jsonl"), "utf8");
		expect(log).toContain("verify.omitido");
		expect(await readFile(join(raiz, "report.html"), "utf8")).toContain(
			"verify",
		);
	});

	it("VER-007 the terminal shows the verify.omitido notice in ES and EN", async () => {
		const d = forbidden();
		const result = await stageVerify(raiz, { target: d.thunk, run: d.run });
		expect(humanSummary(result, "es")).toContain(
			"Este proyecto no se probó en un contenedor",
		);
		expect(humanSummary(result, "en")).toContain(
			"This project was not tested in a container",
		);
	});

	it("VER-007 without package the generic adapter is blocked like any other", async () => {
		const state = await readState(raiz);
		state.etapas.package.estado = "pendiente";
		await writeState(raiz, state);
		const d = forbidden();
		const err = await errOf(stageVerify(raiz, { target: d.thunk, run: d.run }));
		expect(err.codigo).toBe("PUERTA_BLOQUEADA");
		expect(err.detalle?.motivo).toBe("sin-package");
	});

	it("VER-007 a dist/ changed after an omitted verify gives APROBACION_DESACTUALIZADA in publish", async () => {
		const d = forbidden();
		await stageVerify(raiz, { target: d.thunk, run: d.run });
		const state = await readState(raiz);
		await writeFile(
			join(raiz, "approval.json"),
			JSON.stringify({ schemaVersion: 1, arbolSha256: state.workSha256 }),
		);
		await expect(checkHashes(raiz, state)).resolves.toBeUndefined();
		await writeFile(join(raiz, "dist", "src", "index.php"), "<?php echo 2;\n");
		const err = await errOf(checkHashes(raiz, state));
		expect(err.codigo).toBe("APROBACION_DESACTUALIZADA");
		expect(err.exit).toBe(11);
	});

	it("VER-007 a dist/ that is not the one package produced is refused before the omitted verify", async () => {
		await writeFile(join(raiz, "dist", "extra.php"), "x\n");
		const d = forbidden();
		const err = await errOf(stageVerify(raiz, { target: d.thunk, run: d.run }));
		expect(err.codigo).toBe("WORKSPACE_INVALIDO");
		expect((await readState(raiz)).verificado).toBeNull();
	});
});
