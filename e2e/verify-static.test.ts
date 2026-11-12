import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { MctError } from "../packages/contract/src/errors.js";
import {
	type DockerTarget,
	resolveDocker,
} from "../packages/core/src/docker.js";
import { hashTree } from "../packages/core/src/hash.js";
import { stageVerify } from "../packages/core/src/verify.js";
import {
	createWorkspace,
	readState,
	writeState,
} from "../packages/core/src/workspace.js";

// Real Docker (DOCKER_HOST=ssh://servidor-casa). No fallback: without Docker the suite fails.
let target: DockerTarget;
let base = "";
let raiz = "";

const SITE = fileURLToPath(new URL("./fixtures/static-site/", import.meta.url));

beforeAll(async () => {
	target = await resolveDocker({ env: process.env });
}, 60_000);

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-c13s-"));
	raiz = join(base, ".mct");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** A static workspace: dist/ and work/ hold the fixture site plus `files`; package already passed. */
async function build(files: Record<string, string> = {}): Promise<void> {
	const ws = await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "origen" },
		adapter: "estatico",
	});
	for (const root of [ws.work, ws.dist]) {
		await cp(SITE, root, { recursive: true });
		for (const [name, content] of Object.entries(files)) {
			await mkdir(root, { recursive: true });
			await writeFile(join(root, name), content);
		}
	}
	const state = await readState(raiz);
	state.workSha256 = await hashTree(ws.work);
	state.distSha256 = await hashTree(ws.dist);
	state.etapas.package.estado = "ok";
	await writeState(raiz, state);
}

const E2E_MS = 240_000;

/** index.html linking n files `r<i>.txt`. */
const indexWith = (n: number) =>
	[
		"<!doctype html>",
		'<html lang="es"><head><title>fx</title></head><body>',
		...Array.from({ length: n }, (_, i) => `<a href="r${i}.txt">r${i}</a>`),
		"</body></html>",
		"",
	].join("\n");

describe("WEB-002 static verify against real Docker", () => {
	it(
		"WEB-002 a healthy site passes",
		async () => {
			await build();
			const result = await stageVerify(raiz, { target });
			expect(result.healthcheck.tipo).toBe("http");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
		},
		E2E_MS,
	);

	it(
		"WEB-002 a broken local link blocks with recurso-roto",
		async () => {
			await build({
				"index.html": [
					"<!doctype html>",
					"<html><body>",
					'<link rel="stylesheet" href="css/site.css">',
					'<a href="no-existe.html">roto</a>',
					"</body></html>",
					"",
				].join("\n"),
			});
			const err = await stageVerify(raiz, { target }).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(MctError);
			expect((err as MctError).codigo).toBe("PUERTA_BLOQUEADA");
			expect((err as MctError).detalle?.motivo).toBe("recurso-roto");
			expect((err as MctError).detalle?.ruta).toBe("/no-existe.html");
		},
		E2E_MS,
	);

	it(
		"WEB-002 with more than 50 resources only the first 50 are checked",
		async () => {
			// r0..r49 exist; r50..r59 do not and must not be looked at.
			const files: Record<string, string> = { "index.html": indexWith(60) };
			for (let i = 0; i < 50; i++) files[`r${i}.txt`] = "x";
			await build(files);
			const result = await stageVerify(raiz, { target });
			expect(result.healthcheck.tipo).toBe("http");
			const state = await readState(raiz);
			expect(state.etapas.verify.estado).toBe("ok");
		},
		E2E_MS,
	);
});
