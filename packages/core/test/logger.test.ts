import {
	chmod,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createLogger } from "../src/logger.js";
import { createWorkspace } from "../src/workspace.js";

let base: string;
let raiz: string;

const init = {
	mctVersion: "0.0.0",
	origen: { tipo: "carpeta" as const, ref: "origen" },
	adapter: "node",
};
const token = () => `${"gh"}${"p_"}${"a1B2".repeat(9)}`;
const hash = () => "ab".repeat(32);
const ahora = () => "2026-11-08T10:00:00.000Z";

async function rechazo(p: Promise<unknown>): Promise<MctError> {
	try {
		await p;
	} catch (e) {
		if (e instanceof MctError) return e;
		throw e;
	}
	throw new Error("se esperaba un rechazo");
}

async function lineas(etapa: string): Promise<Record<string, unknown>[]> {
	const txt = await readFile(join(raiz, "logs", `${etapa}.jsonl`), "utf8");
	return txt
		.split("\n")
		.filter((l) => l !== "")
		.map((l) => JSON.parse(l) as Record<string, unknown>);
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t43-"));
	raiz = join(base, ".mct");
	await createWorkspace(raiz, init);
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("OBS-001 logger JSONL por etapa", () => {
	it("OBS-001 escribe solo los campos permitidos, una línea por evento", async () => {
		const log = createLogger(raiz, "scan", { now: ahora });
		await log.log({
			evento: "regla-aplicada",
			duracionMs: 12,
			archivo: "src/a.ts",
			regla: "openai-key",
			hallazgoId: hash(),
		});
		await log.log({ evento: "fin" });
		const out = await lineas("scan");
		expect(out).toHaveLength(2);
		expect(out[0]).toEqual({
			ts: "2026-11-08T10:00:00.000Z",
			etapa: "scan",
			evento: "regla-aplicada",
			duracionMs: 12,
			archivo: "src/a.ts",
			regla: "openai-key",
			hallazgoId: hash(),
		});
		expect(Object.keys(out[1] ?? {}).sort()).toEqual(["etapa", "evento", "ts"]);
	});

	it("OBS-001 rechaza contenido, valores y cualquier campo fuera de la lista", async () => {
		const log = createLogger(raiz, "scan");
		for (const campo of ["contenido", "valor", "fragmento", "env", "stdout"]) {
			const e = await rechazo(
				log.log({ evento: "x", [campo]: "algo" } as never),
			);
			expect(e.codigo).toBe("INTERNO");
		}
		await expect(
			readFile(join(raiz, "logs", "scan.jsonl"), "utf8"),
		).rejects.toThrow();
	});

	it("OBS-001 rechaza tipos inválidos y un hallazgoId que no es sha256", async () => {
		const log = createLogger(raiz, "scan");
		for (const mal of [
			{ evento: 3 },
			{ evento: "x", duracionMs: -1 },
			{ evento: "x", duracionMs: Number.NaN },
			{ evento: "x", archivo: "/etc/passwd" },
			{ evento: "x", archivo: "../fuera" },
			{ evento: "x", hallazgoId: "sk-secreto" },
			{ evento: "x", hallazgoId: "sha-256" },
		]) {
			const e = await rechazo(log.log(mal as never));
			expect(e.codigo).toBe("INTERNO");
		}
	});

	it("OBS-001 rechaza una etapa desconocida", () => {
		expect(() => createLogger(raiz, "../x" as never)).toThrow(MctError);
	});

	it("OBS-001 redacta tokens en los campos permitidos", async () => {
		const log = createLogger(raiz, "package");
		await log.log({ evento: `fallo ${token()}`, regla: `r-${token()}` });
		const crudo = await readFile(join(raiz, "logs", "package.jsonl"), "utf8");
		expect(crudo).not.toContain(token());
		expect(crudo).toContain("[REDACTADO]");
	});

	it("OBS-001 redacta el mensaje, la causa y el detalle anidado de un error", async () => {
		const log = createLogger(raiz, "publish");
		const err = new MctError("INTERNO", `mensaje ${token()}`, {
			cause: new Error(`causa ${token()}`),
			detalle: { a: { b: [token()] } },
		});
		await log.error(err);
		await log.error(new Error(`plano ${token()}`));
		await log.error(`texto ${token()}`);
		const crudo = await readFile(join(raiz, "logs", "publish.jsonl"), "utf8");
		expect(crudo).not.toContain(token());
		const out = await lineas("publish");
		expect(out).toHaveLength(3);
		for (const l of out) {
			expect(Object.keys(l).sort()).toEqual(["etapa", "evento", "ts"]);
		}
	});

	it("OBS-001 crea logs/ 0700 y el archivo 0600 en POSIX", async () => {
		const log = createLogger(raiz, "init");
		await log.log({ evento: "x" });
		if (process.platform === "win32") return;
		expect((await stat(join(raiz, "logs"))).mode & 0o777).toBe(0o700);
		expect((await stat(join(raiz, "logs", "init.jsonl"))).mode & 0o777).toBe(
			0o600,
		);
	});

	it("SEG-010 falla cerrado si .mct es un enlace simbólico", async () => {
		const enlace = join(base, "enlace");
		try {
			await symlink(raiz, enlace, "junction");
		} catch {
			return;
		}
		const e = await rechazo(createLogger(enlace, "scan").log({ evento: "x" }));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("SEG-010 falla cerrado si logs/ es un enlace simbólico", async () => {
		const real = join(base, "real");
		await mkdir(real);
		try {
			await symlink(real, join(raiz, "logs"), "junction");
		} catch {
			return;
		}
		const e = await rechazo(createLogger(raiz, "scan").log({ evento: "x" }));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		await expect(readFile(join(real, "scan.jsonl"), "utf8")).rejects.toThrow();
	});

	it("SEG-010 falla cerrado con permisos abiertos en POSIX", async () => {
		if (process.platform === "win32") return;
		await chmod(raiz, 0o755);
		const e = await rechazo(createLogger(raiz, "scan").log({ evento: "x" }));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		await chmod(raiz, 0o700);
		await createLogger(raiz, "scan").log({ evento: "x" });
		await chmod(join(raiz, "logs"), 0o777);
		const e2 = await rechazo(createLogger(raiz, "scan").log({ evento: "x" }));
		expect(e2.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("SEG-010 falla cerrado sin workspace válido", async () => {
		const e = await rechazo(
			createLogger(join(base, "nada"), "scan").log({ evento: "x" }),
		);
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
	});
});
