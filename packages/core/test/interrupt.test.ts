import { createHash } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding } from "@mct/contract/types";
import { findingId, leerClave } from "@mct/scanner/finding-id";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type Decision,
	type Decisor,
	type SanitizeOptions,
	sanitize,
} from "../src/sanitize.js";
import { createWorkspace } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
// Synthetic values built from fragments (T05).
const SECRET = ["tok", "en-", "a1b2c3d4e5f6a7b8c9d0"].join("");
const SECRET_B = ["tok", "en-", "z9y8x7w6v5u4t3s2r1q0"].join("");

let base: string;
let raiz: string;
let work: string;

async function put(rel: string, content: string | Buffer) {
	const full = join(work, ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, content);
}

function finding(archivo: string, text: string, value: string): Finding {
	const at = text.indexOf(value);
	const before = text.slice(0, at);
	const linea = before.split("\n").length;
	const columna = at - (before.lastIndexOf("\n") + 1) + 1;
	return {
		id: findingId(
			{
				motor: "mct",
				regla: "generic-token",
				archivo,
				linea,
				value,
			},
			CLAVE,
		),
		motor: "mct",
		regla: "generic-token",
		tipo: "secreto",
		zona: "work",
		archivo,
		linea,
		columna,
		fragmento: "tok-****",
		severidad: "critico",
		estado: "abierto",
	};
}

function binario(archivo: string): Finding {
	return {
		...finding("x", "x", "x"),
		id: findingId(
			{
				motor: "mct",
				regla: "binary-unknown",
				archivo,
				linea: 0,
				value: "bin",
			},
			CLAVE,
		),
		regla: "binary-unknown",
		tipo: "binario",
		archivo,
		linea: 0,
		columna: 0,
		fragmento: "****",
	};
}

/** Whole `.mct` as path -> sha256 + mode, ignoring logs/tmp (append-only audit, scratch). */
async function snapshot(dir = raiz, rel = ""): Promise<Record<string, string>> {
	const out: Record<string, string> = {};
	for (const e of await readdir(join(dir, rel), { withFileTypes: true })) {
		const r = rel === "" ? e.name : `${rel}/${e.name}`;
		if (r === "logs" || r === "tmp") continue;
		if (e.isDirectory()) {
			out[`${r}/`] = "dir";
			Object.assign(out, await snapshot(dir, r));
		} else {
			const full = join(dir, r);
			const mode = (await stat(full)).mode & 0o777;
			out[r] = `${createHash("sha256")
				.update(await readFile(full))
				.digest("hex")}:${mode.toString(8)}`;
		}
	}
	return out;
}

async function sembrar(): Promise<Finding[]> {
	const t1 = `a="${SECRET}"\n`;
	const t2 = `b="${SECRET_B}"\n`;
	await put("a.ts", t1);
	await put("b.ts", t2);
	await put("assets/blob.bin", Buffer.from([0, 1, 2, 3, 0, 255]));
	await chmod(join(work, "a.ts"), 0o755);
	const hallazgos = [
		finding("a.ts", t1, SECRET),
		finding("b.ts", t2, SECRET_B),
		binario("assets/blob.bin"),
	];
	await writeFile(
		join(raiz, "findings.json"),
		JSON.stringify({
			schemaVersion: 2,
			mctVersion: "0.0.0",
			gitleaksVersion: "8.30.1",
			generadoEn: T0,
			hallazgos,
		}),
	);
	return hallazgos;
}

function rescanDe(hallazgos: Finding[]): SanitizeOptions["rescan"] {
	return async () => {
		const out: Finding[] = [];
		for (const f of hallazgos) {
			const txt = await readFile(join(work, f.archivo)).catch(() => null);
			if (txt === null) continue;
			if (
				f.tipo === "binario" ||
				txt.toString("utf8").includes(f.archivo === "a.ts" ? SECRET : SECRET_B)
			) {
				out.push({ ...f });
			}
		}
		return { hallazgos: out, gitleaksVersion: "8.30.1" };
	};
}

function decisor(fn: (h: Finding) => Promise<Decision> | Decision): Decisor {
	return { decidir: async (h) => fn(h), confirmar: async () => true };
}

function opts(
	over: Partial<SanitizeOptions> & Pick<SanitizeOptions, "decisor" | "rescan">,
): SanitizeOptions {
	return {
		raiz,
		tty: true,
		mctVersion: "0.0.0",
		now: () => T0,
		usuario: () => "tester",
		...over,
	};
}

async function sinRastros() {
	await expect(stat(join(raiz, "lock"))).rejects.toThrow();
	const tmp = await readdir(join(raiz, "tmp")).catch(() => []);
	expect(tmp.filter((n) => n.startsWith("sanitize-"))).toEqual([]);
}

let CLAVE: Uint8Array;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t19i-"));
	raiz = join(base, ".mct");
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "x" },
		adapter: "node",
		now: () => T0,
	});
	CLAVE = await leerClave(raiz);
	work = join(raiz, "work");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("sanitize · Ctrl+C", () => {
	it("SAN-006 Ctrl+C a mitad de la revisión sale con 130 y deja el workspace como antes", async () => {
		const hallazgos = await sembrar();
		const antes = await snapshot();
		const ctl = new AbortController();
		let n = 0;
		const d = decisor((h) => {
			n++;
			if (n === 3) ctl.abort();
			return h.tipo === "binario"
				? { accion: "reemplazar" }
				: { accion: "reemplazar" };
		});
		const err = await sanitize(
			opts({ decisor: d, rescan: rescanDe(hallazgos), signal: ctl.signal }),
		).catch((e) => e);
		expect(err).toBeInstanceOf(MctError);
		expect(err.codigo).toBe("INTERRUMPIDO");
		expect(err.exit).toBe(130);
		expect(await snapshot()).toEqual(antes);
		await sinRastros();
	});

	it("SAN-006 Ctrl+C con una pregunta pendiente corta sin esperar la respuesta", async () => {
		const hallazgos = await sembrar();
		const antes = await snapshot();
		const ctl = new AbortController();
		const d = decisor(
			() =>
				new Promise<Decision>(() => {
					setTimeout(() => ctl.abort(), 10);
				}),
		);
		const err = await sanitize(
			opts({ decisor: d, rescan: rescanDe(hallazgos), signal: ctl.signal }),
		).catch((e) => e);
		expect(err.exit).toBe(130);
		expect(await snapshot()).toEqual(antes);
		await sinRastros();
	});

	it("SAN-006 Ctrl+C durante el re-scan restaura archivos editados, binarios borrados y modos", async () => {
		const hallazgos = await sembrar();
		const antes = await snapshot();
		const ctl = new AbortController();
		const base = rescanDe(hallazgos);
		let llamadas = 0;
		const rescan: SanitizeOptions["rescan"] = async (ctx) => {
			llamadas++;
			// first call = initial scan; second = after the edits and deletions were applied
			if (llamadas === 2) {
				expect(await readFile(join(work, "a.ts"), "utf8")).not.toContain(
					SECRET,
				);
				await expect(stat(join(work, "assets/blob.bin"))).rejects.toThrow();
				ctl.abort();
			}
			return base(ctx);
		};
		const err = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan,
				signal: ctl.signal,
			}),
		).catch((e) => e);
		expect(err.exit).toBe(130);
		expect(llamadas).toBe(2);
		expect(await snapshot()).toEqual(antes);
		expect(await readFile(join(work, "a.ts"), "utf8")).toContain(SECRET);
		await expect(stat(join(work, ".env.example"))).rejects.toThrow();
		await sinRastros();
	});

	it("SAN-006 Ctrl+C antes de empezar no toca nada", async () => {
		const hallazgos = await sembrar();
		const antes = await snapshot();
		const ctl = new AbortController();
		ctl.abort();
		const err = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan: rescanDe(hallazgos),
				signal: ctl.signal,
			}),
		).catch((e) => e);
		expect(err.exit).toBe(130);
		expect(await snapshot()).toEqual(antes);
		await sinRastros();
	});

	it("SAN-006 un fallo del motor a mitad de la etapa también restaura el workspace", async () => {
		const hallazgos = await sembrar();
		const antes = await snapshot();
		const base = rescanDe(hallazgos);
		let llamadas = 0;
		const rescan: SanitizeOptions["rescan"] = async (ctx) => {
			if (++llamadas === 2) {
				throw new MctError("MOTOR_NO_DISPONIBLE", "gitleaks falló");
			}
			return base(ctx);
		};
		await expect(
			sanitize(
				opts({
					decisor: decisor(() => ({ accion: "reemplazar" })),
					rescan,
				}),
			),
		).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
		expect(await snapshot()).toEqual(antes);
		await sinRastros();
	});

	it("SAN-006 tras una interrupción se puede volver a correr y termina bien", async () => {
		const hallazgos = await sembrar();
		const ctl = new AbortController();
		let n = 0;
		await sanitize(
			opts({
				decisor: decisor(() => {
					if (++n === 2) ctl.abort();
					return { accion: "reemplazar" };
				}),
				rescan: rescanDe(hallazgos),
				signal: ctl.signal,
			}),
		).catch(() => undefined);
		const res = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "reemplazar" })),
				rescan: rescanDe(hallazgos),
			}),
		);
		expect(res.abiertos).toBe(0);
		expect(res.aprobacion?.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
		const a = await readFile(join(work, "a.ts"), "utf8");
		expect(a).not.toContain(SECRET);
	});

	it("SAN-006 el lock lo toma una sola corrida y se libera al terminar", async () => {
		const hallazgos = await sembrar();
		let lockVisto = false;
		const res = await sanitize(
			opts({
				decisor: decisor(async () => {
					lockVisto = await stat(join(raiz, "lock")).then(
						() => true,
						() => false,
					);
					return { accion: "reemplazar" };
				}),
				rescan: rescanDe(hallazgos),
			}),
		);
		expect(res.abiertos).toBe(0);
		expect(lockVisto).toBe(true);
		await sinRastros();
	});
});
