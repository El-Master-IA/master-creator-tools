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
import type { Finding } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { reconcileFindings } from "../../core/src/workspace.js";
import type { Runner } from "../src/gitleaks.js";
import { scan } from "../src/scan.js";
import { buildFixture } from "./fixtures/build.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const c of cleanups.splice(0)) await c();
});

/** gitleaks falso: reporta cada ocurrencia literal de las agujas, con --redact. */
function fakeGitleaks(needles: readonly string[]): Runner {
	return async (_cmd, args) => {
		if (args.includes("version")) {
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		}
		const target = args[args.indexOf("dir") + 1] as string;
		const reportPath = args[args.indexOf("--report-path") + 1] as string;
		const out: unknown[] = [];
		const entries = await readdir(target, {
			recursive: true,
			withFileTypes: true,
		});
		for (const e of entries) {
			if (!e.isFile()) continue;
			const file = join(e.parentPath, e.name);
			const lines = (await readFile(file, "utf8")).split("\n");
			lines.forEach((line, i) => {
				for (const n of needles) {
					const at = line.indexOf(n);
					if (at >= 0) {
						// Semántica real de gitleaks 8.30.1 (detect/location.go): columnas
						// en bytes, base 1, y +1 de desfase fuera de la primera línea.
						const shift = i > 0 ? 1 : 0;
						const start = Buffer.byteLength(line.slice(0, at));
						out.push({
							RuleID: "generic-api-key",
							File: file,
							StartLine: i + 1,
							EndLine: i + 1,
							StartColumn: start + 1 + shift,
							EndColumn: start + Buffer.byteLength(n) + shift,
						});
					}
				}
			});
		}
		await writeFile(reportPath, JSON.stringify(out));
		return {
			code: out.length > 0 ? 2 : 0,
			signal: null,
			stdout: "",
			timedOut: false,
		};
	};
}

async function tmpDirs(): Promise<{ tmpDir: string; installDir: string }> {
	const base = await mkdtemp(join(tmpdir(), "mct-scan-"));
	cleanups.push(() => rm(base, { recursive: true, force: true }));
	await mkdir(join(base, "tmp"), { recursive: true });
	return { tmpDir: join(base, "tmp"), installDir: join(base, "bin") };
}

async function run(
	fx: { work: string; quarantine: string; truthValues: string[] },
	previos?: Finding[],
) {
	const dirs = await tmpDirs();
	return scan({
		work: fx.work,
		quarantine: fx.quarantine,
		...(previos === undefined ? {} : { previos, reconcile: reconcileFindings }),
		gitleaks: {
			binary: process.execPath,
			...dirs,
			run: fakeGitleaks(fx.truthValues),
		},
	});
}

async function fixture(name: "node" | "n8n") {
	const fx = await buildFixture(name);
	cleanups.push(() => fx.cleanup());
	return {
		work: fx.work,
		quarantine: fx.quarantine,
		truthValues: fx.truth.secrets.map((s) => s.value),
	};
}

describe("IDs estables y decisiones", () => {
	it("SCAN-009 re-escanear un árbol sin cambios produce los mismos IDs", async () => {
		const fx = await fixture("node");
		const a = await run(fx);
		const b = await run(fx);
		expect(a.hallazgos.length).toBeGreaterThan(0);
		expect(b.hallazgos.map((f) => f.id)).toEqual(a.hallazgos.map((f) => f.id));
		expect(new Set(a.hallazgos.map((f) => f.id)).size).toBe(a.hallazgos.length);
		for (const f of a.hallazgos) expect(f.id).toMatch(/^[0-9a-f]{64}$/);
	});

	it("SCAN-009 el mismo contenido en otra raíz produce los mismos IDs", async () => {
		const a = await run(await fixture("node"));
		const b = await run(await fixture("node"));
		expect(b.hallazgos.map((f) => f.id)).toEqual(a.hallazgos.map((f) => f.id));
	});

	it("SCAN-009 un re-scan conserva las decisiones previas", async () => {
		const fx = await fixture("node");
		const first = await run(fx);
		const open = first.hallazgos.filter((f) => f.estado === "abierto");
		const [fp, acc] = open;
		if (!fp || !acc) throw new Error("se esperaban dos hallazgos abiertos");
		const previos: Finding[] = first.hallazgos.map((f) =>
			f.id === fp.id
				? {
						...f,
						estado: "falso-positivo",
						motivo: "prueba",
						decidio: "u",
						decididoEn: "2026-01-01T00:00:00Z",
					}
				: f.id === acc.id
					? {
							...f,
							estado: "aceptado",
							motivo: "prueba",
							decidio: "u",
							decididoEn: "2026-01-01T00:00:00Z",
						}
					: f,
		);
		const again = await run(fx, previos);
		expect(again.hallazgos.map((f) => f.id).sort()).toEqual(
			first.hallazgos.map((f) => f.id).sort(),
		);
		expect(again.hallazgos.find((f) => f.id === fp.id)).toMatchObject({
			estado: "falso-positivo",
			motivo: "prueba",
			decidio: "u",
		});
		expect(again.hallazgos.find((f) => f.id === acc.id)).toMatchObject({
			estado: "aceptado",
		});
	});

	it("SCAN-009 un resuelto que reaparece se reabre y uno decidido que desaparece queda obsoleto", async () => {
		const fx = await fixture("node");
		const first = await run(fx);
		const [a] = first.hallazgos.filter((f) => f.estado === "abierto");
		if (!a) throw new Error("se esperaba un hallazgo abierto");
		const gone: Finding = {
			...a,
			id: "f".repeat(64),
			estado: "aceptado",
			motivo: "m",
		};
		const previos: Finding[] = [{ ...a, estado: "resuelto" }, gone];
		const again = await run(fx, previos);
		expect(again.hallazgos.find((f) => f.id === a.id)?.estado).toBe("abierto");
		expect(again.hallazgos.find((f) => f.id === gone.id)?.estado).toBe(
			"obsoleto",
		);
	});

	it("SCAN-009 los aislados se recalculan y no se arrastran del escaneo previo", async () => {
		const fx = await fixture("node");
		const first = await run(fx);
		const stale: Finding = {
			...(first.hallazgos[0] as Finding),
			id: "e".repeat(64),
			zona: "quarantine",
			estado: "aislado",
		};
		const again = await run(fx, [...first.hallazgos, stale]);
		expect(again.hallazgos.some((f) => f.id === stale.id)).toBe(false);
		expect(again.hallazgos.filter((f) => f.estado === "aislado").length).toBe(
			first.hallazgos.filter((f) => f.estado === "aislado").length,
		);
	});

	it("SCAN-009 sin función de conciliación un escaneo previo se rechaza", async () => {
		const fx = await fixture("node");
		const dirs = await tmpDirs();
		await expect(
			scan({
				work: fx.work,
				quarantine: fx.quarantine,
				previos: [],
				gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
			}),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
	});
});

describe("ID de gitleaks atado al secreto real (gitleaks 8.30.1)", () => {
	const make = (first: string, tail: string) =>
		[first, "kq", "Z9", "r", "T4", "mw", tail].join("");

	async function treeWithSecret(secret: string, lineIndex: number) {
		const base = await mkdtemp(join(tmpdir(), "mct-sid-"));
		cleanups.push(() => rm(base, { recursive: true, force: true }));
		const work = join(base, "work");
		await mkdir(work, { recursive: true });
		const lines = ["# cabecera", "uno = dos", "tres = cuatro", "# fin"];
		lines[lineIndex] = `clave = "${secret}" # nota`;
		await writeFile(join(work, "cfg.txt"), `${lines.join("\n")}\n`);
		return {
			work,
			quarantine: join(base, "quarantine"),
			truthValues: [secret],
		};
	}

	const gl = (r: { hallazgos: Finding[] }) =>
		r.hallazgos.filter((f) => f.motor === "gitleaks");

	it("SCAN-009 la columna de salida es la real, en la primera línea y fuera de ella", async () => {
		for (const lineIndex of [0, 2]) {
			const secret = make("A", "x");
			const [f] = gl(await run(await treeWithSecret(secret, lineIndex)));
			expect(f).toMatchObject({ linea: lineIndex + 1, columna: 10 });
			expect(f?.fragmento.startsWith(secret.slice(0, 4))).toBe(true);
			expect(f?.fragmento).not.toContain(secret);
		}
	});

	it("SCAN-009 rotar solo el primer o el último carácter del secreto cambia el ID", async () => {
		const ids = new Set<string>();
		for (const secret of [make("A", "x"), make("B", "x"), make("A", "y")]) {
			const found = gl(await run(await treeWithSecret(secret, 2)));
			expect(found).toHaveLength(1);
			ids.add(found[0]?.id ?? "");
		}
		expect(ids.size).toBe(3);
	});

	it("SCAN-009 un secreto rotado no hereda la decisión aceptado del anterior", async () => {
		const old = gl(await run(await treeWithSecret(make("A", "x"), 2)))[0];
		if (!old) throw new Error("se esperaba un hallazgo de gitleaks");
		const previos: Finding[] = [
			{
				...old,
				estado: "aceptado",
				motivo: "m",
				decidio: "u",
				decididoEn: "2026-01-01T00:00:00Z",
			},
		];
		const again = await run(await treeWithSecret(make("B", "x"), 2), previos);
		const fresh = gl(again)[0];
		expect(fresh?.id).not.toBe(old.id);
		expect(fresh?.estado).toBe("abierto");
		expect(again.hallazgos.find((f) => f.id === old.id)?.estado).toBe(
			"obsoleto",
		);
	});

	it("SCAN-009 el mismo secreto en otra raíz conserva el ID", async () => {
		const a = gl(await run(await treeWithSecret(make("A", "x"), 2)))[0];
		const b = gl(await run(await treeWithSecret(make("A", "x"), 2)))[0];
		expect(b?.id).toBe(a?.id);
	});
});
