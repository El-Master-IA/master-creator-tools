import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@mct/contract/types";
import { findingId } from "@mct/scanner/finding-id";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	invalidateApproval,
	signApproval,
	verifyApproval,
} from "../src/approval.js";
import { hashTree } from "../src/hash.js";
import {
	type Decision,
	type Decisor,
	type SanitizeOptions,
	sanitize,
} from "../src/sanitize.js";
import { createWorkspace, readState } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
// Synthetic values built from fragments (T05).
const SECRET = ["tok", "en-", "a1b2c3d4e5f6a7b8c9d0"].join("");
const FP = "Es un dato de ejemplo del manual";

let base: string;
let raiz: string;
let work: string;

async function put(rel: string, content: string) {
	const full = join(work, ...rel.split("/"));
	await mkdir(dirname(full), { recursive: true });
	await writeFile(full, content);
}

function hallazgo(
	id: string,
	estado: Finding["estado"],
	zona: Finding["zona"] = "work",
): Finding {
	return {
		id,
		motor: "mct",
		regla: "generic-token",
		tipo: "secreto",
		zona,
		archivo: "a.ts",
		linea: 1,
		columna: 1,
		fragmento: "tok****",
		severidad: "critico",
		estado,
	};
}

const idOf = (n: string) =>
	findingId({ motor: "mct", regla: "r", archivo: n, linea: 1, value: n });

function sign(hallazgos: Finding[]) {
	return signApproval({
		raiz,
		hallazgos,
		gitleaksVersion: "8.30.1",
		mctVersion: "0.0.0",
		now: () => T0,
		user: () => "tester",
	});
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t19a-"));
	raiz = join(base, ".mct");
	await createWorkspace(raiz, {
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "x" },
		adapter: "node",
		now: () => T0,
	});
	work = join(raiz, "work");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("approval · firma", () => {
	it("SAN-003 con cero abiertos firma approval.json con el hash SHA256 del árbol", async () => {
		await put("a.ts", "export const a = 1;\n");
		const a = idOf("a");
		const b = idOf("b");
		const res = await sign([
			hallazgo(a, "resuelto"),
			hallazgo(b, "falso-positivo"),
			hallazgo(idOf("c"), "obsoleto"),
		]);
		const disco = JSON.parse(
			await readFile(join(raiz, "approval.json"), "utf8"),
		);
		expect(disco).toEqual(res);
		expect(disco.arbolSha256).toBe(await hashTree(work));
		expect(disco.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
		expect(disco.hallazgosDecididos).toEqual([a, b].sort());
		expect(disco).toMatchObject({
			schemaVersion: 1,
			aprobadoPor: "tester",
			aprobadoEn: T0,
			mctVersion: "0.0.0",
			gitleaksVersion: "8.30.1",
		});
		expect(Object.keys(disco).sort()).toEqual(
			[
				"aprobadoEn",
				"aprobadoPor",
				"arbolSha256",
				"gitleaksVersion",
				"hallazgosDecididos",
				"mctVersion",
				"schemaVersion",
			].sort(),
		);
	});

	it("SAN-003 los aislados no cuentan como abiertos", async () => {
		await put("a.ts", "x\n");
		await expect(
			sign([hallazgo(idOf("q"), "aislado", "quarantine")]),
		).resolves.toMatchObject({ hallazgosDecididos: [] });
	});

	it("SAN-003 con un abierto no firma: PUERTA_BLOQUEADA y sin archivo", async () => {
		await put("a.ts", "x\n");
		await expect(sign([hallazgo(idOf("a"), "abierto")])).rejects.toMatchObject({
			codigo: "PUERTA_BLOQUEADA",
			detalle: { abiertos: 1 },
		});
		await expect(stat(join(raiz, "approval.json"))).rejects.toThrow();
	});
});

describe("approval · verificación (falla cerrado)", () => {
	async function aprobar() {
		await put("a.ts", "uno\n");
		await put("sub/b.ts", "dos\n");
		const res = await sign([]);
		const st = await readState(raiz);
		const { writeState } = await import("../src/workspace.js");
		await writeState(raiz, {
			...st,
			workSha256: res.arbolSha256,
			etapas: { ...st.etapas, sanitize: { estado: "ok", ts: T0 } },
		});
		return res;
	}

	it("SAN-003 un árbol sin cambios verifica", async () => {
		const res = await aprobar();
		await expect(verifyApproval(raiz)).resolves.toEqual(res);
	});

	it.each([
		["un byte editado", async () => put("a.ts", "unp\n")],
		["un archivo nuevo", async () => put("nuevo.txt", "")],
		["un archivo borrado", async () => rm(join(work, "sub", "b.ts"))],
		["un archivo vacío agregado", async () => put("sub/otro/vacio.txt", "")],
		[
			"un archivo renombrado",
			async () => {
				const { rename } = await import("node:fs/promises");
				await rename(join(work, "a.ts"), join(work, "z.ts"));
			},
		],
	])(
		"SAN-003 %s invalida la aprobación (APROBACION_DESACTUALIZADA)",
		async (_n, cambio) => {
			await aprobar();
			await cambio();
			await expect(verifyApproval(raiz)).rejects.toMatchObject({
				codigo: "APROBACION_DESACTUALIZADA",
				exit: 11,
			});
		},
	);

	it("SAN-003 un approval.json con hash editado a mano no verifica", async () => {
		await aprobar();
		const file = join(raiz, "approval.json");
		const a = JSON.parse(await readFile(file, "utf8"));
		a.arbolSha256 = "0".repeat(64);
		await writeFile(file, JSON.stringify(a));
		await expect(verifyApproval(raiz)).rejects.toMatchObject({
			codigo: "APROBACION_DESACTUALIZADA",
		});
	});

	it.each([
		["ausente", async () => invalidateApproval(raiz)],
		["vacío", async () => writeFile(join(raiz, "approval.json"), "")],
		["no JSON", async () => writeFile(join(raiz, "approval.json"), "{{")],
		["sin campos", async () => writeFile(join(raiz, "approval.json"), "{}\n")],
		[
			"con hash que no es sha256",
			async () => {
				const file = join(raiz, "approval.json");
				const a = JSON.parse(await readFile(file, "utf8"));
				a.arbolSha256 = "xyz";
				await writeFile(file, JSON.stringify(a));
			},
		],
	])("SAN-003 un approval.json %s no verifica", async (_n, rompe) => {
		await aprobar();
		await rompe();
		await expect(verifyApproval(raiz)).rejects.toMatchObject({
			codigo: "APROBACION_DESACTUALIZADA",
		});
	});

	it("SAN-003 un schemaVersion desconocido falla con WORKSPACE_INVALIDO", async () => {
		await aprobar();
		const file = join(raiz, "approval.json");
		const a = JSON.parse(await readFile(file, "utf8"));
		a.schemaVersion = 99;
		await writeFile(file, JSON.stringify(a));
		await expect(verifyApproval(raiz)).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
		});
	});

	it("SAN-003 si la etapa sanitize no está ok la aprobación no vale", async () => {
		await aprobar();
		const st = await readState(raiz);
		const { writeState } = await import("../src/workspace.js");
		await writeState(raiz, {
			...st,
			etapas: { ...st.etapas, sanitize: { estado: "pendiente", ts: T0 } },
		});
		await expect(verifyApproval(raiz)).rejects.toMatchObject({
			codigo: "APROBACION_DESACTUALIZADA",
		});
	});
});

describe("approval · sanitize y --reopen", () => {
	function decisor(fn: (h: Finding) => Decision | Promise<Decision>): Decisor {
		return {
			decidir: async (h) => fn(h),
			confirmar: async () => true,
		};
	}

	const sinDecisiones = decisor(() => ({ accion: "abortar" }));

	function opts(
		over: Partial<SanitizeOptions> & Pick<SanitizeOptions, "decisor">,
	): SanitizeOptions {
		return {
			raiz,
			tty: true,
			mctVersion: "0.0.0",
			now: () => T0,
			usuario: () => "tester",
			rescan: async () => ({ hallazgos: [], gitleaksVersion: "8.30.1" }),
			...over,
		};
	}

	async function guardaFindings(hallazgos: Finding[]) {
		await writeFile(
			join(raiz, "findings.json"),
			JSON.stringify({
				schemaVersion: 1,
				mctVersion: "0.0.0",
				gitleaksVersion: "8.30.1",
				generadoEn: T0,
				hallazgos,
			}),
		);
	}

	/** A tree holding one value that the re-scan keeps reporting; first run marks it falso-positivo. */
	async function firmadoConFalsoPositivo() {
		await put("a.ts", `x="${SECRET}"\n`);
		const f = hallazgo(
			findingId({
				motor: "mct",
				regla: "generic-token",
				archivo: "a.ts",
				linea: 1,
				value: SECRET,
			}),
			"abierto",
		);
		await guardaFindings([f]);
		const rescan: SanitizeOptions["rescan"] = async () => ({
			hallazgos: [{ ...f }],
			gitleaksVersion: "8.30.1",
		});
		const res = await sanitize(
			opts({
				decisor: decisor(() => ({ accion: "falso-positivo", motivo: FP })),
				rescan,
			}),
		);
		return { f, rescan, res };
	}

	it("SAN-003 correrlo con cero abiertos solo vuelve a firmar el mismo hash", async () => {
		await put("a.ts", "ok\n");
		await guardaFindings([]);
		const r1 = await sanitize(opts({ decisor: sinDecisiones }));
		const r2 = await sanitize(opts({ decisor: sinDecisiones }));
		expect(r2.aprobacion?.arbolSha256).toBe(r1.aprobacion?.arbolSha256);
		await expect(verifyApproval(raiz)).resolves.toBeTruthy();
	});

	it("SAN-003 una decisión de falso positivo firma y la conserva en el re-scan", async () => {
		const { res } = await firmadoConFalsoPositivo();
		expect(res.decididos.falsoPositivo).toBe(1);
		expect(res.abiertos).toBe(0);
		await expect(verifyApproval(raiz)).resolves.toBeTruthy();
	});

	it("SAN-003 --reopen con un ID inexistente sale con VALIDACION sin tocar nada", async () => {
		const { rescan } = await firmadoConFalsoPositivo();
		const antes = await readFile(join(raiz, "approval.json"), "utf8");
		for (const id of ["f".repeat(64), "no-es-un-id", ""]) {
			await expect(
				sanitize(opts({ decisor: sinDecisiones, rescan, reopen: id })),
			).rejects.toMatchObject({ codigo: "VALIDACION", exit: 2 });
		}
		expect(await readFile(join(raiz, "approval.json"), "utf8")).toBe(antes);
		expect((await readState(raiz)).etapas.sanitize.estado).toBe("ok");
	});

	it("SAN-003 --reopen de un hallazgo aislado también sale con VALIDACION", async () => {
		await put("a.ts", "ok\n");
		const q = hallazgo(idOf("q"), "aislado", "quarantine");
		await guardaFindings([q]);
		await expect(
			sanitize(opts({ decisor: sinDecisiones, reopen: q.id })),
		).rejects.toMatchObject({ codigo: "VALIDACION" });
	});

	it("SAN-003 --reopen de un resuelto cuyo valor ya no existe sigue abierto y se presenta al Decisor", async () => {
		await put("a.ts", "ok\n");
		const f = hallazgo(idOf("r"), "resuelto");
		await guardaFindings([f]);
		await sign([f]);
		const visto: string[] = [];
		const d = decisor((h) => {
			visto.push(h.id);
			return { accion: "falso-positivo", motivo: FP };
		});
		const res = await sanitize(
			opts({
				decisor: d,
				reopen: f.id,
				rescan: async () => ({ hallazgos: [], gitleaksVersion: "8.30.1" }),
			}),
		);
		expect(visto).toEqual([f.id]);
		expect(res.abiertos).toBe(0);
	});

	it("SAN-003 --reopen devuelve el hallazgo a abierto, invalida approval.json y pone licenses, package y verify en pendiente", async () => {
		const { f, rescan } = await firmadoConFalsoPositivo();
		const st = await readState(raiz);
		const { writeState } = await import("../src/workspace.js");
		await writeState(raiz, {
			...st,
			etapas: {
				...st.etapas,
				licenses: { estado: "ok", ts: T0 },
				package: { estado: "ok", ts: T0 },
				verify: { estado: "ok", ts: T0 },
			},
		});
		const dentro: Record<string, unknown> = {};
		const res = await sanitize(
			opts({
				rescan,
				reopen: f.id,
				decisor: decisor(async (h) => {
					const s = await readState(raiz);
					dentro.visto = h.id;
					dentro.estado = h.estado;
					dentro.approval = await stat(join(raiz, "approval.json")).then(
						() => true,
						() => false,
					);
					dentro.etapas = [
						s.etapas.sanitize,
						s.etapas.licenses,
						s.etapas.package,
						s.etapas.verify,
					].map((e) => e.estado);
					return { accion: "aceptar", motivo: `${FP} (revisado de nuevo)` };
				}),
			}),
		);
		expect(dentro).toEqual({
			visto: f.id,
			estado: "abierto",
			approval: false,
			etapas: ["pendiente", "pendiente", "pendiente", "pendiente"],
		});
		expect(res.decididos.aceptado).toBe(1);
		const fin = await readState(raiz);
		expect(fin.etapas.sanitize.estado).toBe("ok");
		expect(fin.etapas.licenses.estado).toBe("pendiente");
		expect(fin.etapas.package.estado).toBe("pendiente");
		expect(fin.etapas.verify.estado).toBe("pendiente");
		await expect(verifyApproval(raiz)).resolves.toBeTruthy();
	});

	it("SAN-003 --reopen cancelado deja todo como estaba, incluida la firma", async () => {
		const { f, rescan } = await firmadoConFalsoPositivo();
		const antes = await readFile(join(raiz, "approval.json"), "utf8");
		await expect(
			sanitize(opts({ decisor: sinDecisiones, rescan, reopen: f.id })),
		).rejects.toMatchObject({ codigo: "CANCELADO" });
		expect(await readFile(join(raiz, "approval.json"), "utf8")).toBe(antes);
		await expect(verifyApproval(raiz)).resolves.toBeTruthy();
	});

	it("SAN-003 approval.json y el estado no contienen valores de secretos ni motivos", async () => {
		await firmadoConFalsoPositivo();
		for (const rel of ["approval.json", "state.json"]) {
			const txt = await readFile(join(raiz, rel), "utf8");
			expect(txt).not.toContain(SECRET);
			expect(txt).not.toContain(FP);
		}
	});
});
