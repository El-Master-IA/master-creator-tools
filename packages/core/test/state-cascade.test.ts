import type { Finding, State } from "@mct/contract/types";
import { describe, expect, it } from "vitest";
import { applyCascade, ETAPAS, reconcileFindings } from "../src/workspace.js";

const T0 = "2026-11-08T00:00:00.000Z";
const T1 = "2026-11-08T01:00:00.000Z";

function estadoOk(): State {
	const etapas = {} as State["etapas"];
	for (const e of ETAPAS) etapas[e] = { estado: "ok", ts: T0 };
	return {
		schemaVersion: 1,
		mctVersion: "0.0.0",
		origen: { tipo: "carpeta", ref: "x" },
		adapter: "node",
		workSha256: "a".repeat(64),
		distSha256: "b".repeat(64),
		verificado: null,
		etapas,
	};
}

const hallazgo = (id: string, estado: Finding["estado"]): Finding => ({
	id,
	motor: "mct",
	regla: "r",
	tipo: "secreto",
	zona: "work",
	archivo: "a.ts",
	linea: 1,
	columna: 1,
	fragmento: "ab**",
	severidad: "alto",
	estado,
});

describe("cascada de estado", () => {
	it("STATE-001 cambia workSha256 y sanitize, licenses, package y verify pasan a pendiente", () => {
		const next = applyCascade(estadoOk(), { workSha256: "c".repeat(64) }, T1);
		for (const e of ["sanitize", "licenses", "package", "verify"] as const) {
			expect(next.etapas[e]).toEqual({ estado: "pendiente", ts: T1 });
		}
		expect(next.etapas.scan.estado).toBe("ok");
		expect(next.etapas.publish.estado).toBe("ok");
		expect(next.workSha256).toBe("c".repeat(64));
	});

	it("STATE-001 mismo workSha256 no cambia nada", () => {
		const s = estadoOk();
		expect(applyCascade(s, { workSha256: s.workSha256 }, T1)).toEqual(s);
	});

	it("STATE-001 package regenera dist y solo verify pasa a pendiente", () => {
		const next = applyCascade(estadoOk(), { distSha256: "d".repeat(64) }, T1);
		expect(next.etapas.verify.estado).toBe("pendiente");
		expect(next.etapas.package.estado).toBe("ok");
		expect(next.etapas.sanitize.estado).toBe("ok");
		expect(next.distSha256).toBe("d".repeat(64));
	});

	it("STATE-001 hallazgo decidido que no reaparece pasa a obsoleto sin borrarse", () => {
		const previos = [
			hallazgo("1", "resuelto"),
			hallazgo("2", "falso-positivo"),
			hallazgo("3", "aceptado"),
			hallazgo("4", "falso-positivo"),
		];
		const out = reconcileFindings(previos, [hallazgo("4", "abierto")]);
		expect(out.map((f) => [f.id, f.estado])).toEqual([
			["1", "obsoleto"],
			["2", "obsoleto"],
			["3", "obsoleto"],
			["4", "falso-positivo"],
		]);
	});

	it("STATE-001 resuelto que el re-scan vuelve a encontrar pasa a abierto; aceptado conserva", () => {
		const out = reconcileFindings(
			[hallazgo("1", "resuelto"), hallazgo("2", "aceptado")],
			[hallazgo("1", "abierto"), hallazgo("2", "abierto")],
		);
		expect(out.map((f) => [f.id, f.estado])).toEqual([
			["1", "abierto"],
			["2", "aceptado"],
		]);
	});

	it("STATE-001 obsoleto que reaparece vuelve a abierto y los nuevos se agregan", () => {
		const out = reconcileFindings(
			[hallazgo("1", "obsoleto")],
			[hallazgo("1", "abierto"), hallazgo("9", "abierto")],
		);
		expect(out.map((f) => [f.id, f.estado])).toEqual([
			["1", "abierto"],
			["9", "abierto"],
		]);
	});
});
