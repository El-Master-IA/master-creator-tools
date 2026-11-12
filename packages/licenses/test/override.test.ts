import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import { gateExit, judgePackage, parseAllow } from "../src/verdict.js";

const dep = (spdx: string | undefined) => ({
	paquete: "some-dep",
	version: "2.0.0",
	spdx,
	origen: "transitiva" as const,
});

function catchError(fn: () => unknown): unknown {
	try {
		fn();
	} catch (e) {
		return e;
	}
	return undefined;
}

describe("LIC-003 licenses.allow overrides", () => {
	it("LIC-003 an allow entry with motivo accepts the SPDX and shows the override", () => {
		const allow = parseAllow({
			licenses: {
				allow: [{ spdx: "GPL-3.0", motivo: "solo herramienta de desarrollo" }],
			},
		});
		const entry = judgePackage(dep("GPL-3.0"), allow);
		expect(entry.veredicto).toBe("ok");
		expect(entry.override).toEqual({
			motivo: "solo herramienta de desarrollo",
		});
		expect(gateExit([entry])).toBe(0);
	});

	it("LIC-003 revisar stays closed until allowed", () => {
		const closed = judgePackage(dep("MPL-2.0"), parseAllow({}));
		expect(closed.veredicto).toBe("revisar");
		expect(closed.override).toBeUndefined();
		const allowed = judgePackage(
			dep("MPL-2.0"),
			parseAllow({
				licenses: {
					allow: [{ spdx: "MPL-2.0", motivo: "revisado por legal" }],
				},
			}),
		);
		expect(allowed.veredicto).toBe("ok");
		expect(allowed.override?.motivo).toBe("revisado por legal");
	});

	it("LIC-003 an unrelated allow entry does not accept other licenses", () => {
		const allow = parseAllow({
			licenses: { allow: [{ spdx: "MPL-2.0", motivo: "motivo valido" }] },
		});
		const entry = judgePackage(dep("GPL-3.0"), allow);
		expect(entry.veredicto).toBe("bloquea");
		expect(entry.override).toBeUndefined();
		expect(judgePackage(dep(undefined), allow).veredicto).toBe("revisar");
		expect(judgePackage(dep("Foo-License"), allow).veredicto).toBe("revisar");
	});

	it("LIC-003 a different GPL version is not accepted by an exact allow", () => {
		const allow = parseAllow({
			licenses: { allow: [{ spdx: "GPL-2.0-only", motivo: "motivo valido" }] },
		});
		expect(judgePackage(dep("GPL-3.0-only"), allow).veredicto).toBe("bloquea");
	});

	it("LIC-003 override applies per leaf inside expressions", () => {
		const allow = parseAllow({
			licenses: { allow: [{ spdx: "LGPL-3.0", motivo: "enlace dinamico" }] },
		});
		const entry = judgePackage(dep("MIT AND LGPL-3.0"), allow);
		expect(entry.veredicto).toBe("ok");
		expect(entry.override?.motivo).toBe("enlace dinamico");
		expect(judgePackage(dep("GPL-3.0 AND LGPL-3.0"), allow).veredicto).toBe(
			"bloquea",
		);
	});

	it("LIC-003 an already ok package carries no override", () => {
		const allow = parseAllow({
			licenses: { allow: [{ spdx: "GPL-3.0", motivo: "motivo valido" }] },
		});
		expect(judgePackage(dep("MIT"), allow).override).toBeUndefined();
	});

	it("LIC-003 override without motivo fails with VALIDACION", () => {
		for (const bad of [
			{ spdx: "GPL-3.0" },
			{ spdx: "GPL-3.0", motivo: "" },
			{ spdx: "GPL-3.0", motivo: "   " },
			{ spdx: "GPL-3.0", motivo: 5 },
			{ spdx: "GPL-3.0", motivo: "." },
			{ spdx: "GPL-3.0", motivo: "​​​​​​" },
			{ spdx: "GPL-3.0", motivo: "ab‮​cd" },
		]) {
			const caught = catchError(() =>
				parseAllow({ licenses: { allow: [bad] } }),
			);
			expect(caught).toBeInstanceOf(MctError);
			expect((caught as MctError).codigo).toBe("VALIDACION");
			expect((caught as MctError).exit).toBe(2);
		}
	});

	it("LIC-003 malformed allow entries fail with VALIDACION", () => {
		for (const bad of [
			{ licenses: { allow: "GPL-3.0" } },
			{ licenses: { allow: [null] } },
			{ licenses: { allow: [{ motivo: "motivo valido" }] } },
			{
				licenses: { allow: [{ spdx: "Foo-License", motivo: "motivo valido" }] },
			},
			{
				licenses: {
					allow: [{ spdx: "MIT OR GPL-3.0", motivo: "motivo valido" }],
				},
			},
			{ licenses: "nope" },
		]) {
			const caught = catchError(() => parseAllow(bad));
			expect(caught).toBeInstanceOf(MctError);
			expect((caught as MctError).codigo).toBe("VALIDACION");
		}
	});

	it("LIC-003 an allow scoped with paquetes only accepts those packages", () => {
		const allow = parseAllow({
			licenses: {
				allow: [
					{
						spdx: "MPL-2.0",
						motivo: "solo dependencia de desarrollo",
						paquetes: ["lightningcss", "lightningcss"],
					},
				],
			},
		});
		expect(allow[0]?.paquetes).toEqual(["lightningcss"]);
		const scoped = judgePackage(
			{ ...dep("MPL-2.0"), paquete: "lightningcss" },
			allow,
		);
		expect(scoped.veredicto).toBe("ok");
		expect(scoped.override?.motivo).toBe("solo dependencia de desarrollo");
		const other = judgePackage(dep("MPL-2.0"), allow);
		expect(other.veredicto).toBe("revisar");
		expect(other.override).toBeUndefined();
		expect(gateExit([scoped, other])).not.toBe(0);
	});

	it("LIC-003 malformed paquetes fail with VALIDACION", () => {
		for (const paquetes of [
			[],
			"lightningcss",
			[""],
			[42],
			["../evil"],
			["a b"],
			["x[31m"],
			Array.from({ length: 201 }, (_, i) => `p${i}`),
		]) {
			const caught = catchError(() =>
				parseAllow({
					licenses: {
						allow: [{ spdx: "MPL-2.0", motivo: "motivo valido", paquetes }],
					},
				}),
			);
			expect(caught).toBeInstanceOf(MctError);
			expect((caught as MctError).codigo).toBe("VALIDACION");
		}
		expect(
			parseAllow({
				licenses: {
					allow: [
						{
							spdx: "MPL-2.0",
							motivo: "motivo valido",
							paquetes: ["@scope/pkg.name_x-1"],
						},
					],
				},
			})[0]?.paquetes,
		).toEqual(["@scope/pkg.name_x-1"]);
	});

	it("LIC-003 no config or no licenses key means no overrides", () => {
		expect(parseAllow(undefined)).toEqual([]);
		expect(parseAllow({})).toEqual([]);
		expect(parseAllow({ licenses: {} })).toEqual([]);
	});
});
