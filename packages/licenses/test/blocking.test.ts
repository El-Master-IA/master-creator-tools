import { describe, expect, it } from "vitest";
import { gateExit, judgePackage, verdictForSpdx } from "../src/verdict.js";

const dep = (paquete: string, spdx: string | undefined) => ({
	paquete,
	version: "1.0.0",
	spdx,
	origen: "directa" as const,
});

describe("LIC-001 verdict table", () => {
	it("LIC-001 GPL, AGPL, SSPL and proprietary block", () => {
		for (const id of [
			"GPL-3.0",
			"GPL-2.0-only",
			"GPL-3.0-or-later",
			"GPL-2.0+",
			"AGPL-3.0",
			"AGPL-3.0-only",
			"SSPL-1.0",
			"UNLICENSED",
		]) {
			expect(verdictForSpdx(id), id).toBe("bloquea");
		}
	});

	it("LIC-001 LGPL, MPL, EPL and CC-BY-SA need review", () => {
		for (const id of [
			"LGPL-3.0",
			"LGPL-2.1-only",
			"MPL-2.0",
			"EPL-2.0",
			"CC-BY-SA-4.0",
		]) {
			expect(verdictForSpdx(id), id).toBe("revisar");
		}
	});

	it("LIC-001 permissive licenses are ok", () => {
		for (const id of [
			"MIT",
			"ISC",
			"BSD-2-Clause",
			"BSD-3-Clause",
			"Apache-2.0",
			"0BSD",
			"Unlicense",
			"CC0-1.0",
		]) {
			expect(verdictForSpdx(id), id).toBe("ok");
		}
	});

	it("LIC-001 missing license or unrecognized SPDX is revisar", () => {
		expect(verdictForSpdx(undefined)).toBe("revisar");
		expect(verdictForSpdx(null)).toBe("revisar");
		expect(verdictForSpdx("")).toBe("revisar");
		expect(verdictForSpdx("   ")).toBe("revisar");
		expect(verdictForSpdx("Foo-License")).toBe("revisar");
		expect(verdictForSpdx("SEE LICENSE IN LICENSE.md")).toBe("revisar");
		expect(verdictForSpdx("LicenseRef-custom")).toBe("revisar");
		expect(verdictForSpdx("CC-BY-NC-4.0")).toBe("revisar");
	});

	it("LIC-001 invalid expressions fail closed to revisar", () => {
		for (const bad of [
			"MIT OR",
			"(MIT",
			"MIT AND",
			"OR MIT",
			"mit",
			"MIT GPL",
		]) {
			expect(verdictForSpdx(bad), bad).toBe("revisar");
		}
		expect(verdictForSpdx({} as unknown as string)).toBe("revisar");
	});

	it("LIC-001 OR takes the most permissive and AND the most restrictive", () => {
		expect(verdictForSpdx("(MIT OR GPL-3.0)")).toBe("ok");
		expect(verdictForSpdx("GPL-3.0 OR LGPL-3.0")).toBe("revisar");
		expect(verdictForSpdx("MIT AND GPL-3.0")).toBe("bloquea");
		expect(verdictForSpdx("MIT AND LGPL-3.0")).toBe("revisar");
		expect(verdictForSpdx("(MIT OR GPL-3.0) AND LGPL-3.0")).toBe("revisar");
		expect(verdictForSpdx("MIT AND GPL-3.0 OR ISC")).toBe("ok");
		expect(verdictForSpdx("Foo-License OR GPL-3.0")).toBe("revisar");
		expect(verdictForSpdx("MIT AND Foo-License")).toBe("revisar");
	});

	it("LIC-001 exit is 10 when anything blocks or needs review, else 0", () => {
		const ok = judgePackage(dep("a", "MIT"), []);
		const rev = judgePackage(dep("b", undefined), []);
		const blk = judgePackage(dep("c", "GPL-3.0"), []);
		expect(gateExit([ok])).toBe(0);
		expect(gateExit([ok, rev])).toBe(10);
		expect(gateExit([ok, blk])).toBe(10);
		expect(gateExit([])).toBe(0);
	});
});
