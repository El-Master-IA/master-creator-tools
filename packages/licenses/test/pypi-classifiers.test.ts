import { describe, expect, it } from "vitest";
import classifiers from "../data/pypi-classifiers.json" with { type: "json" };
import {
	isValidSpdx,
	loadClassifierTable,
	normalizePypiName,
	spdxFromClassifiers,
	spdxFromPypiInfo,
} from "../src/pypi.js";
import { verdictForSpdx } from "../src/verdict.js";

describe("LIC-005 classifier table", () => {
	it("LIC-005 every key is a License classifier and every value a valid SPDX or null", () => {
		for (const [key, value] of Object.entries(classifiers)) {
			expect(key.startsWith("License ::")).toBe(true);
			if (value !== null) expect(isValidSpdx(value)).toBe(true);
		}
		expect(Object.keys(loadClassifierTable()).length).toBeGreaterThan(20);
	});

	it("LIC-005 ambiguous BSD and Apache classifiers give revisar (no SPDX)", () => {
		expect(
			spdxFromClassifiers(["License :: OSI Approved :: BSD License"]),
		).toBeUndefined();
		expect(
			spdxFromClassifiers([
				"License :: OSI Approved :: Apache Software License",
			]),
		).toBeUndefined();
	});

	it("LIC-005 a clear classifier maps to its SPDX and the verdict table applies", () => {
		const mit = spdxFromClassifiers([
			"Programming Language :: Python :: 3",
			"License :: OSI Approved",
			"License :: OSI Approved :: MIT License",
		]);
		expect(mit).toBe("MIT");
		expect(verdictForSpdx(mit)).toBe("ok");
		const gpl = spdxFromClassifiers([
			"License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
		]);
		expect(verdictForSpdx(gpl)).toBe("bloquea");
	});

	it("LIC-005 unknown or mixed license classifiers stay undecided", () => {
		expect(spdxFromClassifiers(["License :: Made Up"])).toBeUndefined();
		expect(
			spdxFromClassifiers([
				"License :: OSI Approved :: MIT License",
				"License :: OSI Approved :: ISC License (ISCL)",
			]),
		).toBeUndefined();
		expect(spdxFromClassifiers(undefined)).toBeUndefined();
	});

	it("LIC-005 SPDX order: license_expression, then license if valid, then classifiers", () => {
		const classifiersMit = ["License :: OSI Approved :: MIT License"];
		expect(
			spdxFromPypiInfo({
				license_expression: "Apache-2.0",
				license: "MIT",
				classifiers: classifiersMit,
			}),
		).toBe("Apache-2.0");
		expect(
			spdxFromPypiInfo({
				license_expression: null,
				license: "BSD-3-Clause",
				classifiers: classifiersMit,
			}),
		).toBe("BSD-3-Clause");
		expect(
			spdxFromPypiInfo({
				license: "Permission is hereby granted, free of charge, to any person",
				classifiers: classifiersMit,
			}),
		).toBe("MIT");
		expect(spdxFromPypiInfo({ license: "BSD" })).toBeUndefined();
	});

	it("LIC-005 names follow PEP 503", () => {
		expect(normalizePypiName("Foo_Bar.baz--Qux")).toBe("foo-bar-baz-qux");
	});
});
