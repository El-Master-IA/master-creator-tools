import { describe, expect, it } from "vitest";
import { PYTHON_IMAGE_REFS, PYTHON_IMAGES, UV_VERSION } from "../src/pins.js";

describe("ERR-005 pins de Python y uv", () => {
	it("ERR-005 cada imagen python lleva @sha256 de 64 hex", () => {
		expect(Object.keys(PYTHON_IMAGE_REFS).sort()).toEqual([
			"3.13-slim",
			"3.14-slim",
			"3.15-slim",
		]);
		for (const ref of Object.values(PYTHON_IMAGE_REFS)) {
			expect(ref).toMatch(/^python:3\.\d+-slim@sha256:[0-9a-f]{64}$/);
		}
	});

	it("ERR-005 PYTHON_IMAGES expone tag y digest por separado", () => {
		for (const [tag, digest] of Object.entries(PYTHON_IMAGES)) {
			expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
			expect(PYTHON_IMAGE_REFS[tag as keyof typeof PYTHON_IMAGES]).toBe(
				`python:${tag}@${digest}`,
			);
		}
	});

	it("ERR-005 uv es una versión exacta", () => {
		expect(UV_VERSION).toBe("0.13.7");
		expect(UV_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
	});
});
