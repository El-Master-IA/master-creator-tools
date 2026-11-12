import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

describe("smoke", () => {
	it("T39 el runner de tests arranca", async () => {
		expect(1 + 1).toBe(2);
	});

	it("T39 node calcula un digest sha256", async () => {
		const digest = createHash("sha256").update("mct").digest("hex");
		expect(digest).toHaveLength(64);
	});
});
