import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { auditLicenses } from "../src/audit.js";

const repo = join(dirname(fileURLToPath(import.meta.url)), "../../..");

describe("LIC-004 the repo's own lockfile", () => {
	it("LIC-004 reads this repo's env pnpm-lock.yaml without error", async () => {
		const result = await auditLicenses({
			lockDir: repo,
			lockfile: "pnpm-lock.yaml",
			offline: true,
		});
		expect(result.entries.length).toBeGreaterThan(0);
		expect(result.entries.some((e) => e.paquete.startsWith("@pnpm/exe."))).toBe(
			false,
		);
	});
});
