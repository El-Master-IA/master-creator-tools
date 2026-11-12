import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["e2e/**/*.test.ts"],
		exclude: ["**/node_modules/**", "**/dist/**", "**/.mct/**", "**/*.spec.ts"],
		mockReset: true,
		restoreMocks: true,
		testTimeout: 120_000,
	},
});
