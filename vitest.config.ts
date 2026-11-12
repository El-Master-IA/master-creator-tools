import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["packages/**/test/**/*.test.ts", "test/**/*.test.ts"],
		exclude: [
			"**/node_modules/**",
			"**/dist/**",
			"**/.mct/**",
			"e2e/**",
			"**/*.spec.ts",
		],
		mockReset: true,
		restoreMocks: true,
		testTimeout: 20_000,
	},
});
