import { defineConfig } from "playwright/test";

export default defineConfig({
	testDir: "e2e",
	testMatch: "**/*.spec.ts",
	fullyParallel: false,
	forbidOnly: true,
	retries: 0,
	reporter: "list",
	use: {
		browserName: "chromium",
		viewport: { width: 1280, height: 800 },
	},
});
