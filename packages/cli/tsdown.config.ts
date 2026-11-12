import { defineConfig } from "tsdown";

export default defineConfig({
	entry: { main: "src/main.ts" },
	format: "esm",
	platform: "node",
	dts: false,
	fixedExtension: false,
	clean: true,
	// Workspace packages and their JSON data are inlined; npm dependencies stay external.
	deps: { alwaysBundle: [/^@mct\//] },
});
