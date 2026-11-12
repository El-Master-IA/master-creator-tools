import { Command } from "commander";
import { describe, expect, it } from "vitest";
import { register } from "../src/commands/verify.js";

describe("VER-002 verify command", () => {
	it("VER-002 registers `verify` with --remote and --local and no --yes", () => {
		const program = new Command();
		register(program);
		const cmd = program.commands.find((c) => c.name() === "verify");
		expect(cmd).toBeDefined();
		const flags = cmd?.options.map((o) => o.long) ?? [];
		expect(flags).toContain("--remote");
		expect(flags).toContain("--local");
		expect(flags).not.toContain("--yes");
	});
});
