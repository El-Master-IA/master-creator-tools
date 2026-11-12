import { describe, expect, it } from "vitest";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

const TEN = [
	"init",
	"scan",
	"sanitize",
	"licenses",
	"package",
	"verify",
	"publish",
	"clean",
	"doctor",
	"run",
];

function makeIo() {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: "en_US.UTF-8" },
		stdinIsTTY: false,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

describe("RUN-001 registro de comandos", () => {
	it("RUN-001 mct --help lista los 10 comandos", async () => {
		const { io, out } = makeIo();
		expect(await runCli(["--help"], io)).toBe(0);
		const text = out.join("");
		for (const name of TEN) {
			expect(text, name).toMatch(new RegExp(`^\\s+${name}\\b`, "m"));
		}
	});

	it("RUN-001 ningun comando ofrece --yes", async () => {
		for (const name of TEN) {
			const { io, out } = makeIo();
			expect(await runCli([name, "--help"], io), name).toBe(0);
			expect(out.join(""), name).not.toContain("--yes");
		}
	});

	it("RUN-001 run no acepta un flag para el decisor", async () => {
		const { io, out } = makeIo();
		await runCli(["run", "--help"], io);
		const text = out.join("");
		expect(text).not.toMatch(/decisor/i);
		expect(text).toContain("--repo");
		expect(text).toContain("--dry-run");
	});
});
