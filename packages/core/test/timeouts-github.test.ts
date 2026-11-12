import {
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	CLONE_TIMEOUT_MS,
	cloneGithub,
	type Runner,
	spawnRunner,
} from "../src/clone.js";
import { initFromSource } from "../src/init.js";

let base: string;

const exists = (p: string) =>
	lstat(p).then(
		() => true,
		() => false,
	);

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t21o-"));
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

/** Writes a partial clone and then hangs until aborted. */
const hanging: Runner = async (_f, args, o) => {
	const dir = args[args.length - 1] as string;
	await mkdir(join(dir, ".git"), { recursive: true });
	await writeFile(join(dir, "partial.bin"), "x");
	return new Promise((_, reject) => {
		o.signal.addEventListener("abort", () => reject(new Error("aborted")));
	});
};

describe("TMO-001 clone timeout", () => {
	it("TMO-001 the limit is 120 s", () => {
		expect(CLONE_TIMEOUT_MS).toBe(120_000);
	});

	it("TMO-001 cuts the clone, deletes the partial copy and exits ORIGEN_NO_ENCONTRADO", async () => {
		const dir = join(base, "repo");
		const err = await errOf(
			cloneGithub({
				url: "https://github.com/octo/demo",
				dir,
				env: {},
				run: hanging,
				gitPath: join(base, "g"),
				timeoutMs: 50,
			}),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		expect(err.detalle?.motivo).toBe("timeout");
		expect(await exists(dir)).toBe(false);
	});

	it("TMO-001 cuts even a runner that ignores the abort signal", async () => {
		const stuck: Runner = () => new Promise(() => undefined);
		const err = await errOf(
			cloneGithub({
				url: "https://github.com/octo/demo",
				dir: join(base, "repo"),
				env: {},
				run: stuck,
				gitPath: join(base, "g"),
				timeoutMs: 50,
				graceMs: 100,
			}),
		);
		expect(err.detalle?.motivo).toBe("timeout");
	});

	it("TMO-001 the real runner kills a process that outlives the signal", async () => {
		const ctl = new AbortController();
		setTimeout(() => ctl.abort(), 150);
		const t0 = Date.now();
		const res = await spawnRunner(
			process.execPath,
			["-e", "setTimeout(() => {}, 60000)"],
			{
				env: { ...process.env } as Record<string, string>,
				cwd: base,
				signal: ctl.signal,
			},
		);
		expect(res.code).not.toBe(0);
		expect(Date.now() - t0).toBeLessThan(20_000);
	});

	it.skipIf(process.platform === "win32")(
		"TMO-001 POSIX: the abort kills the grandchild that inherits stdio and resolves",
		async () => {
			const pidFile = join(base, "grandchild.pid");
			const grand =
				"require('fs').writeFileSync(process.argv[1],String(process.pid));setTimeout(()=>{},60000)";
			const parent =
				"const {spawn}=require('child_process');" +
				`spawn(process.execPath,['-e',${JSON.stringify(grand)},process.argv[1]],{stdio:'inherit'});` +
				"setTimeout(()=>{},60000)";
			const ctl = new AbortController();
			const t0 = Date.now();
			setTimeout(() => ctl.abort(), 1500);
			const res = await spawnRunner(process.execPath, ["-e", parent, pidFile], {
				env: { ...process.env } as Record<string, string>,
				cwd: base,
				signal: ctl.signal,
			});
			expect(res.code).not.toBe(0);
			expect(Date.now() - t0).toBeLessThan(8_000);
			const pid = Number(await readFile(pidFile, "utf8"));
			expect(pid).toBeGreaterThan(0);
			await new Promise((r) => setTimeout(r, 200));
			let alive = true;
			try {
				process.kill(pid, 0);
			} catch {
				alive = false;
			}
			expect(alive).toBe(false);
		},
		20_000,
	);

	it("TMO-001 init exits with the timeout and creates no workspace", async () => {
		const dest = join(base, "dest");
		await mkdir(dest, { recursive: true });
		const err = await errOf(
			initFromSource({
				origen: "https://github.com/octo/demo",
				dest,
				isTTY: false,
				mctVersion: "0.0.0",
				home: join(base, "home"),
				env: {},
				clon: { run: hanging, gitPath: join(base, "g"), timeoutMs: 50 },
			}),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		expect(err.detalle?.motivo).toBe("timeout");
		expect(await exists(join(dest, ".mct"))).toBe(false);
	});

	it("TMO-001 waits for a real process holding files before deleting the copy", async () => {
		const dir = join(base, "repo");
		const script =
			"const fs=require('fs');const p=require('path');const d=process.argv[1];" +
			"const fd=fs.openSync(p.join(d,'tmp_pack_x'),'w');" +
			"setInterval(()=>{try{fs.writeSync(fd,'x'.repeat(4096));" +
			"fs.writeFileSync(p.join(d,'f'+Math.floor(Math.random()*50)),'y')}catch{}},5)";
		const holder: Runner = async (_f, args, o) => {
			const target = args[args.length - 1] as string;
			await mkdir(target, { recursive: true });
			return spawnRunner(process.execPath, ["-e", script, target], o);
		};
		const { SystemRoot: sys } = process.env;
		const err = await errOf(
			cloneGithub({
				url: "https://github.com/octo/demo",
				dir,
				env: sys === undefined ? {} : { SystemRoot: sys },
				run: holder,
				gitPath: join(base, "g"),
				timeoutMs: 1500,
			}),
		);
		expect(err.codigo).toBe("ORIGEN_NO_ENCONTRADO");
		expect(err.detalle?.motivo).toBe("timeout");
		expect(await exists(dir)).toBe(false);
	}, 30_000);
});
