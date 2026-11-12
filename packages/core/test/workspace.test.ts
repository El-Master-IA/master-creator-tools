import { execFileSync } from "node:child_process";
import {
	chmod,
	mkdir,
	mkdtemp,
	readdir,
	rm,
	stat,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashTree } from "../src/hash.js";
import {
	createWorkspace,
	readState,
	updateState,
	withLock,
	writeState,
} from "../src/workspace.js";

let base: string;
let raiz: string;

const init = {
	mctVersion: "0.0.0",
	origen: { tipo: "carpeta" as const, ref: "origen" },
	adapter: "node",
};

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-t06-"));
	raiz = join(base, ".mct");
});
afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

async function rechazo(p: Promise<unknown>): Promise<MctError> {
	try {
		await p;
	} catch (e) {
		expect(e).toBeInstanceOf(MctError);
		return e as MctError;
	}
	throw new Error("se esperaba un rechazo");
}

describe("workspace", () => {
	it("STATE-001 crea state.json con schemaVersion y etapas", async () => {
		await createWorkspace(raiz, init);
		const s = await readState(raiz);
		expect(s.schemaVersion).toBe(1);
		expect(s.etapas.init.estado).toBe("ok");
		expect(s.etapas.verify.estado).toBe("pendiente");
		expect(s.verificado).toBeNull();
	});

	it("STATE-001 schemaVersion desconocido sale con WORKSPACE_INVALIDO", async () => {
		await createWorkspace(raiz, init);
		await writeFile(
			join(raiz, "state.json"),
			JSON.stringify({ schemaVersion: 99 }),
		);
		const e = await rechazo(readState(raiz));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		expect(e.exit).toBe(4);
	});

	it("STATE-001 otro comando con el lock rechaza la escritura", async () => {
		await createWorkspace(raiz, init);
		await writeFile(join(raiz, "lock"), `${process.pid}\n`);
		const e = await rechazo(updateState(raiz, (s) => s));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		expect((await readdir(raiz)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
	});

	it("STATE-001 un lock con PID muerto se recupera", async () => {
		await createWorkspace(raiz, init);
		await writeFile(join(raiz, "lock"), "2147483646\n");
		const s = await updateState(raiz, (x) => ({ ...x, adapter: "n8n" }));
		expect(s.adapter).toBe("n8n");
		expect(await readdir(raiz)).not.toContain("lock");
	});

	it("STATE-001 state.json con forma inválida sale con WORKSPACE_INVALIDO", async () => {
		await createWorkspace(raiz, init);
		const s = await readState(raiz);
		for (const malo of [
			{ ...s, origen: { tipo: "ftp", ref: "x" } },
			{ ...s, etapas: { init: s.etapas.init } },
			{ ...s, workSha256: "zz" },
			{ ...s, adapter: 5 },
		]) {
			await writeFile(join(raiz, "state.json"), JSON.stringify(malo));
			const e = await rechazo(readState(raiz));
			expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		}
	});

	it("SEG-010 rechaza .mct o subdirectorios que sean enlaces", async () => {
		const real = join(base, "real");
		await mkdir(real);
		try {
			await symlink(real, raiz, "junction");
		} catch {
			return;
		}
		const e = await rechazo(createWorkspace(raiz, init));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		await rm(raiz, { recursive: true, force: true });
		await createWorkspace(raiz, init);
		await rm(join(raiz, "work"), { recursive: true, force: true });
		await symlink(real, join(raiz, "work"), "junction");
		const e2 = await rechazo(readState(raiz));
		expect(e2.codigo).toBe("WORKSPACE_INVALIDO");
	});

	it("STATE-001 el lock se libera al terminar, también si falla", async () => {
		await createWorkspace(raiz, init);
		await expect(
			withLock(raiz, () => Promise.reject(new Error("falla"))),
		).rejects.toThrow("falla");
		expect(await readdir(raiz)).not.toContain("lock");
		await withLock(raiz, async () => {
			const e = await rechazo(withLock(raiz, async () => undefined));
			expect(e.codigo).toBe("WORKSPACE_INVALIDO");
		});
		expect(await readdir(raiz)).not.toContain("lock");
	});

	it("STATE-001 la escritura es atómica y no deja temporales", async () => {
		await createWorkspace(raiz, init);
		const s = await readState(raiz);
		await writeState(raiz, { ...s, adapter: "n8n" });
		expect((await readState(raiz)).adapter).toBe("n8n");
		expect((await readdir(raiz)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
	});

	it("STATE-001 aplica 0700 al directorio y 0600 a los archivos", async () => {
		await createWorkspace(raiz, init);
		if (process.platform === "win32") {
			for (const p of [join(raiz, "state.json"), raiz]) {
				const acl = execFileSync("icacls", [p]).toString();
				// Language-independent: every ACE reads "<principal>:(perms)".
				const principals = acl
					.split(/\r?\n/)
					.flatMap((l) => [...l.matchAll(/(\S+):\([^)]*\)/g)])
					.map((m) => (m[1] ?? "").split("\\").pop()?.toLowerCase());
				expect(principals.length).toBeGreaterThan(0);
				for (const pr of principals) {
					expect(pr).toBe(userInfo().username.toLowerCase());
				}
			}
			return;
		}
		expect((await stat(raiz)).mode & 0o777).toBe(0o700);
		expect((await stat(join(raiz, "work"))).mode & 0o777).toBe(0o700);
		expect((await stat(join(raiz, "state.json"))).mode & 0o777).toBe(0o600);
	});
});

describe("hashTree", () => {
	it("STATE-001 es estable, ordena rutas y es hex de 64", async () => {
		const a = join(base, "a");
		const b = join(base, "b");
		await mkdir(join(a, "d"), { recursive: true });
		await mkdir(join(b, "d"), { recursive: true });
		await writeFile(join(a, "x.txt"), "1");
		await writeFile(join(a, "d", "y.txt"), "2");
		await writeFile(join(b, "d", "y.txt"), "2");
		await writeFile(join(b, "x.txt"), "1");
		const h = await hashTree(a);
		expect(h).toMatch(/^[0-9a-f]{64}$/);
		expect(await hashTree(b)).toBe(h);
	});

	it("STATE-001 cambia con el contenido y con el nombre", async () => {
		const a = join(base, "a");
		await mkdir(a);
		await writeFile(join(a, "x.txt"), "1");
		const h1 = await hashTree(a);
		await writeFile(join(a, "x.txt"), "2");
		const h2 = await hashTree(a);
		await writeFile(join(a, "z.txt"), "2");
		expect(new Set([h1, h2, await hashTree(a)]).size).toBe(3);
	});

	it("STATE-001 cambia con el modo del archivo (POSIX)", async () => {
		if (process.platform === "win32") return;
		const a = join(base, "a");
		await mkdir(a);
		await writeFile(join(a, "x.sh"), "1");
		await chmod(join(a, "x.sh"), 0o644);
		const h1 = await hashTree(a);
		await chmod(join(a, "x.sh"), 0o755);
		expect(await hashTree(a)).not.toBe(h1);
	});

	it("STATE-001 rechaza enlaces simbólicos", async () => {
		const a = join(base, "a");
		await mkdir(a);
		await writeFile(join(a, "x.txt"), "1");
		try {
			await symlink(join(a, "x.txt"), join(a, "l"));
		} catch {
			return; // sin privilegio de symlink en Windows
		}
		const e = await rechazo(hashTree(a));
		expect(e.codigo).toBe("WORKSPACE_INVALIDO");
	});
});
