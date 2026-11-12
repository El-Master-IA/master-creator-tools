import { MctError } from "@mct/contract/errors";
import { GITLEAKS_VERSION } from "@mct/contract/pins";
import type { Runner } from "@mct/scanner/gitleaks";
import { describe, expect, it } from "vitest";
import { type DoctorOptions, runDoctor } from "../src/doctor.js";

// Token-shaped fixtures are assembled from fragments (never literal).
const TOKEN = `${"gh"}${"p_"}${"Z9".repeat(15)}`;
const HOME = "/home/ana";

interface Call {
	file: string;
	args: readonly string[];
}

/** Fake process boundary: answers by executable name. */
function fakeRun(
	answers: {
		gitleaks?: string | "ausente";
		docker?: number | "timeout";
		ssh?: number | "timeout";
	} = {},
	calls: Call[] = [],
): Runner {
	return async (file, args) => {
		calls.push({ file, args });
		const name = file.replace(/\\/g, "/").split("/").pop() ?? "";
		const done = { signal: null, stdout: "", timedOut: false };
		if (name.startsWith("gitleaks")) {
			const v = answers.gitleaks ?? GITLEAKS_VERSION;
			if (v === "ausente") {
				return {
					...done,
					code: null,
					error: Object.assign(new Error("x"), { code: "ENOENT" }),
				};
			}
			return { ...done, code: 0, stdout: `${v}\n` };
		}
		const key = name.startsWith("ssh") ? "ssh" : "docker";
		const a = answers[key] ?? 0;
		if (a === "timeout") return { ...done, code: null, timedOut: true };
		return { ...done, code: a };
	};
}

const exe = async (name: string) => `/usr/bin/${name}`;
const openPerms = {
	platform: "linux" as const,
	stat: async () => ({ mode: 0o100644 }),
};
const goodPerms = {
	platform: "linux" as const,
	stat: async () => ({ mode: 0o100600 }),
};

function opts(extra: Partial<DoctorOptions> = {}): DoctorOptions {
	return {
		home: HOME,
		env: { GITHUB_TOKEN: TOKEN },
		remoto: "servidor-casa",
		run: fakeRun(),
		resolveExe: exe,
		perms: goodPerms,
		...extra,
	};
}

describe("CLI-007 doctor", () => {
	it("CLI-007 hace cinco chequeos y sugiere mct init si todo esta bien", async () => {
		const r = await runDoctor(opts());
		expect(r.checks.map((c) => c.id)).toEqual([
			"gitleaks",
			"docker",
			"ssh",
			"github",
			"permisos",
		]);
		expect(r.checks.every((c) => c.estado === "ok")).toBe(true);
		expect(r.siguiente).toBe("mct init <origen>");
	});

	it("CLI-007 el siguiente comando sale en ingles con lang en", async () => {
		const r = await runDoctor(opts({ lang: "en" }));
		expect(r.siguiente).toBe("mct init <source>");
	});

	it("CLI-007 sin gitleaks falla y el siguiente es instalarlo", async () => {
		const r = await runDoctor(opts({ run: fakeRun({ gitleaks: "ausente" }) }));
		const g = r.checks.find((c) => c.id === "gitleaks");
		expect(g?.estado).toBe("falla");
		expect(r.siguiente).toContain("mct doctor --install-gitleaks");
	});

	it("CLI-007 gitleaks de otra version mayor falla", async () => {
		const r = await runDoctor(opts({ run: fakeRun({ gitleaks: "9.0.1" }) }));
		expect(r.checks[0]?.estado).toBe("falla");
	});

	it("CLI-007 con token dice presente y nunca lo muestra", async () => {
		const r = await runDoctor(opts());
		const g = r.checks.find((c) => c.id === "github");
		expect(g?.estado).toBe("ok");
		expect(g?.mensaje).toMatch(/presente|present/);
		expect(JSON.stringify(r)).not.toContain(TOKEN);
	});

	it("CLI-007 un token con formato roto avisa sin copiar su valor", async () => {
		const malo = `no valido ${TOKEN}`;
		const r = await runDoctor(opts({ env: { GH_TOKEN: malo } }));
		const g = r.checks.find((c) => c.id === "github");
		expect(g?.estado).toBe("aviso");
		expect(JSON.stringify(r)).not.toContain(TOKEN);
	});

	it("CLI-007 sin token y sin gh avisa con la accion", async () => {
		const noGh = async (name: string) =>
			name === "gh" ? null : `/usr/bin/${name}`;
		const r = await runDoctor(opts({ env: {}, resolveExe: noGh }));
		const g = r.checks.find((c) => c.id === "github");
		expect(g?.estado).toBe("aviso");
		expect(g?.accion).toContain("GITHUB_TOKEN");
		expect(g?.accion).toContain("gh auth login");
	});

	it("CLI-007 sin variables pero con sesion de gh auth dice presente", async () => {
		const calls: Call[] = [];
		const secret = `${"gh"}${"o_"}${"Q7".repeat(15)}`;
		const run: Runner = async (file, args) => {
			calls.push({ file, args });
			const name = file.split("/").pop() ?? "";
			if (name === "gh") {
				return { code: 0, signal: null, stdout: secret, timedOut: false };
			}
			return fakeRun()(file, args, {
				cwd: ".",
				env: {},
				timeoutMs: 1,
			});
		};
		const r = await runDoctor(opts({ env: {}, run }));
		const g = r.checks.find((c) => c.id === "github");
		expect(g?.estado).toBe("ok");
		expect(g?.mensaje).toMatch(/presente|present/);
		const gh = calls.find((c) => c.file.endsWith("/gh"));
		expect(gh?.args).toEqual(["auth", "status"]);
		expect(JSON.stringify(r)).not.toContain(secret);
	});

	it("CLI-007 gh auth status que falla mantiene el aviso", async () => {
		const run: Runner = async (file, args) => {
			const name = file.split("/").pop() ?? "";
			if (name === "gh") {
				return { code: 1, signal: null, stdout: "", timedOut: false };
			}
			return fakeRun()(file, args, { cwd: ".", env: {}, timeoutMs: 1 });
		};
		const r = await runDoctor(opts({ env: {}, run }));
		const g = r.checks.find((c) => c.id === "github");
		expect(g?.estado).toBe("aviso");
		expect(g?.accion).toContain("gh auth login");
	});

	it("CLI-007 sin verify.remoto el chequeo SSH es un aviso y no corre ssh", async () => {
		const calls: Call[] = [];
		const r = await runDoctor(
			opts({ remoto: undefined, run: fakeRun({}, calls) }),
		);
		const s = r.checks.find((c) => c.id === "ssh");
		expect(s?.estado).toBe("aviso");
		expect(s?.mensaje).toMatch(/sin remoto|no remote/);
		expect(calls.some((c) => c.file.endsWith("ssh"))).toBe(false);
	});

	it("CLI-007 SSH que no responde en 15 s es falla", async () => {
		const r = await runDoctor(opts({ run: fakeRun({ ssh: "timeout" }) }));
		expect(r.checks.find((c) => c.id === "ssh")?.estado).toBe("falla");
	});

	it("CLI-007 un alias que empieza con guion no llega a ssh", async () => {
		const calls: Call[] = [];
		const r = await runDoctor(
			opts({ remoto: "-oProxyCommand=x", run: fakeRun({}, calls) }),
		);
		expect(r.checks.find((c) => c.id === "ssh")?.estado).toBe("falla");
		expect(calls.some((c) => c.file.endsWith("ssh"))).toBe(false);
	});

	it("CLI-007 el SSH usa el alias como argumento propio y BatchMode", async () => {
		const calls: Call[] = [];
		await runDoctor(opts({ run: fakeRun({}, calls) }));
		const ssh = calls.find((c) => c.file.endsWith("ssh"));
		expect(ssh?.args).toContain("BatchMode=yes");
		expect(ssh?.args).toContain("servidor-casa");
	});

	it("SEC-001 el SSH fija StrictHostKeyChecking=yes", async () => {
		const calls: Call[] = [];
		await runDoctor(opts({ run: fakeRun({}, calls) }));
		const ssh = calls.find((c) => c.file.endsWith("ssh"));
		const i = ssh?.args.indexOf("StrictHostKeyChecking=yes") ?? -1;
		expect(i).toBeGreaterThan(0);
		expect(ssh?.args[i - 1]).toBe("-o");
	});

	it("CLI-007 con la config invalida el chequeo ssh falla y no corre ssh", async () => {
		const calls: Call[] = [];
		const r = await runDoctor(
			opts({ configInvalid: true, run: fakeRun({}, calls) }),
		);
		const c = r.checks.find((x) => x.id === "ssh");
		expect(c?.estado).toBe("falla");
		expect(c?.accion).toBe("revisa mct.config.json");
		expect(calls.some((x) => x.file.endsWith("ssh"))).toBe(false);
	});

	it("CLI-007 sin Docker en el PATH ni remoto es falla con accion", async () => {
		const r = await runDoctor(
			opts({
				remoto: undefined,
				resolveExe: async (n) => (n === "docker" ? null : `/usr/bin/${n}`),
			}),
		);
		const d = r.checks.find((c) => c.id === "docker");
		expect(d?.estado).toBe("falla");
		expect(d?.accion).toBeTruthy();
	});

	it("CLI-007 Docker instalado con el servicio caido y sin remoto es falla", async () => {
		const r = await runDoctor(
			opts({ remoto: undefined, run: fakeRun({ docker: 1 }) }),
		);
		expect(r.checks.find((c) => c.id === "docker")?.estado).toBe("falla");
	});

	it("CLI-007 con verify.remoto que responde, Docker local caido es aviso sin accion y no es el siguiente paso", async () => {
		const r = await runDoctor(opts({ run: fakeRun({ docker: 1 }) }));
		const d = r.checks.find((c) => c.id === "docker");
		expect(d?.estado).toBe("aviso");
		expect(d?.accion).toBeUndefined();
		expect(d?.mensaje).toContain("servidor-casa");
		expect(r.siguiente).not.toMatch(/Docker/);
	});

	it("CLI-007 con verify.remoto que responde, Docker ausente del PATH es aviso", async () => {
		const r = await runDoctor(
			opts({
				resolveExe: async (n) => (n === "docker" ? null : `/usr/bin/${n}`),
			}),
		);
		expect(r.checks.find((c) => c.id === "docker")?.estado).toBe("aviso");
	});

	it("CLI-007 si el remoto no responde, Docker local caido sigue siendo falla", async () => {
		const r = await runDoctor(
			opts({ run: fakeRun({ docker: 1, ssh: "timeout" }) }),
		);
		expect(r.checks.find((c) => c.id === "docker")?.estado).toBe("falla");
		expect(r.siguiente).toMatch(/Docker/);
	});

	it("CLI-007 un chequeo que lanza algo inesperado es falla, nunca ok", async () => {
		const r = await runDoctor(
			opts({
				resolveExe: async () => {
					throw new Error("boom");
				},
			}),
		);
		expect(r.checks.find((c) => c.id === "docker")?.estado).toBe("falla");
		expect(r.checks.find((c) => c.id === "ssh")?.estado).toBe("falla");
	});

	it("CLI-007 el entorno de los hijos no lleva el token", async () => {
		let seen = "";
		const run: Runner = async (file, args, o) => {
			seen += JSON.stringify(o.env);
			return fakeRun()(file, args, o);
		};
		await runDoctor(opts({ run }));
		expect(seen).not.toContain(TOKEN);
	});
});

describe("SEC-001 doctor avisa de sensible.txt abierto", () => {
	it("SEC-001 permisos abiertos avisan con la accion y la ponen en siguiente", async () => {
		const r = await runDoctor(opts({ perms: openPerms }));
		const p = r.checks.find((c) => c.id === "permisos");
		expect(p?.estado).toBe("aviso");
		expect(p?.accion?.replace(/\\/g, "/")).toBe(
			`chmod 600 "${HOME}/.mct/sensible.txt"`,
		);
		expect(r.siguiente).toContain("chmod 600");
	});

	it("SEC-001 archivo ausente no es aviso", async () => {
		const r = await runDoctor(
			opts({
				perms: {
					platform: "linux",
					stat: async () => {
						throw Object.assign(new Error("x"), { code: "ENOENT" });
					},
				},
			}),
		);
		expect(r.checks.find((c) => c.id === "permisos")?.estado).toBe("ok");
	});
});

describe("CLI-007 --install-gitleaks", () => {
	it("CLI-007 instala cuando falta y luego el chequeo pasa", async () => {
		let installed = false;
		const run: Runner = async (file, args, o) =>
			fakeRun({ gitleaks: installed ? GITLEAKS_VERSION : "ausente" })(
				file,
				args,
				o,
			);
		const dirs: string[] = [];
		const r = await runDoctor(
			opts({
				run,
				installGitleaks: true,
				install: async ({ destDir }) => {
					installed = true;
					dirs.push(destDir);
					return `${destDir}/gitleaks`;
				},
			}),
		);
		expect(dirs).toHaveLength(1);
		expect(dirs[0]?.replace(/\\/g, "/")).toBe(`${HOME}/.mct/bin`);
		expect(r.checks[0]?.estado).toBe("ok");
	});

	it("CLI-007 no vuelve a descargar si la version fijada ya esta", async () => {
		let n = 0;
		await runDoctor(
			opts({
				installGitleaks: true,
				install: async () => {
					n++;
					return "x";
				},
			}),
		);
		expect(n).toBe(0);
	});

	it("CLI-007 si falla la descarga lanza MOTOR_NO_DISPONIBLE (exit 12)", async () => {
		const p = runDoctor(
			opts({
				run: fakeRun({ gitleaks: "ausente" }),
				installGitleaks: true,
				install: async () => {
					throw new MctError("MOTOR_NO_DISPONIBLE", "descarga fallida");
				},
			}),
		);
		await expect(p).rejects.toMatchObject({
			codigo: "MOTOR_NO_DISPONIBLE",
			exit: 12,
		});
	});

	it("CLI-007 un error ajeno al instalar tambien sale como MOTOR_NO_DISPONIBLE", async () => {
		const p = runDoctor(
			opts({
				run: fakeRun({ gitleaks: "ausente" }),
				installGitleaks: true,
				install: async () => {
					throw new Error("red caida");
				},
			}),
		);
		await expect(p).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
	});

	it("CLI-007 si tras instalar el binario no responde, tambien es error", async () => {
		const p = runDoctor(
			opts({
				run: fakeRun({ gitleaks: "ausente" }),
				installGitleaks: true,
				install: async ({ destDir }) => `${destDir}/gitleaks`,
			}),
		);
		await expect(p).rejects.toMatchObject({ exit: 12 });
	});
});
