import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { readApproval, verifyApproval } from "@mct/core/approval";
import { hashTree } from "@mct/core/hash";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Runner } from "../../scanner/src/gitleaks.js";
import { overrideFlowDeps, type Prompter } from "../src/commands/flow.js";
import { runCli } from "../src/main.js";
import {
	createContext,
	type Io,
	reportError,
	scanGlobals,
} from "../src/output.js";

// Fixture values are assembled from fragments: no literal secret lives here.
const TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"].join(
	"",
);

const okRunner: Runner = async (_c, args) => {
	if (args.includes("version")) {
		return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
	}
	const rp = args[args.indexOf("--report-path") + 1] as string;
	await writeFile(rp, "[]");
	return { code: 0, signal: null, stdout: "", timedOut: false };
};

let base: string;
let origen: string;
let dest: string;
let home: string;
let restore: () => void;

function makeIo(tty: boolean) {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: "es_CO.UTF-8" },
		stdinIsTTY: tty,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

interface Script {
	selects: string[];
	texts: (string | null)[];
	asked: string[];
}

function scripted(script: Script): Prompter {
	return {
		select: async (o) => {
			script.asked.push(o.message);
			return (script.selects.shift() ?? null) as never;
		},
		text: async (o) => {
			script.asked.push(o.message);
			return script.texts.shift() ?? null;
		},
		confirm: async (o) => {
			script.asked.push(o.message);
			return true;
		},
	};
}

function useScript(script: Script): void {
	restore();
	restore = overrideFlowDeps({
		home,
		prompter: scripted(script),
		gitleaks: {
			binary: process.execPath,
			installDir: join(base, "bin"),
			run: okRunner,
		},
	});
}

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "mct-cli-review-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	home = join(base, "home");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(home, { recursive: true });
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(
		join(origen, "src", "index.js"),
		`const token = "${TOKEN}";\nmodule.exports = token;\n`,
	);
	restore = overrideFlowDeps({});
});

afterEach(async () => {
	restore();
	await rm(base, { recursive: true, force: true });
});

const ws = () => join(dest, ".mct");

async function initAndScan(): Promise<void> {
	useScript({ selects: [], texts: [], asked: [] });
	const a = await runCli(["init", origen, "--dest", dest], makeIo(false).io);
	expect(a).toBe(0);
	const b = await runCli(["scan", "--workspace", ws()], makeIo(false).io);
	expect(b).toBe(10);
}

describe("Ctrl+C en init", () => {
	it("CLI-001 con señal abortada conserva el aviso de residuo y el texto propio", async () => {
		const controller = new AbortController();
		controller.abort();
		const lanza = (nombre: string, error: MctError) => (program: Command) => {
			program.command(nombre).action(() => {
				throw error;
			});
		};
		for (const [nombre, error, texto] of [
			["a", new MctError("INTERRUMPIDO", "texto propio"), "texto propio"],
			[
				"b",
				new MctError("VALIDACION", "quedó residuo", {
					detalle: { residuo: true },
				}),
				"quedó residuo",
			],
		] as const) {
			const { io, err } = makeIo(false);
			await runCli([nombre], io, [lanza(nombre, error)], controller.signal);
			expect(err.join("")).toContain(texto);
		}
	});

	it("CLI-001 sale con 130 solo después de quitar el workspace a medias", async () => {
		useScript({ selects: [], texts: [], asked: [] });
		await writeFile(join(origen, ".env"), "A=1\n");
		await mkdir(dest, { recursive: true });
		for (const reads of [2, 3, 4, 5, 6]) {
			let seen = 0;
			const signal = {
				get aborted() {
					seen += 1;
					return seen > reads;
				},
				addEventListener() {},
				removeEventListener() {},
			} as unknown as AbortSignal;
			const code = await runCli(
				["init", origen, "--dest", dest],
				makeIo(false).io,
				[],
				signal,
			);
			expect(code).toBe(130);
			await expect(access(ws())).rejects.toThrow();
			await expect(access(join(dest, ".gitignore"))).rejects.toThrow();
		}
	});
});

describe("CLI-001 salida de init", () => {
	it("CLI-001 muestra la confianza del adaptador con dos decimales como máximo", async () => {
		useScript({ selects: [], texts: [], asked: [] });
		const { io, out, err } = makeIo(false);
		expect(await runCli(["init", origen, "--dest", dest], io)).toBe(0);
		const texto = out.join("") + err.join("");
		expect(texto).toMatch(/confianza \d+(\.\d{1,2})?\)/);
	});
});

describe("SAN-002 revision interactiva", () => {
	it("SAN-002 CUANDO se corre init, scan y sanitize sobre un fixture EL SISTEMA DEBE terminar con approval.json firmado", async () => {
		await initAndScan();
		useScript({ selects: ["reemplazar"], texts: ["MI_TOKEN"], asked: [] });
		const { io, out, err } = makeIo(true);
		const code = await runCli(["sanitize", "--workspace", ws()], io);
		expect(code).toBe(0);
		const approval = await readApproval(ws());
		expect(approval.arbolSha256).toMatch(/^[0-9a-f]{64}$/);
		await verifyApproval(ws());
		expect(err.join("")).toContain("aprobación firmada");
		expect(out.join("") + err.join("")).not.toContain(TOKEN);
	});

	it("SAN-002 CUANDO el motivo tiene menos de 10 caracteres EL SISTEMA DEBE volver a pedirlo", async () => {
		await initAndScan();
		const script: Script = {
			selects: ["falso-positivo"],
			texts: ["corto", "   ", "es un valor de prueba del fixture"],
			asked: [],
		};
		useScript(script);
		const { io, err } = makeIo(true);
		const code = await runCli(["sanitize", "--workspace", ws()], io);
		expect(code).toBe(0);
		// select + 3 text prompts (two short reasons asked again) + the batch question
		expect(script.asked).toHaveLength(5);
		expect(script.texts).toHaveLength(0);
		expect(err.join("")).toContain("10");
		await access(join(ws(), "approval.json"));
	});

	it("SAN-011 CUANDO se confirma el lote EL SISTEMA DEBE aplicar la misma decisión a los hallazgos de la misma regla y carpeta", async () => {
		await writeFile(
			join(origen, "src", "otro.js"),
			`const token = "${TOKEN}";
module.exports = token;
`,
		);
		await initAndScan();
		const script: Script = {
			selects: ["falso-positivo"],
			texts: ["es un valor de prueba del fixture"],
			asked: [],
		};
		useScript(script);
		const { io, err } = makeIo(true);
		const code = await runCli(["sanitize", "--workspace", ws()], io);
		expect(code).toBe(0);
		// one select, one reason and one batch question cover both findings
		expect(script.asked).toHaveLength(3);
		expect(err.join("")).toContain("lote confirmado");
		await access(join(ws(), "approval.json"));
	});

	it("SAN-002 CUANDO el motivo contiene el valor del hallazgo (en mayúsculas) EL SISTEMA DEBE rechazarlo con VALIDACION sin firmar ni repetir el valor", async () => {
		await initAndScan();
		useScript({
			selects: ["falso-positivo"],
			texts: [`es el mismo ${TOKEN.toUpperCase()} de siempre`],
			asked: [],
		});
		const { io, out, err } = makeIo(true);
		const code = await runCli(["sanitize", "--workspace", ws()], io);
		expect(code).toBe(2);
		expect(out.join("") + err.join("")).not.toContain(TOKEN);
		expect(out.join("") + err.join("")).not.toContain(TOKEN.toUpperCase());
		await expect(access(join(ws(), "approval.json"))).rejects.toThrow();
	});

	it("SAN-002 CUANDO la persona elige abortar EL SISTEMA DEBE salir con CANCELADO sin firmar", async () => {
		await initAndScan();
		useScript({ selects: ["abortar"], texts: [], asked: [] });
		const code = await runCli(
			["sanitize", "--workspace", ws()],
			makeIo(true).io,
		);
		expect(code).toBe(20);
		await expect(access(join(ws(), "approval.json"))).rejects.toThrow();
	});

	it("SAN-006 CUANDO la persona cancela un prompt (Ctrl+C en clack) EL SISTEMA DEBE salir con INTERRUMPIDO (130) sin firmar", async () => {
		await initAndScan();
		useScript({ selects: [], texts: [], asked: [] });
		const before = await hashTree(join(ws(), "work"));
		const { io, err } = makeIo(true);
		const code = await runCli(["sanitize", "--workspace", ws()], io);
		expect(code).toBe(130);
		expect(err.join("")).toContain("Revisión interrumpida");
		expect(await hashTree(join(ws(), "work"))).toBe(before);
		await expect(access(join(ws(), "approval.json"))).rejects.toThrow();
	});

	it("SAN-006 CUANDO llega Ctrl+C a mitad de sanitize EL SISTEMA DEBE salir con 130 y dejar work/ idéntico", async () => {
		await initAndScan();
		const controller = new AbortController();
		let calls = 0;
		const abortingRunner: Runner = async (c, args, opts) => {
			if (!args.includes("version")) {
				calls++;
				// Second re-scan runs after the replacement was applied to work/.
				if (calls === 2) controller.abort();
			}
			return okRunner(c, args, opts);
		};
		restore();
		restore = overrideFlowDeps({
			home,
			prompter: scripted({
				selects: ["reemplazar"],
				texts: ["MI_TOKEN"],
				asked: [],
			}),
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				run: abortingRunner,
			},
		});
		const before = await hashTree(join(ws(), "work"));
		const code = await runCli(
			["sanitize", "--workspace", ws()],
			makeIo(true).io,
			[],
			controller.signal,
		);
		expect(code).toBe(130);
		expect(calls).toBeGreaterThanOrEqual(2);
		expect(await hashTree(join(ws(), "work"))).toBe(before);
		await expect(access(join(ws(), "approval.json"))).rejects.toThrow();
		await expect(access(join(ws(), "lock"))).rejects.toThrow();
	});

	it("SAN-004 CUANDO work/ cambia durante el re-scan EL SISTEMA DEBE fallar sin firmar", async () => {
		await initAndScan();
		const mutating: Runner = async (c, args, opts) => {
			if (!args.includes("version")) {
				await writeFile(
					join(ws(), "work", "src", "index.js"),
					`const token = "${TOKEN}";
// cambio concurrente
`,
				);
			}
			return okRunner(c, args, opts);
		};
		restore();
		restore = overrideFlowDeps({
			home,
			prompter: scripted({
				selects: ["reemplazar"],
				texts: ["MI_TOKEN"],
				asked: [],
			}),
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				run: mutating,
			},
		});
		const code = await runCli(
			["sanitize", "--workspace", ws()],
			makeIo(true).io,
		);
		expect(code).not.toBe(0);
		await expect(access(join(ws(), "approval.json"))).rejects.toThrow();
	});

	it("SEG-203 CUANDO --verbose y el error no es MctError EL SISTEMA NO DEBE imprimir su mensaje ni la ruta", async () => {
		const { io, err } = makeIo(true);
		const ctx = createContext(new Command(), io, {
			...scanGlobals(["--verbose"]),
		});
		const fallo = Object.assign(
			new Error(
				`EACCES: permission denied, open '${join(base, "ClienteSecretoZeta", "a.txt")}'`,
			),
			{ code: "EACCES" },
		);
		reportError(ctx, fallo, true);
		const text = err.join("");
		expect(text).toContain("EACCES");
		expect(text).not.toContain("ClienteSecretoZeta");
		expect(text).not.toContain(base);
	});
});
