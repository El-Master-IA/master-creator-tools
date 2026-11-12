import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Rule, Severidad } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { n8nAdapter } from "../../adapter-n8n/src/index.js";
import { nodeAdapter } from "../../adapter-node/src/index.js";
import type { Runner } from "../src/gitleaks.js";
import { PROVIDER_RULES } from "../src/rules.js";
import { scan } from "../src/scan.js";
import { CLAVE_PRUEBA } from "./clave.js";

const cleanups: string[] = [];
afterEach(async () => {
	for (const d of cleanups.splice(0)) {
		await rm(d, { recursive: true, force: true });
	}
});

/** Reglas de todos los adaptadores presentes (los de otros paquetes se cargan si existen). */
async function reglasDeAdaptadores(): Promise<Map<string, readonly Rule[]>> {
	const out = new Map<string, readonly Rule[]>([
		["n8n", n8nAdapter.rules()],
		["node", nodeAdapter.rules()],
	]);
	for (const nombre of ["python", "static", "generic"]) {
		let mod: Record<string, unknown>;
		try {
			mod = (await import(`../../adapter-${nombre}/src/index.ts`)) as Record<
				string,
				unknown
			>;
		} catch {
			continue;
		}
		for (const valor of Object.values(mod)) {
			const rules = (valor as { rules?: unknown } | null)?.rules;
			if (typeof rules === "function") {
				out.set(nombre, (valor as { rules(): Rule[] }).rules());
			}
		}
	}
	return out;
}

describe("SCAN-014 severidad por regla", () => {
	it("SCAN-014 toda regla de tipo secreto de cualquier adaptador es critico", async () => {
		const adaptadores = await reglasDeAdaptadores();
		expect(adaptadores.size).toBeGreaterThanOrEqual(2);
		for (const [nombre, reglas] of adaptadores) {
			for (const r of reglas.filter((x) => x.tipo === "secreto")) {
				expect(r.severidad, `${nombre}:${r.id}`).toBe("critico");
			}
		}
	});

	it("SCAN-014 las tres reglas de secreto de n8n y las de credenciales de node son critico", () => {
		const sev = (reglas: readonly Rule[], id: string): Severidad | undefined =>
			reglas.find((r) => r.id === id)?.severidad;
		for (const id of [
			"n8n-literal-auth-param",
			"n8n-literal-auth-param-rev",
			"n8n-code-password",
		]) {
			expect(sev(n8nAdapter.rules(), id), id).toBe("critico");
		}
		for (const id of ["node-url-credenciales", "node-npmrc-credenciales"]) {
			expect(sev(nodeAdapter.rules(), id), id).toBe("critico");
		}
	});

	it("SCAN-014 la tabla de estructura de n8n y node se conserva", () => {
		const n8n = new Map(n8nAdapter.rules().map((r) => [r.id, r.severidad]));
		expect(n8n.get("n8n-pindata")).toBe("alto");
		expect(n8n.get("n8n-staticdata")).toBe("alto");
		expect(n8n.get("n8n-instance-id")).toBe("medio");
		expect(n8n.get("n8n-instance-url")).toBe("medio");
		const node = new Map(nodeAdapter.rules().map((r) => [r.id, r.severidad]));
		expect(node.get("node-git-privado")).toBe("alto");
	});

	it("SCAN-014 las reglas secretas del motor propio y todo hallazgo de gitleaks salen critico", async () => {
		const base = await mkdtemp(join(tmpdir(), "mct-sev-"));
		cleanups.push(base);
		const work = join(base, "work");
		await mkdir(work, { recursive: true });
		await mkdir(join(base, "tmp"), { recursive: true });
		const aws = ["AK", "IA", "ABCDEFGHIJKLMNOP"].join("");
		const llave = ["-----BEGIN ", "RSA PRIVATE", " KEY-----"].join("");
		const marcador = ["marca", "dor", "-gl-", "7q9x2m4k8w1z"].join("");
		await writeFile(join(work, "a.txt"), `a=${aws}\n${llave}\n`);
		await writeFile(join(work, "b.txt"), `x = "${marcador}"\n`);
		expect(PROVIDER_RULES.length).toBeGreaterThan(0);
		const gitleaks: Runner = async (_c, args) => {
			if (args.includes("version")) {
				return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
			}
			const rp = args[args.indexOf("--report-path") + 1] as string;
			await writeFile(
				rp,
				JSON.stringify([
					{
						RuleID: "generic-api-key",
						File: join(work, "b.txt"),
						StartLine: 1,
						EndLine: 1,
						StartColumn: 1,
						EndColumn: 5 + marcador.length,
					},
				]),
			);
			return { code: 2, signal: null, stdout: "", timedOut: false };
		};
		const r = await scan({
			work,
			quarantine: join(base, "quarantine"),
			clave: CLAVE_PRUEBA,
			gitleaks: {
				binary: process.execPath,
				installDir: join(base, "bin"),
				tmpDir: join(base, "tmp"),
				run: gitleaks,
			},
		});
		const secretos = r.hallazgos.filter((h) => h.tipo === "secreto");
		expect(secretos.some((h) => h.motor === "mct")).toBe(true);
		expect(secretos.some((h) => h.motor === "gitleaks")).toBe(true);
		for (const h of secretos) expect(h.severidad, h.regla).toBe("critico");
	});
});
