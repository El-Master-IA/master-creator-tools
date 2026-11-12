import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Change, Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { n8nAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(work: Record<string, string>): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-n8n-pin-"));
	roots.push(raiz);
	for (const zone of ["work", "quarantine", "dist"]) {
		await mkdir(join(raiz, zone), { recursive: true });
	}
	for (const [rel, content] of Object.entries(work)) {
		const target = join(raiz, "work", rel);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, content, "utf8");
	}
	return {
		raiz,
		work: join(raiz, "work"),
		quarantine: join(raiz, "quarantine"),
		dist: join(raiz, "dist"),
		estado: () => Promise.reject(new Error("no usado")),
	};
}

afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
	);
});

function apply(text: string, ruta: string, changes: Change[]): string {
	const c = changes.find((x) => x.ruta === ruta);
	if (c?.tipo !== "editar") throw new Error(`sin cambio para ${ruta}`);
	return text.slice(0, c.desde) + c.texto + text.slice(c.hasta);
}

// Real shape of `n8n export:workflow` (pretty-printed, 2 spaces).
function realExport(name: string): string {
	return `${JSON.stringify(
		{
			name,
			nodes: [
				{
					parameters: { rule: { interval: [{ field: "hours" }] } },
					type: "n8n-nodes-base.scheduleTrigger",
					typeVersion: 1.2,
					position: [0, 0],
					id: "11111111-1111-4111-8111-111111111111",
					name: "Schedule Trigger",
				},
			],
			pinData: {
				"Schedule Trigger": [{ json: { dato: "valor-de-prueba-privado" } }],
			},
			connections: {},
			active: false,
			settings: { executionOrder: "v1" },
			staticData: {
				"node:Schedule Trigger": { recurrenceRules: [], seen: "marca-privada" },
			},
			meta: { templateCredsSetupCompleted: true },
			id: "AbCdEf12",
		},
		null,
		2,
	)}\n`;
}

describe("WF-001 pinData y staticData", () => {
	it("WF-001 quita pinData y staticData sin escribir en disco", async () => {
		const original = realExport("uno");
		const ws = await makeWs({ "uno.json": original });
		const changes = await n8nAdapter.sanitize?.(ws);
		expect(changes).toHaveLength(1);
		expect(await readFile(join(ws.work, "uno.json"), "utf8")).toBe(original);
		const out = apply(original, "uno.json", changes ?? []);
		const parsed = JSON.parse(out) as Record<string, unknown>;
		expect("pinData" in parsed).toBe(false);
		expect("staticData" in parsed).toBe(false);
		expect(out).not.toContain("valor-de-prueba-privado");
		expect(out).not.toContain("marca-privada");
		expect(out.endsWith("\n")).toBe(true);
		expect(out).not.toContain("\r");
		expect(parsed.name).toBe("uno");
	});

	it("WF-001 procesa un arreglo de workflows y archivos en subcarpetas", async () => {
		const a = realExport("a");
		const b = realExport("b");
		const arr = `${JSON.stringify([JSON.parse(a), JSON.parse(b)], null, 2)}\n`;
		const ws = await makeWs({ "sub/dos.json": arr, "otro.json": a });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		expect(changes.map((c) => c.ruta).sort()).toEqual([
			"otro.json",
			"sub/dos.json",
		]);
		const out = JSON.parse(apply(arr, "sub/dos.json", changes)) as Record<
			string,
			unknown
		>[];
		expect(out).toHaveLength(2);
		for (const wf of out) {
			expect("pinData" in wf).toBe(false);
			expect("staticData" in wf).toBe(false);
		}
	});

	it("WF-001 es idempotente: sin pinData ni staticData no hay cambios", async () => {
		const original = realExport("uno");
		const ws = await makeWs({ "uno.json": original });
		const once = apply(
			original,
			"uno.json",
			(await n8nAdapter.sanitize?.(ws)) ?? [],
		);
		const ws2 = await makeWs({ "uno.json": once });
		expect(await n8nAdapter.sanitize?.(ws2)).toEqual([]);
	});

	it("WF-001 conserva CRLF y export minificado", async () => {
		const crlf = realExport("crlf").replace(/\n/g, "\r\n");
		const min = JSON.stringify(JSON.parse(realExport("min")));
		const ws = await makeWs({ "crlf.json": crlf, "min.json": min });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const outCrlf = apply(crlf, "crlf.json", changes);
		expect(outCrlf).toContain("\r\n");
		expect(outCrlf.replace(/\r\n/g, "")).not.toContain("\n");
		const outMin = apply(min, "min.json", changes);
		expect(outMin.trimEnd()).not.toContain("\n");
		expect(outMin).not.toContain("pinData");
	});

	it("WF-001 falla cerrado con JSON inválido, sin workflows o demasiado grande", async () => {
		const invalid = await makeWs({ "roto.json": "{ no es json" });
		await expect(n8nAdapter.sanitize?.(invalid)).rejects.toBeInstanceOf(
			MctError,
		);
		const vacio = await makeWs({ "otro.json": '{"a":1}' });
		await expect(n8nAdapter.sanitize?.(vacio)).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
			detalle: { motivo: "sin-workflows" },
		});
		const grande = await makeWs({
			"grande.json": `"${"x".repeat(21 * 1024 * 1024)}"`,
		});
		await expect(n8nAdapter.sanitize?.(grande)).rejects.toMatchObject({
			codigo: "WORKSPACE_INVALIDO",
			detalle: { motivo: "demasiado-grande" },
		});
		await expect(n8nAdapter.analyze(invalid)).rejects.toBeInstanceOf(MctError);
	});

	it("WF-001 las reglas detectan pinData y staticData con datos, también minificados", () => {
		const rules = n8nAdapter.rules();
		const pin = rules.find((r) => r.id === "n8n-pindata");
		const stat = rules.find((r) => r.id === "n8n-staticdata");
		expect(pin?.patron.test('  "pinData": {\n    "Webhook": []')).toBe(true);
		expect(pin?.patron.test('"pinData":{"A":[]}')).toBe(true);
		expect(pin?.patron.test('"pinData": {}')).toBe(false);
		expect(stat?.patron.test('"staticData":{"node:X":{}}')).toBe(true);
		expect(stat?.patron.test('"staticData": null')).toBe(false);
	});

	it("WF-001 una entrada hostil no provoca backtracking", () => {
		const hostile = `"pinData"${" ".repeat(200000)}:`;
		const start = performance.now();
		for (const r of n8nAdapter.rules()) r.patron.test(hostile);
		expect(performance.now() - start).toBeLessThan(500);
	});
});
