import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Change, Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { n8nAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(
	work: Record<string, string>,
	dist: Record<string, string> = {},
): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-n8n-str-"));
	roots.push(raiz);
	for (const [zone, files] of [
		["work", work],
		["quarantine", {}],
		["dist", dist],
	] as const) {
		await mkdir(join(raiz, zone), { recursive: true });
		for (const [rel, content] of Object.entries(files)) {
			const target = join(raiz, zone, rel);
			await mkdir(dirname(target), { recursive: true });
			await writeFile(target, content, "utf8");
		}
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

const ph = (name: string): string => `\${${name}}`;
const INSTANCE = "ab12cd34".repeat(8);

// Real shape of `n8n export:workflow`.
function realExport(): string {
	return `${JSON.stringify(
		{
			name: "Lead intake",
			nodes: [
				{
					parameters: {
						httpMethod: "POST",
						path: "mi-ruta-privada",
						options: {},
					},
					type: "n8n-nodes-base.webhook",
					typeVersion: 2,
					position: [0, 0],
					id: "11111111-1111-4111-8111-111111111111",
					name: "Webhook",
					webhookId: "22222222-2222-4222-8222-222222222222",
				},
				{
					parameters: {
						method: "POST",
						url: "https://n8n.empresa-privada.example/webhook/abc123/secreto",
						sendBody: true,
					},
					type: "n8n-nodes-base.httpRequest",
					typeVersion: 4.2,
					position: [220, 0],
					id: "33333333-3333-4333-8333-333333333333",
					name: "Llamar otro flujo",
				},
				{
					parameters: { channel: "general", text: "hola" },
					type: "n8n-nodes-base.slack",
					typeVersion: 2.3,
					position: [440, 0],
					id: "55555555-5555-4555-8555-555555555555",
					name: "Slack",
					credentials: {
						slackApi: { id: "cr3d1", name: "Slack de la oficina" },
					},
				},
				{
					parameters: { url: "http://localhost:5678/rest/workflows" },
					type: "n8n-nodes-base.httpRequest",
					typeVersion: 4.2,
					position: [660, 0],
					id: "66666666-6666-4666-8666-666666666666",
					name: "Local",
				},
				{
					parameters: { url: "https://api.publica.example/v1/items" },
					type: "n8n-nodes-base.httpRequest",
					typeVersion: 4.2,
					position: [880, 0],
					id: "77777777-7777-4777-8777-777777777777",
					name: "API publica",
				},
			],
			pinData: {},
			connections: {
				Webhook: {
					main: [[{ node: "Llamar otro flujo", type: "main", index: 0 }]],
				},
			},
			active: false,
			settings: { executionOrder: "v1" },
			versionId: "44444444-4444-4444-8444-444444444444",
			meta: { templateCredsSetupCompleted: true, instanceId: INSTANCE },
			id: "AbCdEf12",
			tags: [
				{
					createdAt: "2026-01-01T00:00:00.000Z",
					updatedAt: "2026-01-01T00:00:00.000Z",
					id: "t1",
					name: "ventas",
				},
			],
		},
		null,
		2,
	)}\n`;
}

describe("WF-002 placeholders", () => {
	it("WF-002 reemplaza credenciales, webhooks, URLs e instanceId por placeholders", async () => {
		const original = realExport();
		const ws = await makeWs({ "flujo.json": original });
		const out = apply(
			original,
			"flujo.json",
			(await n8nAdapter.sanitize?.(ws)) ?? [],
		);
		const wf = JSON.parse(out) as {
			meta: { instanceId: string };
			nodes: {
				webhookId?: string;
				credentials?: Record<string, { id: string; name: string }>;
				parameters: Record<string, string>;
			}[];
		};
		expect(wf.meta.instanceId).toBe(ph("N8N_INSTANCE_ID"));
		expect(wf.nodes[0]?.parameters.path).toBe(ph("WEBHOOK_PATH"));
		expect(wf.nodes[0]?.webhookId).toBe(ph("WEBHOOK_ID"));
		expect(wf.nodes[1]?.parameters.url).toBe(ph("N8N_WEBHOOK_URL"));
		expect(wf.nodes[2]?.credentials?.slackApi).toEqual({
			id: ph("CREDENTIAL_SLACK_API_ID"),
			name: ph("CREDENTIAL_SLACK_API_NAME"),
		});
		expect(wf.nodes[3]?.parameters.url).toBe(
			`${ph("N8N_INSTANCE_URL")}/rest/workflows`,
		);
		expect(wf.nodes[4]?.parameters.url).toBe(
			"https://api.publica.example/v1/items",
		);
		for (const leaked of [
			INSTANCE,
			"mi-ruta-privada",
			"22222222-2222-4222-8222-222222222222",
			"cr3d1",
			"Slack de la oficina",
			"empresa-privada",
			"localhost",
		]) {
			expect(out).not.toContain(leaked);
		}
	});

	it("WF-002 numera los webhooks repetidos y no toca placeholders ya puestos", async () => {
		const wf = JSON.parse(realExport()) as { nodes: Record<string, unknown>[] };
		wf.nodes.push({
			parameters: { path: "otra-ruta" },
			type: "n8n-nodes-base.webhook",
			typeVersion: 2,
			position: [0, 200],
			id: "88888888-8888-4888-8888-888888888888",
			name: "Webhook 2",
		});
		const original = `${JSON.stringify(wf, null, 2)}\n`;
		const ws = await makeWs({ "flujo.json": original });
		const once = apply(
			original,
			"flujo.json",
			(await n8nAdapter.sanitize?.(ws)) ?? [],
		);
		const parsed = JSON.parse(once) as {
			nodes: { parameters: { path?: string } }[];
		};
		expect(parsed.nodes[5]?.parameters.path).toBe(ph("WEBHOOK_PATH_2"));
		const ws2 = await makeWs({ "flujo.json": once });
		expect(await n8nAdapter.sanitize?.(ws2)).toEqual([]);
	});

	it("WF-002 no devuelve el valor reemplazado en ningún Change más allá del texto del archivo limpio", async () => {
		const original = realExport();
		const ws = await makeWs({ "flujo.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		expect(JSON.stringify(changes)).not.toContain(INSTANCE);
		expect(JSON.stringify(changes)).not.toContain("cr3d1");
	});

	it("WF-002 una cadena hostil de URL no provoca backtracking", async () => {
		const hostile = `https://${"a".repeat(300000)}`;
		const wf = JSON.parse(realExport()) as {
			nodes: { parameters: Record<string, string> }[];
		};
		const first = wf.nodes[4];
		if (first) first.parameters.url = hostile;
		const ws = await makeWs({ "flujo.json": JSON.stringify(wf) });
		const start = performance.now();
		await n8nAdapter.sanitize?.(ws);
		expect(performance.now() - start).toBeLessThan(2000);
	});

	it("WF-002 la regla n8n-instance-id detecta el id real y no el placeholder", () => {
		const rule = n8nAdapter.rules().find((r) => r.id === "n8n-instance-id");
		expect(rule?.patron.exec(`"instanceId": "${INSTANCE}"`)?.[1]).toBe(
			INSTANCE,
		);
		expect(rule?.patron.test(`"instanceId": "${ph("N8N_INSTANCE_ID")}"`)).toBe(
			false,
		);
	});
});

describe("detect", () => {
	it("WF-002 devuelve confianza 0 si el JSON no es un export válido", async () => {
		const casos: Record<string, string> = {
			"a.json": "{ roto",
			"b.json": JSON.stringify({ name: "x" }),
			"c.json": JSON.stringify({ nodes: [], connections: {} }),
			"d.json": JSON.stringify({
				nodes: [{ name: "sin tipo" }],
				connections: {},
			}),
			"e.json": JSON.stringify([1, 2, 3]),
		};
		for (const [file, content] of Object.entries(casos)) {
			const ws = await makeWs({ [file]: content });
			expect(await n8nAdapter.detect(ws.work)).toBe(0);
		}
		expect(
			await n8nAdapter.detect(join(tmpdir(), "mct-n8n-no-existe-xyz")),
		).toBe(0);
		expect(await n8nAdapter.detect((await makeWs({})).work)).toBe(0);
	});

	it("WF-002 devuelve confianza alta con un export real, en carpeta o archivo", async () => {
		const ws = await makeWs({ "flujo.json": realExport() });
		expect(await n8nAdapter.detect(ws.work)).toBeGreaterThanOrEqual(0.9);
		expect(
			await n8nAdapter.detect(join(ws.work, "flujo.json")),
		).toBeGreaterThanOrEqual(0.9);
		const mixed = await makeWs({
			"flujo.json": realExport(),
			"otro.json": "{}",
		});
		const score = await n8nAdapter.detect(mixed.work);
		expect(score).toBeGreaterThan(0);
		expect(score).toBeLessThan(0.9);
	});
});

describe("generalize", () => {
	it("WF-002 quita tags y versionId de dist y conserva el resto", async () => {
		const original = realExport();
		const ws = await makeWs({}, { "flujo.json": original });
		const changes = (await n8nAdapter.generalize?.(ws)) ?? [];
		expect(changes).toHaveLength(1);
		expect(changes[0]?.tipo).toBe("editar");
		const parsed = JSON.parse(apply(original, "flujo.json", changes)) as Record<
			string,
			unknown
		>;
		expect("tags" in parsed).toBe(false);
		expect("versionId" in parsed).toBe(false);
		expect(parsed.name).toBe("Lead intake");
		expect(
			await n8nAdapter.generalize?.(
				await makeWs({}, { "x.json": JSON.stringify(parsed) }),
			),
		).toEqual([]);
	});
});
