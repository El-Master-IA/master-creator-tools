import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { N8N_IMAGE_REF } from "@mct/contract/pins";
import type { Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { listCommunityNodes, n8nAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(work: Record<string, string>): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-n8n-com-"));
	roots.push(raiz);
	for (const zone of ["work", "quarantine", "dist"]) {
		await mkdir(join(raiz, zone), { recursive: true });
	}
	for (const [rel, content] of Object.entries(work)) {
		await writeFile(join(raiz, "work", rel), content, "utf8");
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

function flujo(types: string[], parameters: Record<string, unknown> = {}) {
	return `${JSON.stringify(
		{
			name: "demo",
			nodes: types.map((type, i) => ({
				parameters,
				type,
				typeVersion: 1,
				position: [i * 200, 0],
				id: `00000000-0000-4000-8000-00000000000${i}`,
				name: `Nodo ${i}`,
			})),
			connections: {},
			active: false,
			settings: { executionOrder: "v1" },
			id: "AbCdEf12",
		},
		null,
		2,
	)}\n`;
}

describe("WF-003 nodos comunitarios", () => {
	it("WF-003 lista los paquetes comunitarios y omite los nodos propios de n8n", async () => {
		const ws = await makeWs({
			"a.json": flujo([
				"n8n-nodes-base.webhook",
				"@n8n/n8n-nodes-langchain.agent",
				"n8n-nodes-evolution-api.evolutionApi",
				"@acme/n8n-nodes-widgets.widgetTrigger",
				"CUSTOM.local",
			]),
			"b.json": flujo([
				"n8n-nodes-evolution-api.evolutionApiTrigger",
				"n8n-nodes-evolution-api.evolutionApi",
			]),
		});
		expect(await listCommunityNodes(ws)).toEqual([
			{
				paquete: "@acme/n8n-nodes-widgets",
				tipos: ["@acme/n8n-nodes-widgets.widgetTrigger"],
			},
			{
				paquete: "n8n-nodes-evolution-api",
				tipos: [
					"n8n-nodes-evolution-api.evolutionApi",
					"n8n-nodes-evolution-api.evolutionApiTrigger",
				],
			},
		]);
	});

	it("WF-003 analyze expone los paquetes en deps, las variables y los workflows", async () => {
		const ws = await makeWs({
			"a.json": flujo(["n8n-nodes-evolution-api.evolutionApi"], {
				token: `\${SERVICE_TOKEN}`,
			}),
		});
		const a = await n8nAdapter.analyze(ws);
		expect(a.stack).toEqual(["n8n"]);
		expect(a.entrypoints).toEqual(["a.json"]);
		expect(a.deps).toEqual([
			{ nombre: "n8n-nodes-evolution-api", version: "latest" },
		]);
		expect(a.envVars).toEqual([{ nombre: "SERVICE_TOKEN", obligatoria: true }]);
		const hints = n8nAdapter.packageHints(a);
		expect(hints.requisitos.join("\n")).toContain("n8n-nodes-evolution-api");
		expect(hints.variables[0]?.nombre).toBe("SERVICE_TOKEN");
	});

	it("WF-003 sin nodos comunitarios la lista queda vacía; un JSON ilegible falla cerrado", async () => {
		const ok = await makeWs({ "a.json": flujo(["n8n-nodes-base.set"]) });
		expect(await listCommunityNodes(ok)).toEqual([]);
		const roto = await makeWs({ "a.json": "{ roto" });
		await expect(listCommunityNodes(roto)).rejects.toBeInstanceOf(MctError);
	});

	it("WF-003 verifyCommand usa la imagen fijada y pasa las rutas como argumentos", async () => {
		const ws = await makeWs({
			"a.json": flujo(["n8n-nodes-base.set"]),
			"b b.json": flujo(["n8n-nodes-base.set"]),
		});
		const spec = n8nAdapter.verifyCommand(await n8nAdapter.analyze(ws));
		expect(spec.imagen).toBe(N8N_IMAGE_REF);
		expect(spec.healthcheck).toEqual({ tipo: "n8n-import" });
		expect(spec.start.slice(0, 2)).toEqual(["sh", "-c"]);
		expect(spec.start.slice(4)).toEqual(["a.json", "b b.json"]);
		expect(spec.start[2]).toContain("n8n import:workflow");
		expect(spec.start[2]).not.toContain("a.json");
		expect(spec.timeoutMin).toBe(10);
		expect(() =>
			n8nAdapter.verifyCommand({
				stack: ["n8n"],
				entrypoints: [],
				envVars: [],
				deps: [],
				comandos: {},
			}),
		).toThrow(MctError);
	});
});
