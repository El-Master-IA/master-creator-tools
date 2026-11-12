import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Change, Workspace } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import { n8nAdapter } from "../src/index.js";

const roots: string[] = [];

async function makeWs(work: Record<string, string>): Promise<Workspace> {
	const raiz = await mkdtemp(join(tmpdir(), "mct-n8n-rev-"));
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

function node(
	type: string,
	parameters: Record<string, unknown>,
	extra: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		parameters,
		type,
		typeVersion: 1,
		position: [0, 0],
		id: "11111111-1111-4111-8111-111111111111",
		name: type,
		...extra,
	};
}

function wf(nodes: Record<string, unknown>[]): Record<string, unknown> {
	return { name: "w", nodes, connections: {}, active: false };
}

const ph = (n: string): string => `\${${n}}`;
const text = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;

describe("WF-002 / SEG-102 dominios propios", () => {
	it("WF-002 reemplaza el host propio con subruta, IP con puerto, /rest y /workflow/N", async () => {
		const host = ["flows", "miempresa", "example"].join(".");
		const ip = ["10", "20", "30", "40"].join(".");
		const original = text(
			wf([
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${host}/base/webhook/abc123` },
					{ name: "a" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${host}/base/api/otro` },
					{ name: "b" },
				),
				node(
					"n8n-nodes-base.set",
					{ value: `ver en ${host} ahora`, api: `https://${host}/rest/login` },
					{ name: "c" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `http://${ip}:5678/rest/workflows` },
					{ name: "d" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `http://${ip}:5678/workflow/12` },
					{ name: "e" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `http://${ip}:5678/healthz` },
					{ name: "f" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: "https://api.publica.example/v1/items" },
					{ name: "g" },
				),
			]),
		);
		const ws = await makeWs({ "f.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const out = apply(original, "f.json", changes);
		expect(out).not.toContain("miempresa");
		expect(out).not.toContain(ip);
		expect(out).toContain("https://api.publica.example/v1/items");
		expect(out).toContain(ph("N8N_INSTANCE_URL"));
	});

	it("WF-002 no deriva el host de /webhook, /form ni /workflow/x en dominios publicos", async () => {
		const click = ["api", "clickup", "com"].join(".");
		const gh = ["github", "com"].join(".");
		const jot = ["www", "jotform", "com"].join(".");
		const original = text(
			wf([
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${click}/webhook/abc` },
					{ name: "a" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${click}/api/v2/team` },
					{ name: "b" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${gh}/workflow/x`, other: `https://${gh}/org/repo` },
					{ name: "c" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${jot}/form/123`, other: `https://${jot}/API/user` },
					{ name: "d" },
				),
			]),
		);
		const ws = await makeWs({ "f.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const out = apply(original, "f.json", changes);
		expect(out).toContain(`https://${click}/api/v2/team`);
		expect(out).toContain(`https://${gh}/org/repo`);
		expect(out).toContain(`https://${jot}/API/user`);
		expect(out).not.toContain("N8N_INSTANCE_HOST");
	});

	it("WF-002 no deriva el host de una API publica con /rest/v1", async () => {
		const api = ["proyecto", "supabase", "co"].join(".");
		const original = text(
			wf([
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${api}/rest/v1/items` },
					{ name: "a" },
				),
			]),
		);
		const ws = await makeWs({ "f.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		expect(changes.filter((c) => c.ruta === "f.json")).toEqual([]);
		expect(original).toContain(`https://${api}/rest/v1/items`);
	});

	it("WF-002 no reemplaza dentro de type ni corrompe el name con un host n8n a secas", async () => {
		const host = ["foo", "example"].join(".");
		const original = text({
			...wf([
				node(
					"n8n-nodes-base.httpRequest",
					{ url: "http://n8n/rest/workflows" },
					{ name: "n8n" },
				),
				node(host, {}, { name: "tipo" }),
			]),
			name: "n8n",
		});
		const ws = {
			...(await makeWs({ "f.json": original })),
			instanceUrl: `https://${host}`,
		};
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const out = JSON.parse(apply(original, "f.json", changes)) as {
			name: string;
			nodes: { name: string; type: string; parameters: { url?: string } }[];
		};
		expect(out.name).toBe("n8n");
		expect(out.nodes[0]?.name).toBe("n8n");
		expect(out.nodes[0]?.parameters.url).toBe(
			`${ph("N8N_INSTANCE_URL")}/rest/workflows`,
		);
		expect(out.nodes[1]?.type).toBe(host);
	});

	it("WF-002 sigue reemplazando n8n.<dominio> con /base/webhook y /rest, IP privada con /workflow/N y /rest a secas", async () => {
		const host = ["n8n", "miempresa", "example"].join(".");
		const ip = ["10", "0", "0", "5"].join(".");
		const ip2 = ["192", "168", "1", "50"].join(".");
		const original = text(
			wf([
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${host}/base/webhook/abc` },
					{ name: "a" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `https://${host}/rest/workflows`, t: `ver ${host}/base/x` },
					{ name: "b" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `http://${ip}:5678/workflow/42`, t: `${ip}:5678 ok` },
					{ name: "c" },
				),
				node(
					"n8n-nodes-base.httpRequest",
					{ url: `http://${ip2}:5678/rest`, t: `http://${ip2}:5678/healthz` },
					{ name: "d" },
				),
			]),
		);
		const ws = await makeWs({ "f.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const out = apply(original, "f.json", changes);
		expect(out).not.toContain("miempresa");
		expect(out).not.toContain(ip);
		expect(out).not.toContain(ip2);
	});

	it("WF-002 usa el instanceUrl de la config cuando llega", async () => {
		const host = ["cfg", "propio", "example"].join(".");
		const original = text(
			wf([
				node("n8n-nodes-base.httpRequest", { url: `https://${host}/health` }),
			]),
		);
		const ws = {
			...(await makeWs({ "f.json": original })),
			instanceUrl: `https://${host}`,
		};
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		expect(apply(original, "f.json", changes)).not.toContain("propio");
	});
});

describe("SEG-103 paths de webhook", () => {
	it("SEG-103 reemplaza parameters.path en mcpTrigger y en cualquier nodo con webhookId", async () => {
		const original = text(
			wf([
				node(
					"@n8n/n8n-nodes-langchain.mcpTrigger",
					{ path: "ruta-mcp-privada" },
					{ name: "m" },
				),
				node(
					"n8n-nodes-base.wait",
					{ path: "ruta-wait-privada" },
					{ name: "w", webhookId: "22222222-2222-4222-8222-222222222222" },
				),
			]),
		);
		const ws = await makeWs({ "f.json": original });
		const changes = (await n8nAdapter.sanitize?.(ws)) ?? [];
		const out = apply(original, "f.json", changes);
		expect(out).not.toContain("privada");
		expect(out).toContain(ph("WEBHOOK_PATH"));
	});
});

describe("SEG-101 fail open", () => {
	const good = text(wf([node("n8n-nodes-base.set", {}, { name: "ok" })]));

	it("SEG-101 un JSON envuelto, con nodos sin type o array mixto da MctError", async () => {
		const malos: Record<string, string> = {
			envuelto: text({ data: JSON.parse(good) }),
			sinType: text({
				nodes: [{ name: "x", parameters: {} }],
				connections: {},
			}),
			mixto: text([JSON.parse(good), { a: 1 }]),
			soloPin: text({ pinData: { a: [{ json: {} }] } }),
		};
		for (const [k, v] of Object.entries(malos)) {
			const ws = await makeWs({ "ok.json": good, [`${k}.json`]: v });
			await expect(n8nAdapter.sanitize?.(ws)).rejects.toBeInstanceOf(MctError);
		}
	});

	it("SEG-101 también falla con extensión .JSON y dentro de dist/ o build/", async () => {
		const envuelto = text({ data: JSON.parse(good) });
		for (const rel of ["X.JSON", "dist/x.json", "build/x.json"]) {
			const ws = await makeWs({ "ok.json": good, [rel]: envuelto });
			await expect(n8nAdapter.sanitize?.(ws)).rejects.toBeInstanceOf(MctError);
		}
	});

	it("SEG-101 omite solo .git, node_modules y .mct", async () => {
		const envuelto = text({ data: JSON.parse(good) });
		const ws = await makeWs({
			"ok.json": good,
			"node_modules/p/x.json": envuelto,
			".git/x.json": envuelto,
			".mct/x.json": envuelto,
		});
		await expect(n8nAdapter.sanitize?.(ws)).resolves.toBeDefined();
	});

	it("SEG-101 un JSON ajeno sin esas claves no aborta, ni un JSONC con comentarios", async () => {
		const jsonc =
			'{\n  // opciones\n  "compilerOptions": { "strict": true, },\n  /* x */ "include": ["src"]\n}\n';
		const ws = await makeWs({
			"ok.json": good,
			"package.json": '{"name":"x"}',
			"tsconfig.json": jsonc,
		});
		await expect(n8nAdapter.sanitize?.(ws)).resolves.toBeDefined();
	});
});

describe("SEG-104 secretos literales", () => {
	const rule = (id: string) => {
		const r = n8nAdapter.rules().find((x) => x.id === id);
		if (!r) throw new Error(id);
		return r.patron;
	};
	const fake = ["abc", "def", "123456"].join("");

	it("SEG-104 detecta valor literal en headers/query y no guarda ni marca placeholders", () => {
		const lit = `{"name":"Authorization","value":"Bearer ${fake}"}`;
		const rev = `{"value":"${fake}","name":"x-api-key"}`;
		const tok = `{ "name": "access_token", "value": "${fake}" }`;
		const expr = '{"name":"Authorization","value":"={{ $json.t }}"}';
		const plh = `{"name":"x-api-key","value":"${ph("API_KEY")}"}`;
		const a = rule("n8n-literal-auth-param");
		const b = rule("n8n-literal-auth-param-rev");
		expect(a.test(lit)).toBe(true);
		expect(a.test(tok)).toBe(true);
		expect(b.test(rev)).toBe(true);
		expect(a.test(expr)).toBe(false);
		expect(a.test(plh)).toBe(false);
		expect(b.test(plh)).toBe(false);
	});

	it("SEG-104 detecta password literal en jsCode", () => {
		const code = JSON.stringify({
			jsCode: `const password = "${fake}";\nreturn items;`,
		});
		expect(rule("n8n-code-password").test(code)).toBe(true);
		const ok = JSON.stringify({ jsCode: "const password = $env.PW;" });
		expect(rule("n8n-code-password").test(ok)).toBe(false);
	});

	it("SEG-104 las regex no explotan con entrada hostil", () => {
		const hostil = `"jsCode": "${"a ".repeat(20000)}`;
		const t0 = Date.now();
		for (const r of n8nAdapter.rules()) r.patron.test(hostil);
		expect(Date.now() - t0).toBeLessThan(2000);
	});
});
