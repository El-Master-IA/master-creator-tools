import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { N8N_IMAGE_REF, N8N_VERSION } from "@mct/contract/pins";
import type {
	Adapter,
	Analysis,
	Change,
	PackageHints,
	Rule,
	VerifySpec,
	Workspace,
} from "@mct/contract/types";

const MAX_FILE_BYTES = 20 * 1024 * 1024;
const DEFAULT_TIMEOUT_MIN = 10;
// Only tool-owned folders are skipped: dist/ and build/ may hold real exports (SEG-101).
const SKIP_DIRS = new Set(["node_modules", ".git", ".mct"]);
const RE_N8N_KEYS = /"(?:nodes|pinData|staticData)"\s{0,20}:/;
const BUILTIN_PACKAGES = new Set([
	"n8n-nodes-base",
	"@n8n/n8n-nodes-langchain",
]);
const WEBHOOK_TYPE = /\.(?:webhook|formTrigger|chatTrigger)$/;
const PLACEHOLDER = /^\$\{[A-Z][A-Z0-9_]{0,80}\}$/;
const RE_PLACEHOLDER_IN_TEXT = /\$\{([A-Z][A-Z0-9_]{0,80})\}/g;
const ph = (name: string): string => `\${${name}}`;

// All quantifiers are bounded and the character classes exclude the
// delimiters that follow them: linear time on hostile strings (SEG-004).
const BASE = String.raw`(?:\/[^\s"'<>\\/?#]{1,100}){0,5}?`;
// Webhook URLs may live under a sub-path (/base/webhook/abc).
const RE_WEBHOOK_URL = new RegExp(
	String.raw`https?:\/\/[^\s"'<>\\/]{1,255}${BASE}\/(?:webhook|webhook-test|webhook-waiting)\/[^\s"'<>\\]{0,500}`,
	"g",
);
const RE_FORM_URL =
	/https?:\/\/[^\s"'<>\\/]{1,255}\/(?:form|form-test)\/[^\s"'<>\\]{0,500}/g;
// Instance origins are derived from the export itself: host[:port] and base path.
// /rest counts only with an n8n subpath or on a recognizable instance host.
const RE_DERIVE_REST = new RegExp(
	String.raw`https?:\/\/([^\s"'<>\\/]{1,255})(${BASE})\/rest(?![\w-])`,
	"g",
);
// A bare /rest is common on public APIs (e.g. /rest/v1): only n8n subpaths or recognizable hosts count.
const RE_N8N_REST_PATH =
	/^\/(?:workflows|credentials|login|settings|executions|active-workflows)(?![\w-])/;
// /webhook, /form and /workflow/x also exist on public sites: only recognizable hosts count.
const RE_DERIVE_WEAK = new RegExp(
	String.raw`https?:\/\/([^\s"'<>\\/]{1,255})(${BASE})\/(?:webhook|webhook-test|webhook-waiting|workflow\/[\w-]{1,40})(?![\w-])`,
	"g",
);
const RE_DERIVE_FORM =
	/https?:\/\/([^\s"'<>\\/]{1,255})\/(?:form|form-test)\//g;
const RE_PRIVATE_IP =
	/^(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|127\.\d{1,3})\.\d{1,3}\.\d{1,3}$/;
/** Host that clearly belongs to an n8n instance (private IP, local port, n8n label, n8n cloud). */
function looksLikeInstance(host: string): boolean {
	const m = /^(.*?)(?::(\d{1,5}))?$/.exec(host);
	const name = (m?.[1] ?? host).toLowerCase();
	if (RE_PRIVATE_IP.test(name)) return true;
	if (name === "localhost") return m?.[2] !== undefined;
	if (name.endsWith(".app.n8n.cloud")) return true;
	const labels = name.split(".");
	return labels.length >= 2 && labels.some((l) => l.includes("n8n"));
}
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);
const escapeRe = (s: string): string =>
	s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
const RE_INSTANCE_URL =
	/https?:\/\/(?:[^\s"'<>\\/]{1,255}\.app\.n8n\.cloud|localhost|127\.0\.0\.1)(?::\d{1,5})?(?![\w.-])/g;

const RULES: readonly Rule[] = [
	{
		id: "n8n-pindata",
		tipo: "estructura",
		severidad: "alto",
		patron: /"pinData"\s{0,20}:\s{0,20}(\{\s{0,20}")/,
	},
	{
		id: "n8n-staticdata",
		tipo: "estructura",
		severidad: "alto",
		patron: /"staticData"\s{0,20}:\s{0,20}(\{\s{0,20}"|"\{)/,
	},
	{
		id: "n8n-instance-id",
		tipo: "estructura",
		severidad: "medio",
		patron: /"instanceId"\s{0,20}:\s{0,20}"([0-9a-fA-F]{16,128})"/,
	},
	{
		// Anything that still looks like an instance or webhook URL after sanitizing is an open finding.
		id: "n8n-instance-url",
		tipo: "estructura",
		severidad: "medio",
		patron: new RegExp(
			String.raw`(https?:\/\/[^\s"'<>\\/]{1,255}${BASE}\/(?:webhook(?:-test|-waiting)?\/|rest\/(?:workflows|credentials|login|settings|executions)(?![\w-])|workflow\/[\w-]{1,40}(?![\w-])))`,
		),
	},
	{
		// Literal header/query value for Authorization, *key* or *token* (name, then value).
		id: "n8n-literal-auth-param",
		tipo: "secreto",
		severidad: "critico",
		patron:
			/"name"\s{0,20}:\s{0,20}"(?:authorization|[^"\\]{0,40}(?:key|token)[^"\\]{0,40})"\s{0,20},\s{0,20}"value"\s{0,20}:\s{0,20}"([^"\\=$\s][^"\\]{5,200})"/i,
	},
	{
		// Same, with "value" before "name".
		id: "n8n-literal-auth-param-rev",
		tipo: "secreto",
		severidad: "critico",
		patron:
			/"value"\s{0,20}:\s{0,20}"([^"\\=$\s][^"\\]{5,200})"\s{0,20},\s{0,20}"name"\s{0,20}:\s{0,20}"(?:authorization|[^"\\]{0,40}(?:key|token)[^"\\]{0,40})"/i,
	},
	{
		// password = "literal" inside a Code node (escaped quotes in the JSON text).
		id: "n8n-code-password",
		tipo: "secreto",
		severidad: "critico",
		patron:
			/"jsCode"\s{0,20}:\s{0,20}"(?:[^"\\]|\\.){0,5000}?\b(?:password|passwd|pwd)\s{0,5}[:=]\s{0,5}(?:\\"|')([^"'\\$\s]{4,200})(?:\\"|')/i,
	},
];

type JsonObject = Record<string, unknown>;

interface Doc {
	/** Path relative to the zone, with "/". */
	ruta: string;
	original: string;
	parsed: unknown;
	workflows: JsonObject[];
}

function isObject(v: unknown): v is JsonObject {
	return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** A valid n8n export: an object with a non-empty nodes[] of typed nodes and a connections object. */
export function isWorkflow(v: unknown): v is JsonObject {
	if (!isObject(v)) return false;
	const { nodes, connections } = v;
	if (!Array.isArray(nodes) || nodes.length === 0) return false;
	if (!isObject(connections)) return false;
	return nodes.every((n) => isObject(n) && typeof n.type === "string");
}

function workflowsOf(parsed: unknown): JsonObject[] | null {
	if (isWorkflow(parsed)) return [parsed];
	if (Array.isArray(parsed) && parsed.length > 0 && parsed.every(isWorkflow)) {
		return parsed as JsonObject[];
	}
	return null;
}

function fail(motivo: string, archivo: string, etapa: string, cause?: unknown) {
	return new MctError(
		"WORKSPACE_INVALIDO",
		"No se pudo leer un export de n8n: no se puede dar por limpio un archivo ilegible.",
		{
			etapa,
			accion:
				"Revisa que el archivo sea un JSON válido exportado desde n8n y pese menos de 20 MB.",
			detalle: { motivo, archivo },
			...(cause === undefined ? {} : { cause }),
		},
	);
}

/** Relative `.json` paths under `root`, sorted. Fails closed when strict. */
async function listJson(
	root: string,
	etapa: string,
	strict: boolean,
	dir = "",
): Promise<string[]> {
	let entries: import("node:fs").Dirent[];
	try {
		entries = await readdir(join(root, dir), { withFileTypes: true });
	} catch (e) {
		if (!strict) return [];
		throw fail("directorio-ilegible", dir || ".", etapa, e);
	}
	const out: string[] = [];
	for (const entry of entries) {
		const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) {
				out.push(...(await listJson(root, etapa, strict, rel)));
			}
		} else if (entry.name.toLowerCase().endsWith(".json")) {
			if (!entry.isFile()) {
				if (strict) throw fail("no-es-archivo", rel, etapa);
				continue;
			}
			out.push(rel);
		}
	}
	return out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Loads every JSON under a zone; unreadable or invalid JSON is an error (fail closed). */
async function loadDocs(root: string, etapa: string): Promise<Doc[]> {
	const docs: Doc[] = [];
	for (const ruta of await listJson(root, etapa, true)) {
		let original: string;
		try {
			const info = await stat(join(root, ruta));
			if (info.size > MAX_FILE_BYTES)
				throw fail("demasiado-grande", ruta, etapa);
			original = await readFile(join(root, ruta), "utf8");
		} catch (e) {
			if (e instanceof MctError) throw e;
			throw fail("ilegible", ruta, etapa, e);
		}
		const body = original.replace(/^﻿/, "");
		let parsed: unknown;
		let foreign = false;
		try {
			parsed = JSON.parse(body);
		} catch (e) {
			// JSONC (comments, trailing commas) from other tools is not an export.
			try {
				parsed = JSON.parse(stripJsonc(body));
				foreign = true;
			} catch {
				throw fail("json-invalido", ruta, etapa, e);
			}
		}
		const workflows = foreign ? null : workflowsOf(parsed);
		if (workflows !== null) {
			docs.push({ ruta, original, parsed, workflows });
		} else if (RE_N8N_KEYS.test(body)) {
			// Looks like n8n data we cannot sanitize: never pass it along as clean.
			throw fail("export-no-saneable", ruta, etapa);
		}
	}
	return docs;
}

/** Removes comments and trailing commas outside strings (single pass). */
function stripJsonc(src: string): string {
	let out = "";
	let i = 0;
	while (i < src.length) {
		const c = src[i] as string;
		const next = src[i + 1];
		if (c === '"') {
			let j = i + 1;
			while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
			out += src.slice(i, j + 1);
			i = j + 1;
		} else if (c === "/" && next === "/") {
			while (i < src.length && src[i] !== "\n") i += 1;
		} else if (c === "/" && next === "*") {
			const end = src.indexOf("*/", i + 2);
			i = end === -1 ? src.length : end + 2;
		} else {
			out += c;
			i += 1;
		}
	}
	return out.replace(/,(\s*[}\]])/g, "$1");
}

function serialize(doc: Doc): string {
	const body = doc.original.replace(/^﻿/, "").trim();
	const indent: string | number = body.includes("\n")
		? (/^([ \t]+)"/m.exec(body)?.[1] ?? 2)
		: 0;
	const text = `${JSON.stringify(doc.parsed, null, indent)}\n`;
	return doc.original.includes("\r\n") ? text.replace(/\n/g, "\r\n") : text;
}

function editOf(doc: Doc): Change {
	return {
		tipo: "editar",
		ruta: doc.ruta,
		desde: 0,
		hasta: doc.original.length,
		texto: serialize(doc),
	};
}

function nodesOf(wf: JsonObject): JsonObject[] {
	return (wf.nodes as unknown[]).filter(isObject);
}

/** Applies `fn` to every string value of the tree (iterative: no stack overflow). Returns true if any changed. */
function mapStrings(
	root: unknown,
	fn: (s: string) => string,
	skipKeys: readonly string[] = [],
): boolean {
	let changed = false;
	const stack: unknown[] = [root];
	while (stack.length > 0) {
		const cur = stack.pop();
		if (cur === null || typeof cur !== "object") continue;
		const container = cur as Record<string, unknown>;
		for (const key of Object.keys(container)) {
			const value = container[key];
			if (typeof value === "string") {
				if (skipKeys.includes(key)) continue;
				const next = fn(value);
				if (next !== value) {
					container[key] = next;
					changed = true;
				}
			} else if (value !== null && typeof value === "object") {
				stack.push(value);
			}
		}
	}
	return changed;
}

function snake(s: string): string {
	return s
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/[^A-Za-z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "")
		.toUpperCase()
		.slice(0, 60);
}

function setPlaceholder(obj: JsonObject, key: string, value: string): boolean {
	const current = obj[key];
	if (typeof current === "string" && PLACEHOLDER.test(current)) return false;
	obj[key] = value;
	return true;
}

interface Origins {
	/** Regexes for scheme://host[:port][/base], longest first. */
	urls: RegExp[];
	/** Regexes for bare host[:port] mentions (non-local hosts only). */
	hosts: RegExp[];
}

function addOrigin(set: Set<string>, host: string, base: string): void {
	set.add(`${host}${base}`);
	set.add(host);
}

/** Derives the instance hosts (and base paths) from the URLs found in the exports. */
function deriveOrigins(docs: Doc[], extra: string[]): Origins {
	const found = new Set<string>();
	for (const url of extra) {
		const m =
			/^https?:\/\/([^\s/]{1,255})((?:\/[^\s/?#]{1,100}){0,5})\/?$/.exec(
				url.trim(),
			);
		if (m?.[1]) addOrigin(found, m[1], m[2] ?? "");
	}
	for (const doc of docs) {
		mapStrings(doc.parsed, (s) => {
			for (const m of s.matchAll(RE_DERIVE_REST)) {
				const rest = s.slice(m.index + m[0].length);
				if (m[1] && (looksLikeInstance(m[1]) || RE_N8N_REST_PATH.test(rest))) {
					addOrigin(found, m[1], m[2] ?? "");
				}
			}
			for (const m of s.matchAll(RE_DERIVE_WEAK)) {
				if (m[1] && looksLikeInstance(m[1])) addOrigin(found, m[1], m[2] ?? "");
			}
			for (const m of s.matchAll(RE_DERIVE_FORM)) {
				if (m[1] && looksLikeInstance(m[1])) found.add(m[1]);
			}
			return s;
		});
	}
	const list = [...found].sort((a, b) => b.length - a.length);
	const hostOnly = (o: string): string => o.split("/")[0] ?? o;
	return {
		urls: list.map(
			(o) => new RegExp(String.raw`https?:\/\/${escapeRe(o)}(?![\w-])`, "g"),
		),
		hosts: [...new Set(list.map(hostOnly))]
			.filter((h) => !LOCAL_HOSTS.has(h.replace(/:\d+$/, "")))
			.filter((h) => h.includes(".") || h.includes(":"))
			.map(
				(h) => new RegExp(String.raw`(?<![\w.-])${escapeRe(h)}(?![\w-])`, "g"),
			),
	};
}

function sanitizeWorkflow(
	wf: JsonObject,
	counters: { path: number; id: number },
	origins: Origins,
): boolean {
	let changed = false;
	for (const field of ["pinData", "staticData"]) {
		if (field in wf) {
			delete wf[field];
			changed = true;
		}
	}
	if (isObject(wf.meta) && "instanceId" in wf.meta) {
		changed =
			setPlaceholder(wf.meta, "instanceId", ph("N8N_INSTANCE_ID")) || changed;
	}
	for (const node of nodesOf(wf)) {
		if (node.credentials !== undefined && node.credentials !== null) {
			const creds = isObject(node.credentials) ? node.credentials : {};
			const out: JsonObject = {};
			for (const type of Object.keys(creds)) {
				const base = snake(type) || "CREDENTIAL";
				const prev = creds[type];
				const entry: JsonObject = isObject(prev) ? { ...prev } : {};
				setPlaceholder(entry, "id", `\${CREDENTIAL_${base}_ID}`);
				setPlaceholder(entry, "name", `\${CREDENTIAL_${base}_NAME}`);
				out[type] = entry;
			}
			if (JSON.stringify(out) !== JSON.stringify(node.credentials)) {
				node.credentials = out;
				changed = true;
			}
		}
		const hasWebhookId = typeof node.webhookId === "string";
		if (
			typeof node.webhookId === "string" &&
			!PLACEHOLDER.test(node.webhookId)
		) {
			counters.id += 1;
			node.webhookId = `\${WEBHOOK_ID${counters.id === 1 ? "" : `_${counters.id}`}}`;
			changed = true;
		}
		if (
			typeof node.type === "string" &&
			(hasWebhookId ||
				WEBHOOK_TYPE.test(node.type) ||
				/Trigger$/.test(node.type)) &&
			isObject(node.parameters) &&
			typeof node.parameters.path === "string" &&
			!PLACEHOLDER.test(node.parameters.path)
		) {
			counters.path += 1;
			node.parameters.path = `\${WEBHOOK_PATH${counters.path === 1 ? "" : `_${counters.path}`}}`;
			changed = true;
		}
	}
	const urls = mapStrings(
		wf,
		(s) => {
			let out = s
				.replace(RE_WEBHOOK_URL, ph("N8N_WEBHOOK_URL"))
				.replace(RE_FORM_URL, ph("N8N_WEBHOOK_URL"));
			for (const re of origins.urls)
				out = out.replace(re, ph("N8N_INSTANCE_URL"));
			out = out.replace(RE_INSTANCE_URL, ph("N8N_INSTANCE_URL"));
			for (const re of origins.hosts)
				out = out.replace(re, ph("N8N_INSTANCE_HOST"));
			return out;
		},
		["type"],
	);
	return changed || urls;
}

/** Community packages of a node type, or null for built-in and local ones. */
function communityPackage(type: string): string | null {
	const dot = type.lastIndexOf(".");
	if (dot <= 0) return null;
	const pkg = type.slice(0, dot);
	if (BUILTIN_PACKAGES.has(pkg) || pkg === "CUSTOM") return null;
	return pkg;
}

export interface CommunityNode {
	paquete: string;
	tipos: string[];
}

/** Community nodes used by the exports in `work/` (WF-003). Types only: no node parameters. */
export async function listCommunityNodes(
	ws: Workspace,
): Promise<CommunityNode[]> {
	const docs = await loadDocs(ws.work, "licenses");
	const byPackage = new Map<string, Set<string>>();
	for (const doc of docs) {
		for (const wf of doc.workflows) {
			for (const node of nodesOf(wf)) {
				const type = node.type as string;
				const pkg = communityPackage(type);
				if (pkg === null) continue;
				const set = byPackage.get(pkg) ?? new Set<string>();
				set.add(type);
				byPackage.set(pkg, set);
			}
		}
	}
	return [...byPackage]
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
		.map(([paquete, tipos]) => ({ paquete, tipos: [...tipos].sort() }));
}

async function readCandidate(path: string): Promise<unknown | undefined> {
	try {
		const info = await stat(path);
		if (!info.isFile() || info.size > MAX_FILE_BYTES) return undefined;
		return JSON.parse((await readFile(path, "utf8")).replace(/^﻿/, ""));
	} catch {
		return undefined;
	}
}

/** These adapters always verify: the narrower type spares callers a null check. */
export const n8nAdapter: Omit<Adapter, "verifyCommand"> & {
	verifyCommand(a: Analysis): VerifySpec;
} = {
	id: "n8n",

	async detect(dir: string): Promise<number> {
		let files: string[];
		try {
			const info = await stat(dir);
			if (info.isFile()) {
				files = [dir];
			} else {
				files = (await listJson(dir, "init", false)).map((f) => join(dir, f));
			}
		} catch {
			return 0;
		}
		if (files.length === 0) return 0;
		let valid = 0;
		for (const file of files) {
			if (workflowsOf(await readCandidate(file)) !== null) valid += 1;
		}
		if (valid === 0) return 0;
		return valid === files.length ? 0.98 : 0.8;
	},

	async analyze(ws: Workspace): Promise<Analysis> {
		const docs = await loadDocs(ws.work, "init");
		const community = await listCommunityNodes(ws);
		const vars = new Set<string>();
		for (const doc of docs) {
			mapStrings(doc.parsed, (s) => {
				for (const m of s.matchAll(RE_PLACEHOLDER_IN_TEXT)) {
					if (m[1]) vars.add(m[1]);
				}
				return s;
			});
		}
		return {
			stack: ["n8n"],
			entrypoints: docs.map((d) => d.ruta),
			envVars: [...vars]
				.sort()
				.map((nombre) => ({ nombre, obligatoria: true })),
			// Exports carry no package version: "latest" asks the registry for the current one (LIC-004 c).
			deps: community.map((c) => ({ nombre: c.paquete, version: "latest" })),
			comandos: {},
		};
	},

	rules(): Rule[] {
		return RULES.map((r) => ({ ...r }));
	},

	async sanitize(ws: Workspace): Promise<Change[]> {
		const docs = await loadDocs(ws.work, "sanitize");
		if (docs.length === 0) {
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"No hay ningún export de n8n válido en work/: no se puede dar por limpio.",
				{
					etapa: "sanitize",
					accion: "Revisa que el origen sea un export JSON de n8n.",
					detalle: { motivo: "sin-workflows" },
				},
			);
		}
		const counters = { path: 0, id: 0 };
		const configured = (ws as Workspace & { instanceUrl?: unknown })
			.instanceUrl;
		const origins = deriveOrigins(
			docs,
			typeof configured === "string" ? [configured] : [],
		);
		const changes: Change[] = [];
		for (const doc of docs) {
			let changed = false;
			for (const wf of doc.workflows) {
				changed = sanitizeWorkflow(wf, counters, origins) || changed;
			}
			if (changed) changes.push(editOf(doc));
		}
		return changes;
	},

	async generalize(ws: Workspace): Promise<Change[]> {
		const docs = await loadDocs(ws.dist, "package");
		const changes: Change[] = [];
		for (const doc of docs) {
			let changed = false;
			for (const wf of doc.workflows) {
				for (const field of ["tags", "versionId"]) {
					if (field in wf) {
						delete wf[field];
						changed = true;
					}
				}
			}
			if (changed) changes.push(editOf(doc));
		}
		return changes;
	},

	packageHints(a: Analysis): PackageHints {
		const requisitos = [`n8n (verificado con ${N8N_VERSION})`];
		for (const dep of a.deps) {
			requisitos.push(`Nodo comunitario: ${dep.nombre}`);
		}
		return {
			instalacion: [
				"En n8n: Workflows > Import from file, o con la CLI: n8n import:workflow --input=<archivo>",
			],
			uso: [
				"Crea las credenciales en tu n8n y asígnalas a cada nodo tras importar.",
			],
			variables: a.envVars.map((v) => ({
				nombre: v.nombre,
				descripcion: v.obligatoria
					? "Obligatoria."
					: "Opcional (tiene valor por defecto o es de ejemplo).",
				obligatoria: v.obligatoria,
			})),
			requisitos,
		};
	},

	verifyCommand(a: Analysis): VerifySpec {
		if (a.entrypoints.length === 0) {
			throw new MctError(
				"PUERTA_BLOQUEADA",
				"No hay ningún workflow de n8n que importar para verificar.",
				{
					etapa: "verify",
					accion: "Revisa que el origen sea un export JSON de n8n.",
					detalle: { motivo: "sin-workflows" },
				},
			);
		}
		return {
			imagen: N8N_IMAGE_REF,
			// Paths travel as positional arguments, never inside the script text.
			start: [
				"sh",
				"-c",
				'for f in "$@"; do n8n import:workflow --input="$f" || exit 1; done',
				"sh",
				...a.entrypoints,
			],
			healthcheck: { tipo: "n8n-import" },
			timeoutMin: DEFAULT_TIMEOUT_MIN,
		};
	},
};
