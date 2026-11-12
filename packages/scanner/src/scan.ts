import { createHash } from "node:crypto";
import { access, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import type { Finding, Rule, Severidad } from "@mct/contract/types";
import fg from "fast-glob";
import { scanBinaries } from "./binary.js";
import { DICT_RULE, detectDictionary } from "./dictionary.js";
import { findingId, normalizeValue } from "./finding-id.js";
import {
	checkGitleaksVersion,
	type GitleaksFinding,
	type InstallOptions,
	installGitleaks,
	MASKED_FRAGMENT,
	type Runner,
	runGitleaks,
} from "./gitleaks.js";
import { maskValue } from "./masking.js";
import { detectPii } from "./pii.js";
import { detectSecrets, MAX_TEXT_BYTES } from "./secrets.js";

type Zona = "work" | "quarantine";

/** Structural copy of the adapter-node `RegistryIssue`: file and line, never a value. */
export interface RegistryIssueInput {
	readonly tipo: string;
	readonly archivo: string;
	readonly zona: Zona;
	readonly linea: number;
}

export type Reconciler = (
	previos: readonly Finding[],
	rescan: readonly Finding[],
) => Finding[];

export interface ScanGitleaksOptions {
	/** Absolute path to the binary. If missing, the pinned release is installed in `installDir`. */
	readonly binary?: string;
	readonly binaryArgs?: readonly string[];
	/** Where the pinned download lives (`~/.mct/bin`). */
	readonly installDir: string;
	/** `.mct/tmp`: gitleaks reports are removed right after reading. */
	readonly tmpDir: string;
	readonly timeoutMs?: number;
	readonly run?: Runner;
	readonly install?: (options: InstallOptions) => Promise<string>;
}

export interface ScanOptions {
	/** Absolute `.mct/work`. */
	readonly work: string;
	/** Absolute `.mct/quarantine` (may not exist: then it is empty). */
	readonly quarantine: string;
	/** Rules of the adapter (`adapter.rules()`), received by parameter. */
	readonly rules?: readonly Rule[];
	/** Terms already loaded with `loadDictionary`. */
	readonly dictionary?: readonly string[];
	/** Output of the adapter `findRegistryIssues`. */
	readonly registryIssues?: readonly RegistryIssueInput[];
	/** Findings of the previous scan; requires `reconcile`. */
	readonly previos?: readonly Finding[];
	/** `reconcileFindings` of core (injected: scanner does not depend on core). */
	readonly reconcile?: Reconciler;
	readonly gitleaks: ScanGitleaksOptions;
	readonly maxBytes?: number;
}

export interface ScanResult {
	readonly hallazgos: Finding[];
	readonly gitleaksVersion: string;
	/**
	 * Finding id -> SHA-256 of its normalized value (the same digest the id is
	 * built from). In memory only, for callers that must tell two values apart
	 * across line shifts; it must never be written anywhere.
	 */
	readonly valueDigests?: ReadonlyMap<string, string>;
}

function motorFalla(
	etapa: string,
	motivo: string,
	mensaje: string,
	cause?: unknown,
): MctError {
	return new MctError("MOTOR_NO_DISPONIBLE", mensaje, {
		accion: "Revisa el motor de escaneo y vuelve a ejecutar `mct scan`",
		etapa,
		detalle: { motivo },
		...(cause === undefined ? {} : { cause }),
	});
}

/** Any detector failure is an engine failure: never "0 findings". */
function guard<T>(etapa: string, fn: () => T): T {
	try {
		return fn();
	} catch (error) {
		if (error instanceof MctError && error.codigo === "MOTOR_NO_DISPONIBLE") {
			throw error;
		}
		throw motorFalla(
			etapa,
			"detector-fallo",
			"Un motor de escaneo falló",
			error,
		);
	}
}

interface Located {
	readonly index: number;
	readonly end: number;
	readonly line: number;
	readonly column: number;
}

function lineStartsOf(text: string): number[] {
	const starts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) === 10) starts.push(i + 1);
	}
	return starts;
}

function locate(starts: readonly number[], offset: number): [number, number] {
	let lo = 0;
	let hi = starts.length - 1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if ((starts[mid] ?? 0) <= offset) lo = mid;
		else hi = mid - 1;
	}
	return [lo + 1, offset - (starts[lo] ?? 0) + 1];
}

interface Draft {
	motor: Finding["motor"];
	regla: string;
	tipo: Finding["tipo"];
	zona: Zona;
	archivo: string;
	linea: number;
	columna: number;
	/** Used only to compute the id; never stored. */
	valor: string;
	/**
	 * What the inheritance digest is built from when it must differ from `valor`:
	 * a gitleaks Match carries the key and the formatting around the secret, so
	 * only its whitespace-free form survives a reformat. Never stored.
	 */
	valorHerencia?: string;
	fragmento: string;
	severidad: Severidad;
	/** Path shown in the Finding when it must differ from the real one (dictionary terms). */
	archivoVisible?: string;
	/** Offsets in the analysed text; only filled when asked for (path scanning). */
	inicio?: number;
	fin?: number;
}

function toFinding(d: Draft): Finding {
	return {
		id: findingId({
			motor: d.motor,
			regla: d.regla,
			archivo: d.archivo,
			linea: d.linea,
			value: d.valor,
		}),
		motor: d.motor,
		regla: d.regla,
		tipo: d.tipo,
		zona: d.zona,
		archivo: d.archivoVisible ?? d.archivo,
		linea: d.linea,
		columna: d.columna,
		fragmento: d.fragmento,
		severidad: d.severidad,
		estado: d.zona === "quarantine" ? "aislado" : "abierto",
	};
}

function ruleMatches(rule: Rule, text: string, starts: readonly number[]) {
	const flags = rule.patron.flags.replace(/[gd]/g, "");
	const re = new RegExp(rule.patron.source, `${flags}gd`);
	const out: { loc: Located; value: string }[] = [];
	for (const m of text.matchAll(re)) {
		const span = m.indices?.[1] ?? m.indices?.[0];
		if (!span) continue;
		const value = text.slice(span[0], span[1]);
		if (value.length === 0) continue;
		const [line, column] = locate(starts, span[0]);
		out.push({ loc: { index: span[0], end: span[1], line, column }, value });
	}
	return out;
}

/**
 * Secret, PII and dictionary detectors over `text`. With `offsets` the drafts
 * also carry the span in `text` (used for paths, which are short).
 */
function builtinDrafts(
	text: string,
	zona: Zona,
	archivo: string,
	options: ScanOptions,
	offsets: boolean,
): Draft[] {
	const drafts: Draft[] = [];
	const base = { zona, archivo } as const;
	const maxBytes = options.maxBytes ?? MAX_TEXT_BYTES;
	const starts = offsets ? lineStartsOf(text) : [];

	for (const m of guard("mct", () => detectSecrets(text, { maxBytes }))) {
		const inicio = offsets
			? (starts[m.line - 1] ?? 0) + m.column - 1
			: undefined;
		drafts.push({
			...base,
			motor: "mct",
			regla: m.rule,
			tipo: "secreto",
			linea: m.line,
			columna: m.column,
			valor: m.value,
			fragmento: maskValue(m.value),
			severidad: "critico",
			...(inicio === undefined ? {} : { inicio, fin: inicio + m.value.length }),
		});
	}
	for (const m of guard("pii", () => detectPii(text, { maxBytes }))) {
		drafts.push({
			...base,
			motor: "mct",
			regla: m.regla,
			tipo: "pii",
			linea: m.linea,
			columna: m.columna,
			valor: text.slice(m.inicio, m.fin),
			fragmento: m.fragmento,
			severidad: "alto",
			...(offsets ? { inicio: m.inicio, fin: m.fin } : {}),
		});
	}
	const terms = options.dictionary ?? [];
	if (terms.length > 0) {
		for (const m of guard("diccionario", () =>
			detectDictionary(text, terms, { maxBytes }),
		)) {
			drafts.push({
				...base,
				motor: "mct",
				regla: DICT_RULE,
				tipo: "pii",
				linea: m.linea,
				columna: m.columna,
				valor: text.slice(m.inicio, m.fin),
				fragmento: m.fragmento,
				severidad: "alto",
				...(offsets ? { inicio: m.inicio, fin: m.fin } : {}),
			});
		}
	}
	return drafts;
}

/** Replaces every dictionary span of `path` by its `[dic:n]` mask. */
function maskDictionaryInPath(path: string, hits: readonly Draft[]): string {
	const spans = hits
		.filter((d) => d.regla === DICT_RULE)
		.map((d) => ({ a: d.inicio ?? 0, b: d.fin ?? 0, mask: d.fragmento }))
		.sort((x, y) => x.a - y.a || y.b - x.b);
	let out = "";
	let at = 0;
	for (const span of spans) {
		if (span.a < at) continue;
		out += path.slice(at, span.a) + span.mask;
		at = span.b;
	}
	return out + path.slice(at);
}

/**
 * SEG-001: a relative path (file or directory) is data too. Each path goes
 * through the secret, PII and dictionary detectors; a hit belongs to the
 * deepest entry its span reaches, so a name in a directory is reported once,
 * on the directory. Findings sit on line 0 / column 0 (like binaries), with a
 * masked fragment. A path holding a dictionary term is shown with the term
 * replaced by `[dic:n]`; the id is still computed from the real path.
 */
function pathDrafts(path: string, zona: Zona, options: ScanOptions): Draft[] {
	const all = builtinDrafts(path, zona, path, options, true);
	if (all.length === 0) return [];
	const lastStart = path.lastIndexOf("/") + 1;
	const visible = maskDictionaryInPath(path, all);
	return all
		.filter((d) => (d.fin ?? 0) >= lastStart)
		.map((d) => ({
			...d,
			linea: 0,
			columna: 0,
			...(visible === path ? {} : { archivoVisible: visible }),
		}));
}

function scanText(
	text: string,
	zona: Zona,
	archivo: string,
	options: ScanOptions,
): Draft[] {
	const drafts: Draft[] = builtinDrafts(text, zona, archivo, options, false);
	const base = { zona, archivo } as const;
	const rules = options.rules ?? [];
	if (rules.length > 0) {
		const starts = lineStartsOf(text);
		for (const rule of rules) {
			for (const { loc, value } of guard("reglas", () =>
				ruleMatches(rule, text, starts),
			)) {
				drafts.push({
					...base,
					motor: "mct",
					regla: rule.id,
					tipo: rule.tipo,
					linea: loc.line,
					columna: loc.column,
					valor: value,
					fragmento: maskValue(value),
					severidad: rule.severidad,
				});
			}
		}
	}
	return drafts;
}

async function exists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}

async function listFiles(root: string): Promise<string[]> {
	const files = await fg("**/*", {
		cwd: root,
		dot: true,
		onlyFiles: true,
		followSymbolicLinks: false,
		unique: true,
		suppressErrors: false,
	});
	return files.sort();
}

async function listDirs(root: string): Promise<string[]> {
	const dirs = await fg("**/*", {
		cwd: root,
		dot: true,
		onlyDirectories: true,
		followSymbolicLinks: false,
		unique: true,
		suppressErrors: false,
	});
	return dirs.sort();
}

const TOKEN_DELIMITERS = /[\s"'`,;<>()[\]{}=:]+/;

interface Recovered {
	/** The whole regex match, in memory only: it feeds the id and is never stored. */
	readonly match: string;
	/** Base 1, UTF-16 units, like the own engine. */
	readonly column: number;
}

/**
 * gitleaks runs with `--redact`, so the matched text is recovered in memory
 * from the file. Positions (already corrected by `runGitleaks`) are bytes:
 * [StartLine:StartColumn, EndLine:EndColumn] is the whole MATCH of the rule,
 * not the secret group (gitleaks 8.30.1, detect/detect.go). The secret cannot
 * be isolated inside it in general, so the id hashes the whole match: a rotated
 * secret changes the match and therefore the id. Fail closed if it cannot be.
 */
async function recoverMatch(
	root: string,
	archivo: string,
	f: GitleaksFinding,
): Promise<Recovered> {
	const fail = (): MctError =>
		motorFalla(
			"gitleaks",
			"posicion-no-recuperable",
			"No se pudo ubicar un hallazgo de gitleaks en el archivo",
		);
	let buffer: Buffer;
	try {
		buffer = await readFile(join(root, archivo));
	} catch {
		throw fail();
	}
	const lineStart = (line: number): number => {
		let at = 0;
		for (let n = 1; n < line; n++) {
			const nl = buffer.indexOf(10, at);
			if (nl < 0) throw fail();
			at = nl + 1;
		}
		return at;
	};
	const lineEnd = (from: number): number => {
		const nl = buffer.indexOf(10, from);
		return nl < 0 ? buffer.length : nl;
	};
	const firstStart = lineStart(f.line);
	const from = firstStart + f.column - 1;
	const lastStart = f.endLine === f.line ? firstStart : lineStart(f.endLine);
	const to = lastStart + f.endColumn;
	if (from >= lineEnd(firstStart) || to <= from || to > lineEnd(lastStart)) {
		throw fail();
	}
	const match = buffer.subarray(from, to).toString("utf8");
	if (match.trim().length === 0) throw fail();
	return {
		match,
		column: buffer.subarray(firstStart, from).toString("utf8").length + 1,
	};
}

/** Longest delimiter-free run of the match: only its first 4 characters are shown. */
function visibleToken(match: string): string {
	let best = "";
	for (const token of match.split(TOKEN_DELIMITERS)) {
		if (token.length > best.length) best = token;
	}
	return best.length > 0 ? best : match.trim();
}

async function resolveBinary(g: ScanGitleaksOptions): Promise<string> {
	if (g.binary !== undefined) return g.binary;
	const name = process.platform === "win32" ? "gitleaks.exe" : "gitleaks";
	const local = join(g.installDir, name);
	if (await exists(local)) return local;
	return (g.install ?? installGitleaks)({ destDir: g.installDir });
}

async function runZone(
	root: string,
	zona: Zona,
	binary: string,
	g: ScanGitleaksOptions,
): Promise<{ version: string; drafts: Draft[] }> {
	const result = await runGitleaks({
		binary,
		...(g.binaryArgs === undefined ? {} : { binaryArgs: g.binaryArgs }),
		target: root,
		tmpDir: g.tmpDir,
		...(g.timeoutMs === undefined ? {} : { timeoutMs: g.timeoutMs }),
		...(g.run === undefined ? {} : { run: g.run }),
	});
	const drafts: Draft[] = [];
	for (const f of result.findings) {
		if (f.line === 0) {
			// Path-only rule (e.g. pkcs12-file): the file is the finding. Its id
			// follows the content hash, so a replaced file is a new finding.
			let content: Buffer;
			try {
				content = await readFile(join(root, f.file));
			} catch {
				throw motorFalla(
					"gitleaks",
					"posicion-no-recuperable",
					"No se pudo ubicar un hallazgo de gitleaks en el archivo",
				);
			}
			drafts.push({
				motor: "gitleaks",
				regla: f.rule,
				tipo: "secreto",
				zona,
				archivo: f.file,
				linea: 0,
				columna: 0,
				valor: createHash("sha256").update(content).digest("hex"),
				fragmento: MASKED_FRAGMENT,
				severidad: "critico",
			});
			continue;
		}
		const { match, column } = await recoverMatch(root, f.file, f);
		drafts.push({
			motor: "gitleaks",
			regla: f.rule,
			tipo: "secreto",
			zona,
			archivo: f.file,
			linea: f.line,
			columna: column,
			valor: match,
			valorHerencia: match.replace(/\s+/g, ""),
			fragmento: maskValue(visibleToken(match)),
			severidad: "critico",
		});
	}
	return { version: result.version, drafts };
}

function registryFinding(issue: RegistryIssueInput): Finding {
	const credenciales = issue.tipo.startsWith("credenciales");
	return toFinding({
		motor: "mct",
		regla: issue.tipo,
		tipo: "estructura",
		zona: issue.zona,
		archivo: issue.archivo,
		linea: issue.linea,
		columna: 1,
		valor: issue.tipo,
		fragmento: "****",
		severidad: credenciales ? "critico" : "alto",
	});
}

function order(a: Finding, b: Finding): number {
	return (
		a.zona.localeCompare(b.zona) ||
		a.archivo.localeCompare(b.archivo) ||
		a.linea - b.linea ||
		a.columna - b.columna ||
		a.motor.localeCompare(b.motor) ||
		a.regla.localeCompare(b.regla) ||
		a.id.localeCompare(b.id)
	);
}

/**
 * Double-engine scan (SCAN-001/002/003/005/009) over `work/` and `quarantine/`.
 * Pure with respect to the tree: reads only, writes nothing (the gitleaks
 * report in `tmpDir` is redacted and removed). Values live in memory just long
 * enough to mask them and compute ids. Any engine failure rejects with
 * MOTOR_NO_DISPONIBLE; unreadable, oversize and non-text files become findings.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
	if (options.previos !== undefined && options.reconcile === undefined) {
		throw new MctError(
			"VALIDACION",
			"Para conciliar con el escaneo previo hace falta la función de conciliación",
		);
	}
	const workInfo = await stat(options.work).catch(() => null);
	if (workInfo === null || !workInfo.isDirectory()) {
		throw new MctError("WORKSPACE_INVALIDO", "work/ no existe", {
			etapa: "scan",
		});
	}
	const zones: {
		zona: Zona;
		root: string;
		files: string[];
		dirs: string[];
	}[] = [
		{
			zona: "work",
			root: options.work,
			files: await listFiles(options.work),
			dirs: await listDirs(options.work),
		},
	];
	if (await exists(options.quarantine)) {
		zones.push({
			zona: "quarantine",
			root: options.quarantine,
			files: await listFiles(options.quarantine),
			dirs: await listDirs(options.quarantine),
		});
	}

	const found = new Map<string, Finding>();
	const valueDigests = new Map<string, string>();
	const add = (f: Finding): void => {
		if (!found.has(f.id)) found.set(f.id, f);
	};
	const addDraft = (d: Draft): void => {
		const f = toFinding(d);
		if (!found.has(f.id)) {
			valueDigests.set(
				f.id,
				createHash("sha256")
					.update(normalizeValue(d.valorHerencia ?? d.valor), "utf8")
					.digest("hex"),
			);
		}
		add(f);
	};

	for (const z of zones) {
		const binaries = await scanBinaries(z.root, z.files, {
			zona: z.zona,
			...(options.maxBytes === undefined ? {} : { maxBytes: options.maxBytes }),
		});
		const skipped = new Set(binaries.map((f) => f.archivo));
		for (const f of binaries) {
			add(z.zona === "quarantine" ? { ...f, estado: "aislado" } : f);
		}
		// SEG-001: names of files and directories are scanned as data too.
		for (const ruta of [...z.dirs, ...z.files]) {
			for (const d of pathDrafts(ruta, z.zona, options)) addDraft(d);
		}
		for (const archivo of z.files) {
			if (skipped.has(archivo)) continue;
			let text: string;
			try {
				text = (await readFile(join(z.root, archivo))).toString("utf8");
			} catch (error) {
				throw motorFalla(
					"mct",
					"archivo-ilegible",
					"Un archivo no se pudo leer durante el escaneo",
					error,
				);
			}
			for (const d of scanText(text, z.zona, archivo, options)) {
				addDraft(d);
			}
		}
	}

	// Second engine: real gitleaks, over each zone that has files.
	const g = options.gitleaks;
	const binary = await resolveBinary(g);
	let gitleaksVersion = "";
	for (const z of zones) {
		if (z.zona === "quarantine" && z.files.length === 0) continue;
		const { version, drafts } = await runZone(z.root, z.zona, binary, g);
		gitleaksVersion = version;
		for (const d of drafts) addDraft(d);
	}
	if (gitleaksVersion === "") {
		gitleaksVersion = await checkGitleaksVersion(binary, {
			...(g.binaryArgs === undefined ? {} : { binaryArgs: g.binaryArgs }),
			...(g.run === undefined ? {} : { run: g.run }),
		});
	}

	for (const issue of options.registryIssues ?? []) add(registryFinding(issue));

	let hallazgos = [...found.values()].sort(order);
	if (options.previos !== undefined && options.reconcile !== undefined) {
		// `aislado` is recalculated on every scan: previous ones are not carried.
		const previos = options.previos.filter((f) => f.estado !== "aislado");
		hallazgos = options.reconcile(previos, hallazgos).sort(order);
	}
	return { hallazgos, gitleaksVersion, valueDigests };
}
