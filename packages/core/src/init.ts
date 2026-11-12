import { constants, type Stats } from "node:fs";
import {
	lstat,
	mkdir,
	mkdtemp,
	open,
	readdir,
	readFile,
	realpath,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
	basename,
	dirname,
	isAbsolute,
	join,
	relative,
	resolve,
} from "node:path";
import { genericAdapter } from "@mct/adapter-generic/index";
import { n8nAdapter } from "@mct/adapter-n8n/index";
import { nodeAdapter } from "@mct/adapter-node/index";
import { pythonAdapter } from "@mct/adapter-python/index";
import { staticAdapter } from "@mct/adapter-static/index";
import { MctError } from "@mct/contract/errors";
import type { Adapter, Workspace } from "@mct/contract/types";
import ignore from "ignore";
import {
	type CloneHooks,
	cloneGithub,
	looksLikeUrl,
	parseGithubUrl,
} from "./clone.js";
import { CONFIG_FILE, loadConfig } from "./config.js";
import { hashTree } from "./hash.js";
import {
	checkDictionaryPerms,
	defaultDictionaryPath,
	guardSyncedDestination,
	type Lang,
	type SyncProvider,
} from "./init-guards.js";
import { createLogger } from "./logger.js";
import { applyCascade, createWorkspace, updateState } from "./workspace.js";

/** CLI-004 / seguridad.md. Binary megabytes (MiB), the same convention as the adapters. */
export const LIMITES = {
	total: 500 * 1024 * 1024,
	archivo: 50 * 1024 * 1024,
	archivos: 50_000,
} as const;

export type Limites = { -readonly [K in keyof typeof LIMITES]: number };

export type InitType =
	| "n8n"
	| "node"
	| "python"
	| "estatico"
	| "generico"
	| "auto";

export interface InitAviso {
	mensaje: string;
	accion?: string;
}

export interface InitSourceOptions {
	/** Folder, `.json` file or `https://github.com/<owner>/<repo>` (clone delegated to clone.ts). */
	origen: string;
	/** Directory that holds `.mct/` and `mct.config.json`. Default: cwd. */
	dest?: string;
	type?: InitType;
	force?: boolean;
	isTTY: boolean;
	lang?: Lang;
	mctVersion: string;
	/** Asks about a synced destination (CLI-006). Only a literal `true` confirms. */
	confirmar?: (info: {
		proveedor: SyncProvider;
		nombre: string;
		ruta: string;
	}) => Promise<boolean>;
	/** Asks before `--force` deletes the old workspace (CLI-008). Only a literal `true` confirms. */
	confirmarForce?: (info: {
		ruta: string;
		perdidas: string[];
	}) => Promise<boolean>;
	env?: Record<string, string | undefined>;
	/** Home used to find `~/.mct/sensible.txt`. */
	home?: string;
	/** Test hook: lower limits only; production uses LIMITES. */
	limites?: Partial<Limites>;
	now?: () => string;
	/** Ctrl+C: stops the copy, removes the partial workspace and fails with INTERRUMPIDO. */
	signal?: AbortSignal;
	/** Test hook for the GitHub clone (runner, shorter timeout). */
	clon?: CloneHooks;
}

export interface InitResult {
	workspace: Workspace;
	adapter: string;
	confianza: number;
	/** Files copied to `work/`. */
	archivos: number;
	/** Files moved to `quarantine/`. */
	cuarentena: number;
	avisos: InitAviso[];
}

const MSG = {
	es: {
		noExiste: "El origen no existe o no se puede leer.",
		accionOrigen: "Revisa la ruta y los permisos del origen.",
		ilegible: "No se pudo leer una parte del origen; no se copió nada.",
		enlace:
			"El origen contiene un enlace simbólico o una unión: no se copia ni se sigue.",
		accionEnlace: "Quita el enlace del origen y vuelve a correr init.",
		tipoRaro:
			"El origen contiene un archivo que no es normal (dispositivo, socket o similar).",
		noCarpetaNiJson: "El origen debe ser una carpeta o un archivo .json.",
		vacio: "El origen no tiene archivos que copiar.",
		accionVacio:
			"Revisa que el origen tenga archivos fuera de .git, node_modules y los excluidos.",
		limiteTotal: "El origen supera el límite de tamaño total (500 MB).",
		limiteArchivo: "Un archivo del origen supera el límite de 50 MB.",
		limiteArchivos: "El origen supera el límite de 50.000 archivos.",
		accionLimite:
			"Excluye lo que no haga falta con exclude en mct.config.json.",
		existe: "Ya hay un workspace en el destino; no se tocó.",
		accionExiste: "Usa --force para recrearlo (pide confirmación).",
		forceSinTty:
			"--force necesita confirmación humana y no hay terminal. No se tocó nada.",
		forceNo: "Cancelado: el workspace existente no se tocó.",
		accionForce: "Corre mct init --force en una terminal y confirma.",
		wsEnlace: "El workspace del destino es un enlace o no es una carpeta.",
		dentroWs: "El origen está dentro del workspace de destino.",
		configCopiada:
			"Se copió mct.config.json del origen al destino; desde ahora las etapas leen esa copia.",
		destDentro:
			"El destino es el origen o está dentro de él: init escribiría .mct/ y .gitignore en el origen.",
		accionDestDentro: "Usa --dest <carpeta fuera del origen>.",
		destNoDir: "El destino no es una carpeta.",
		globMal:
			"Un glob de exclude sale del árbol del origen (ruta absoluta o ..).",
		globMuchos: "Un glob de exclude se expande a demasiadas alternativas.",
		accionGlob: "Usa globs relativos al origen y sin ..",
		tipoNo: "El origen no coincide con el tipo pedido o no se reconoce.",
		accionTipo:
			"Usa --type n8n, node, python, estatico o generico según el origen.",
		ambiguaAccion: "Repite con --type estatico o --type node.",
		gitignoreEnlace: ".gitignore del destino es un enlace; no se escribe.",
		cortado: "Init interrumpido. El destino quedó como estaba.",
		previoNo: "No se pudo apartar el workspace existente; no se tocó.",
		accionPrevioNo:
			"Cierra lo que use .mct y vuelve a correr mct init --force.",
		previoExiste:
			"Ya existe .mct.previo: es el respaldo de un --force que no terminó.",
		previoQueda:
			"No se pudo borrar .mct.previo, el respaldo del workspace anterior; contiene datos privados.",
		accionPrevio: "Revísalo y bórralo, o renómbralo a .mct para recuperarlo.",
		residuo:
			"Init falló y no pudo limpiar: quedaron datos privados en .mct o .mct.previo dentro del destino.",
		accionResiduo:
			"Cierra lo que use esas carpetas y bórralas; si existe .mct.previo, renómbralo a .mct para recuperarlo.",
	},
	en: {
		noExiste: "The source does not exist or cannot be read.",
		accionOrigen: "Check the source path and permissions.",
		ilegible: "Part of the source could not be read; nothing was copied.",
		enlace:
			"The source contains a symbolic link or junction: it is neither copied nor followed.",
		accionEnlace: "Remove the link from the source and run init again.",
		tipoRaro:
			"The source contains a non-regular file (device, socket or similar).",
		noCarpetaNiJson: "The source must be a folder or a .json file.",
		vacio: "The source has no files to copy.",
		accionVacio:
			"Check that the source has files outside .git, node_modules and the excluded ones.",
		limiteTotal: "The source exceeds the total size limit (500 MB).",
		limiteArchivo: "A file in the source exceeds the 50 MB limit.",
		limiteArchivos: "The source exceeds the limit of 50,000 files.",
		accionLimite:
			"Exclude what you do not need with exclude in mct.config.json.",
		existe:
			"A workspace already exists at the destination; it was not touched.",
		accionExiste: "Use --force to recreate it (asks for confirmation).",
		forceSinTty:
			"--force needs human confirmation and there is no terminal. Nothing was touched.",
		forceNo: "Cancelled: the existing workspace was not touched.",
		accionForce: "Run mct init --force in a terminal and confirm.",
		wsEnlace: "The destination workspace is a link or not a folder.",
		dentroWs: "The source is inside the destination workspace.",
		configCopiada:
			"mct.config.json was copied from the source to the destination; every stage now reads that copy.",
		destDentro:
			"The destination is the source or inside the source: init would write .mct/ and .gitignore into the source.",
		accionDestDentro: "Use --dest <folder outside the source>.",
		destNoDir: "The destination is not a folder.",
		globMal: "An exclude glob leaves the source tree (absolute path or ..).",
		globMuchos: "An exclude glob expands to too many alternatives.",
		accionGlob: "Use globs relative to the source and without ..",
		tipoNo:
			"The source does not match the requested type or is not recognized.",
		accionTipo:
			"Use --type n8n, node, python, estatico or generico to match the source.",
		ambiguaAccion: "Run again with --type estatico or --type node.",
		gitignoreEnlace: "The destination .gitignore is a link; not written.",
		cortado: "Init interrupted. The destination is as it was.",
		previoNo:
			"Could not move the existing workspace aside; it was not touched.",
		accionPrevioNo: "Close whatever uses .mct and run mct init --force again.",
		previoExiste:
			".mct.previo already exists: it is the backup of a --force that did not finish.",
		previoQueda:
			"Could not delete .mct.previo, the backup of the old workspace; it holds private data.",
		accionPrevio: "Review and delete it, or rename it to .mct to recover it.",
		residuo:
			"Init failed and could not clean up: private data was left in .mct or .mct.previo in the destination.",
		accionResiduo:
			"Close whatever uses those folders and delete them; if .mct.previo exists, rename it to .mct to recover it.",
	},
} as const;

type Msg = { [K in keyof (typeof MSG)["es"]]: string };

const ALWAYS_SKIP = new Set([".git", "node_modules", ".mct", ".mct.previo"]);
const MAX_GLOB_EXPANSIONS = 1000;
/** Holds the old workspace during --force, so a failed recreation can restore it. */
const PREVIO = ".mct.previo";
const RM_RETRY = {
	recursive: true,
	force: true,
	maxRetries: 20,
	retryDelay: 250,
};
const ENV_FILE = /^\.env/i;
const NPMRC = /^\.npmrc$/i;
const WORKSPACE_ARTIFACTS: readonly [string, string][] = [
	["findings.json", "findings.json"],
	["approval.json", "approval.json"],
	["dist", "dist"],
	["publish-state.json", "publish-state.json"],
	["analysis.json", "analysis.json"],
];

function fail(
	codigo: string,
	mensaje: string,
	accion?: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError(codigo, mensaje, {
		etapa: "init",
		...(accion !== undefined && { accion }),
		...(detalle !== undefined && { detalle }),
	});
}

const isQuarantineName = (name: string): boolean =>
	ENV_FILE.test(name) || NPMRC.test(name);

// ------------------------------------------------------------ exclude globs

/** Expands `{a,b}` groups (nested too). Returns null if it would exceed the cap. */
function expandBraces(pattern: string): string[] | null {
	const out: string[] = [];
	const queue = [pattern];
	while (queue.length > 0) {
		const p = queue.pop() as string;
		const group = findGroup(p);
		if (group === null) {
			out.push(p);
			if (out.length > MAX_GLOB_EXPANSIONS) return null;
			continue;
		}
		for (const alt of group.alts) {
			queue.push(p.slice(0, group.start) + alt + p.slice(group.end + 1));
			if (queue.length + out.length > MAX_GLOB_EXPANSIONS) return null;
		}
	}
	return out;
}

/** First `{...}` group that has a top-level comma. */
function findGroup(
	p: string,
): { start: number; end: number; alts: string[] } | null {
	for (
		let start = p.indexOf("{");
		start !== -1;
		start = p.indexOf("{", start + 1)
	) {
		let depth = 0;
		let last = start + 1;
		const alts: string[] = [];
		for (let i = start; i < p.length; i++) {
			const c = p[i];
			if (c === "{") depth++;
			else if (c === "}") {
				depth--;
				if (depth === 0) {
					alts.push(p.slice(last, i));
					if (alts.length > 1) return { start, end: i, alts };
					break;
				}
			} else if (c === "," && depth === 1) {
				alts.push(p.slice(last, i));
				last = i + 1;
			}
		}
	}
	return null;
}

function escapesTree(glob: string): boolean {
	const body = glob.startsWith("!") ? glob.slice(1) : glob;
	return (
		body.startsWith("/") ||
		body.includes("\\") ||
		/^[A-Za-z]:/.test(body) ||
		body.split("/").includes("..")
	);
}

/** Config validation (T43) misses `..` and absolute paths inside braces: re-check every alternative. */
function expandExclude(globs: readonly string[], m: Msg): string[] {
	const out: string[] = [];
	for (const raw of globs) {
		// Conservative token check, also for unbalanced braces.
		for (const token of raw.split(/[,{}]/)) {
			const t = token.trim().replace(/^!/, "");
			if (
				t.startsWith("/") ||
				/^[A-Za-z]:/.test(t) ||
				t.split("/").includes("..")
			) {
				throw fail("VALIDACION", m.globMal, m.accionGlob);
			}
		}
		const alts = expandBraces(raw);
		if (alts === null) throw fail("VALIDACION", m.globMuchos, m.accionGlob);
		for (const alt of alts) {
			if (escapesTree(alt)) throw fail("VALIDACION", m.globMal, m.accionGlob);
			out.push(alt);
		}
		if (out.length > MAX_GLOB_EXPANSIONS) {
			throw fail("VALIDACION", m.globMuchos, m.accionGlob);
		}
	}
	return out;
}

// -------------------------------------------------------------------- plan

interface PlannedFile {
	abs: string;
	rel: string;
	size: number;
	zona: "work" | "quarantine";
	dev: number;
	ino: number;
}

function limitError(
	cual: "total" | "archivo" | "archivos",
	m: Msg,
	limites: Limites,
	rel?: string,
): MctError {
	const mensaje =
		cual === "total"
			? m.limiteTotal
			: cual === "archivo"
				? m.limiteArchivo
				: m.limiteArchivos;
	return fail("VALIDACION", mensaje, m.accionLimite, {
		limite: cual,
		maximo: limites[cual],
		...(rel !== undefined && { archivo: rel }),
	});
}

function unreadable(root: boolean, rel: string, m: Msg): MctError {
	return fail(
		"ORIGEN_NO_ENCONTRADO",
		root ? m.noExiste : m.ilegible,
		m.accionOrigen,
		rel === "" ? undefined : { ruta: rel },
	);
}

class Planner {
	readonly files: PlannedFile[] = [];
	bytes = 0;

	constructor(
		private readonly m: Msg,
		private readonly limites: Limites,
		private readonly excluded: (rel: string, dir: boolean) => boolean,
	) {}

	add(f: PlannedFile): void {
		if (f.size > this.limites.archivo) {
			throw limitError("archivo", this.m, this.limites, f.rel);
		}
		this.bytes += f.size;
		if (this.bytes > this.limites.total) {
			throw limitError("total", this.m, this.limites);
		}
		if (this.files.length + 1 > this.limites.archivos) {
			throw limitError("archivos", this.m, this.limites);
		}
		this.files.push(f);
	}

	async walk(root: string): Promise<void> {
		const stack: { abs: string; rel: string; quarantine: boolean }[] = [
			{ abs: root, rel: "", quarantine: false },
		];
		while (stack.length > 0) {
			const dir = stack.pop() as (typeof stack)[number];
			let names: string[];
			try {
				names = await readdir(dir.abs);
			} catch {
				throw unreadable(dir.rel === "", dir.rel, this.m);
			}
			names.sort();
			for (const name of names) {
				const lower = name.toLowerCase();
				if (ALWAYS_SKIP.has(lower)) continue;
				if (
					dir.rel === "" &&
					(lower === "mct.config.json" || lower === "decisiones.json")
				) {
					continue;
				}
				const rel = dir.rel === "" ? name : `${dir.rel}/${name}`;
				const abs = join(dir.abs, name);
				let st: Stats;
				try {
					st = await lstat(abs);
				} catch {
					throw unreadable(false, rel, this.m);
				}
				if (st.isSymbolicLink()) {
					throw fail("VALIDACION", this.m.enlace, this.m.accionEnlace, {
						ruta: rel,
					});
				}
				if (st.isDirectory()) {
					if (this.excluded(rel, true)) continue;
					stack.push({
						abs,
						rel,
						quarantine: dir.quarantine || isQuarantineName(name),
					});
				} else if (st.isFile()) {
					if (this.excluded(rel, false)) continue;
					this.add({
						abs,
						rel,
						size: st.size,
						zona:
							dir.quarantine || isQuarantineName(name) ? "quarantine" : "work",
						dev: st.dev,
						ino: st.ino,
					});
				} else {
					throw fail("VALIDACION", this.m.tipoRaro, undefined, { ruta: rel });
				}
			}
		}
	}
}

// -------------------------------------------------------------------- copy

async function copyPlanned(
	files: readonly PlannedFile[],
	ws: Workspace,
	m: Msg,
	limites: Limites,
	stopIfAborted: () => void,
): Promise<void> {
	let bytes = 0;
	for (const f of files) {
		stopIfAborted();
		const raiz = f.zona === "work" ? ws.work : ws.quarantine;
		const destino = join(raiz, ...f.rel.split("/"));
		const rel = relative(raiz, destino);
		if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
			throw fail("VALIDACION", m.enlace, m.accionEnlace, { ruta: f.rel });
		}
		await mkdir(dirname(destino), { recursive: true });
		let fh: Awaited<ReturnType<typeof open>>;
		try {
			fh = await open(f.abs, constants.O_RDONLY);
		} catch {
			throw unreadable(false, f.rel, m);
		}
		try {
			const info = await fh.stat();
			// The file must still be the regular file seen while planning (no swap for a link).
			if (
				!info.isFile() ||
				(f.ino !== 0 &&
					info.ino !== 0 &&
					(info.ino !== f.ino || info.dev !== f.dev))
			) {
				throw fail("VALIDACION", m.enlace, m.accionEnlace, { ruta: f.rel });
			}
			if (info.size > limites.archivo) {
				throw limitError("archivo", m, limites, f.rel);
			}
			bytes += info.size;
			if (bytes > limites.total) throw limitError("total", m, limites);
			const data = await fh.readFile();
			await writeFile(destino, data, { flag: "wx", mode: info.mode & 0o777 });
		} catch (e) {
			if (e instanceof MctError) throw e;
			throw unreadable(false, f.rel, m);
		} finally {
			await fh.close();
		}
	}
}

// ------------------------------------------------------------------- misc

async function inspectOrigin(
	origen: string,
	m: Msg,
): Promise<{ abs: string; dir: boolean }> {
	const abs = resolve(origen);
	let st: Stats;
	try {
		st = await lstat(abs);
	} catch {
		throw fail("ORIGEN_NO_ENCONTRADO", m.noExiste, m.accionOrigen);
	}
	if (st.isSymbolicLink()) {
		throw fail("VALIDACION", m.enlace, m.accionEnlace);
	}
	if (st.isDirectory()) return { abs, dir: true };
	if (st.isFile() && abs.toLowerCase().endsWith(".json")) {
		return { abs, dir: false };
	}
	throw fail("VALIDACION", m.noCarpetaNiJson);
}

/** True when something (file, folder or link) is at `p`. */
async function exists(p: string): Promise<boolean> {
	return lstat(p).then(
		() => true,
		() => false,
	);
}

async function realOrNull(p: string): Promise<string | null> {
	try {
		return await realpath(p);
	} catch {
		return null;
	}
}

function isInside(parent: string, child: string): boolean {
	const rel = relative(parent, child);
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** Realpath of the nearest existing ancestor plus the not-yet-created tail. */
async function realWithTail(p: string): Promise<string> {
	let cur = resolve(p);
	const tail: string[] = [];
	for (;;) {
		const real = await realOrNull(cur);
		if (real !== null) return join(real, ...tail.reverse());
		const parent = dirname(cur);
		if (parent === cur) return resolve(p);
		tail.push(basename(cur));
		cur = parent;
	}
}

/** True when `dest` is the source folder or lives inside it (case-insensitive on Windows). */
function destInsideSource(source: string, dest: string): boolean {
	const fold = (x: string): string =>
		process.platform === "win32" ? x.toLowerCase() : x;
	return isInside(fold(source), fold(dest));
}

/** Names of the artifacts that `--force` would delete, for the confirmation prompt. */
async function lostArtifacts(raiz: string): Promise<string[]> {
	const out: string[] = [];
	for (const [file, label] of WORKSPACE_ARTIFACTS) {
		try {
			await lstat(join(raiz, file));
			out.push(label);
		} catch {
			// absent
		}
	}
	return out;
}

/** Ensures `.mct/` is ignored and returns how to undo exactly that change. */
async function addToGitignore(
	dest: string,
	m: Msg,
	entry = ".mct",
): Promise<() => Promise<void>> {
	const file = join(dest, ".gitignore");
	let current = "";
	let existed = false;
	try {
		const st = await lstat(file);
		if (st.isSymbolicLink() || !st.isFile()) {
			throw fail("VALIDACION", m.gitignoreEnlace);
		}
		current = await readFile(file, "utf8");
		existed = true;
	} catch (e) {
		if (e instanceof MctError) throw e;
		if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
			throw fail("VALIDACION", m.gitignoreEnlace);
		}
	}
	const lines = current.split(/\r?\n/).map((l) => l.trim());
	if (
		lines.some(
			(l) =>
				l === entry ||
				l === `${entry}/` ||
				l === `/${entry}` ||
				l === `/${entry}/`,
		)
	) {
		return async () => undefined;
	}
	const eol = current.includes("\r\n") ? "\r\n" : "\n";
	const sep = current === "" || current.endsWith("\n") ? "" : eol;
	await writeFile(file, `${current}${sep}${entry}/${eol}`);
	return async () => {
		if (existed) await writeFile(file, current);
		else await rm(file, { force: true });
	};
}

/** Windows may hold a just-written folder open for a moment (indexer, antivirus). */
async function renameRetry(from: string, to: string): Promise<void> {
	for (let i = 0; ; i += 1) {
		try {
			await rename(from, to);
			return;
		} catch (e) {
			if (i >= 20) throw e;
			await new Promise((r) => setTimeout(r, 250));
		}
	}
}

async function dropGitignoreLine(dest: string, line: string): Promise<void> {
	const file = join(dest, ".gitignore");
	const current = await readFile(file, "utf8");
	await writeFile(
		file,
		current
			.split("\n")
			.filter((l) => l.trim() !== line)
			.join("\n"),
	);
}

async function assertGitignoreWritable(dest: string, m: Msg): Promise<void> {
	try {
		const st = await lstat(join(dest, ".gitignore"));
		if (st.isSymbolicLink() || !st.isFile()) {
			throw fail("VALIDACION", m.gitignoreEnlace);
		}
	} catch (e) {
		if (e instanceof MctError) throw e;
	}
}

const BY_ID: Readonly<Record<string, Adapter>> = {
	n8n: n8nAdapter,
	node: nodeAdapter,
	python: pythonAdapter,
	estatico: staticAdapter,
	generico: genericAdapter,
};
const AUTO_ORDER: readonly Adapter[] = [
	n8nAdapter,
	nodeAdapter,
	pythonAdapter,
	staticAdapter,
	genericAdapter,
];
const BYTES_SKIP = new Set(["node_modules", ".git"]);
const EXT_OF: Readonly<Record<string, readonly string[]>> = {
	n8n: [".json"],
	node: [".js", ".mjs", ".cjs", ".ts"],
	python: [".py"],
	estatico: [".html", ".htm"],
};

/** Bytes per lowercase extension under `root` (tie-break of DET-001). */
async function bytesByExt(root: string): Promise<Map<string, number>> {
	const out = new Map<string, number>();
	const stack = [root];
	while (stack.length > 0) {
		const dir = stack.pop() as string;
		let entries: import("node:fs").Dirent[];
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const e of entries) {
			const abs = join(dir, e.name);
			if (e.isDirectory()) {
				if (!BYTES_SKIP.has(e.name)) stack.push(abs);
			} else if (e.isFile()) {
				const dot = e.name.lastIndexOf(".");
				if (dot < 0) continue;
				const ext = e.name.slice(dot).toLowerCase();
				try {
					out.set(ext, (out.get(ext) ?? 0) + (await lstat(abs)).size);
				} catch {
					// unreadable file: counts as 0 bytes
				}
			}
		}
	}
	return out;
}

function languageBytes(id: string, bytes: Map<string, number>): number {
	const own = EXT_OF[id];
	let total = 0;
	if (own !== undefined) {
		for (const ext of own) total += bytes.get(ext) ?? 0;
		return total;
	}
	// generico: the language of everything the other adapters do not claim.
	const claimed = new Set(Object.values(EXT_OF).flat());
	for (const [ext, n] of bytes) if (!claimed.has(ext)) total += n;
	return total;
}

/** EXPERIENCE.md: ambiguous detection (DET-001). Only ids and numbers, never content. */
function ambiguousText(
	lang: Lang,
	winner: string,
	wc: number,
	nc: number,
): string {
	const site = winner === "estatico";
	if (lang === "es") {
		const que = site ? "un sitio estático" : "un proyecto python";
		const hay = site ? "index.html" : "archivos .py";
		return `No sé si es ${que} (confianza ${wc}) o un proyecto node (${nc}): hay ${hay} y package.json. No copié nada. Repite con --type ${winner} o --type node.`;
	}
	const what = site ? "a static site" : "a python project";
	const has = site ? "index.html" : ".py files";
	return `Cannot tell whether this is ${what} (confidence ${wc}) or a node project (${nc}): there is ${has} and package.json. Nothing was copied. Run again with --type ${winner} or --type node.`;
}

async function chooseAdapter(
	work: string,
	type: InitType,
	isFile: boolean,
	m: Msg,
	lang: Lang,
): Promise<{ adapter: Adapter; confianza: number }> {
	const candidates: readonly Adapter[] =
		type === "auto"
			? isFile
				? [n8nAdapter]
				: AUTO_ORDER
			: [BY_ID[type] as Adapter];
	const scored: { adapter: Adapter; confianza: number }[] = [];
	for (const adapter of candidates) {
		scored.push({ adapter, confianza: await adapter.detect(work) });
	}
	let best: { adapter: Adapter; confianza: number } | null = null;
	for (const c of scored) {
		if (c.confianza > 0 && (best === null || c.confianza > best.confianza)) {
			best = c;
		}
	}
	// A single .json is an n8n export only if its real shape says so.
	if (best === null || (isFile && best.adapter.id !== "n8n")) {
		throw fail("VALIDACION", m.tipoNo, m.accionTipo);
	}
	const top = best.confianza;
	const tied = scored.filter((c) => Math.abs(c.confianza - top) < 1e-9);
	if (tied.length > 1) {
		const bytes = await bytesByExt(work);
		best = tied.reduce((a, b) =>
			languageBytes(b.adapter.id, bytes) > languageBytes(a.adapter.id, bytes)
				? b
				: a,
		);
	}
	if (type === "auto") {
		const node = scored.find((c) => c.adapter.id === "node");
		const byFiles =
			best.adapter.id === "python" && Math.abs(best.confianza - 0.35) < 1e-9;
		if (
			node !== undefined &&
			node.confianza > 0 &&
			(best.adapter.id === "estatico" || byFiles) &&
			node.confianza >= best.confianza - 0.15 - 1e-9
		) {
			throw fail(
				"VALIDACION",
				ambiguousText(lang, best.adapter.id, best.confianza, node.confianza),
				m.ambiguaAccion,
				{
					motivo: "deteccion-ambigua",
					candidatos: [best, node].map((c) => ({
						adapter: c.adapter.id,
						confianza: c.confianza,
					})),
				},
			);
		}
	}
	return best;
}

// ------------------------------------------------------------------- main

/**
 * `mct init`: copies a folder, n8n `.json` or GitHub repo into `<dest>/.mct/work/`.
 * Never writes to the source. A URL is cloned (clone.ts) to a temp folder that is always deleted.
 */
export async function initFromSource(
	options: InitSourceOptions,
): Promise<InitResult> {
	if (!looksLikeUrl(options.origen)) return initCore(options);
	const lang: Lang = options.lang ?? "es";
	const ref = parseGithubUrl(options.origen, lang);
	const tmp = await mkdtemp(join(tmpdir(), "mct-clone-"));
	try {
		try {
			await cloneGithub({
				...options.clon,
				url: ref.url,
				dir: join(tmp, "repo"),
				lang,
				...(options.env !== undefined && { env: options.env }),
				...(options.signal !== undefined && { signal: options.signal }),
			});
		} catch (e) {
			// A killed clone looks like a failed one; Ctrl+C keeps its own code.
			if (options.signal?.aborted)
				throw fail("INTERRUMPIDO", MSG[lang].cortado);
			throw e;
		}
		return await initCore({ ...options, origen: join(tmp, "repo") }, ref.url);
	} finally {
		// Best effort with retries; a failure here never replaces the real error.
		await rm(tmp, {
			recursive: true,
			force: true,
			maxRetries: 20,
			retryDelay: 250,
		}).catch(() => undefined);
	}
}

async function initCore(
	options: InitSourceOptions,
	remoteUrl?: string,
): Promise<InitResult> {
	const lang: Lang = options.lang ?? "es";
	const m = MSG[lang];
	const limites: Limites = { ...LIMITES, ...options.limites };
	const dest = resolve(options.dest ?? process.cwd());
	const raiz = join(dest, ".mct");
	const env = options.env ?? process.env;
	const type = options.type ?? "auto";
	const t0 = Date.now();

	const origin = await inspectOrigin(options.origen, m);

	// CLI-001: init writes .mct/ and .gitignore at dest, so dest must not be the source or inside it.
	if (origin.dir) {
		const realSrc = (await realOrNull(origin.abs)) ?? origin.abs;
		if (destInsideSource(realSrc, await realWithTail(dest))) {
			throw fail("VALIDACION", m.destDentro, m.accionDestDentro);
		}
	}

	// Destination: a real directory (or not there yet), never a link.
	try {
		const st = await lstat(dest);
		if (!st.isDirectory()) throw fail("VALIDACION", m.destNoDir);
	} catch (e) {
		if (e instanceof MctError) throw e;
		if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
			throw fail("VALIDACION", m.destNoDir);
		}
	}

	// Config: invalid file or glob -> VALIDACION before touching anything.
	// CFG-002: with no config at dest, a folder source's root config is used and copied on success.
	// Never for a cloned GitHub source: a third party must not set licenses.allow or verify.
	const configOrigen =
		remoteUrl === undefined &&
		origin.dir &&
		!(await exists(join(dest, CONFIG_FILE))) &&
		(await exists(join(origin.abs, CONFIG_FILE)));
	const config = await loadConfig(configOrigen ? origin.abs : dest);
	const globs = expandExclude(config.exclude ?? [], m);
	const ig = ignore().add(globs);
	const excluded = (rel: string, dir: boolean): boolean =>
		globs.length > 0 && ig.ignores(dir ? `${rel}/` : rel);

	// The source must not live inside the workspace we write to.
	const realOrigin = (await realOrNull(origin.abs)) ?? origin.abs;
	const realDest = await realOrNull(dest);
	if (realDest !== null && isInside(join(realDest, ".mct"), realOrigin)) {
		throw fail("VALIDACION", m.dentroWs);
	}

	// Existing workspace: never touched without --force.
	let existing: Stats | null = null;
	try {
		existing = await lstat(raiz);
	} catch (e) {
		if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
			throw fail("VALIDACION", m.wsEnlace);
		}
	}
	if (existing !== null) {
		if (existing.isSymbolicLink() || !existing.isDirectory()) {
			throw fail("VALIDACION", m.wsEnlace);
		}
		if (options.force !== true) {
			throw fail("VALIDACION", m.existe, m.accionExiste);
		}
	}
	await assertGitignoreWritable(dest, m);

	// SEC-001 warning (non blocking) and CLI-006 guard (blocking), both before any copy.
	const avisos: InitAviso[] = [];
	const home = options.home ?? homedir();
	const perms = await checkDictionaryPerms({
		path: defaultDictionaryPath(home),
		lang,
		env,
	});
	if (perms.estado === "aviso" || perms.estado === "indeterminado") {
		avisos.push({
			mensaje: perms.mensaje,
			...(perms.accion !== undefined && { accion: perms.accion }),
		});
	}
	await guardSyncedDestination({
		dest,
		isTTY: options.isTTY,
		lang,
		env,
		...(options.confirmar !== undefined && { confirmar: options.confirmar }),
	});

	// Validate the whole source first: limits, links, unreadable parts.
	const planner = new Planner(m, limites, excluded);
	if (origin.dir) {
		await planner.walk(origin.abs);
	} else {
		const st = await lstat(origin.abs);
		planner.add({
			abs: origin.abs,
			rel: basename(origin.abs),
			size: st.size,
			zona: isQuarantineName(basename(origin.abs)) ? "quarantine" : "work",
			dev: st.dev,
			ino: st.ino,
		});
	}
	const enWork = planner.files.filter((f) => f.zona === "work").length;
	if (enWork === 0) throw fail("VALIDACION", m.vacio, m.accionVacio);
	const stopIfAborted = (): void => {
		if (options.signal?.aborted) throw fail("INTERRUMPIDO", m.cortado);
	};
	stopIfAborted();

	// --force: human confirmation, then recreate; the old one is kept until the new one is whole.
	const previo = join(dest, PREVIO);
	if ((await realOrNull(previo)) !== null) {
		throw fail("VALIDACION", m.previoExiste, m.accionPrevio);
	}
	let hayPrevio = false;
	let undoIgnorePrevio: (() => Promise<void>) | undefined;
	if (existing !== null) {
		if (!options.isTTY) {
			throw fail("CANCELADO", m.forceSinTty, m.accionForce);
		}
		const answer: unknown =
			options.confirmarForce === undefined
				? false
				: await options.confirmarForce({
						ruta: raiz,
						perdidas: await lostArtifacts(raiz),
					});
		stopIfAborted();
		if (answer !== true) throw fail("CANCELADO", m.forceNo, m.accionForce);
		// It holds private data: ignored before it gets a name .mct/ does not cover.
		undoIgnorePrevio = await addToGitignore(dest, m, PREVIO);
		try {
			await renameRetry(raiz, previo);
		} catch {
			await undoIgnorePrevio().catch(() => undefined);
			throw fail("INTERNO", m.previoNo, m.accionPrevioNo);
		}
		hayPrevio = true;
	}

	let ws: Workspace | undefined;
	let undoGitignore: (() => Promise<void>) | undefined;
	try {
		// The adapter id is only known after copying: create with a placeholder, then fix the state.
		ws = await createWorkspace(raiz, {
			mctVersion: options.mctVersion,
			origen:
				remoteUrl !== undefined
					? { tipo: "github", ref: remoteUrl }
					: { tipo: origin.dir ? "carpeta" : "n8n-json", ref: origin.abs },
			adapter: "pendiente",
			...(options.now !== undefined && { now: options.now }),
		});
		// Before the first private byte lands: a hard kill must not leave .mct/ committable.
		undoGitignore = await addToGitignore(dest, m);
		await copyPlanned(planner.files, ws, m, limites, stopIfAborted);
		stopIfAborted();
		const { adapter, confianza } = await chooseAdapter(
			ws.work,
			type,
			!origin.dir,
			m,
			lang,
		);
		const workSha256 = await hashTree(ws.work);
		stopIfAborted();
		await updateState(raiz, (s) =>
			applyCascade({ ...s, adapter: adapter.id }, { workSha256 }),
		);
		await createLogger(raiz, "init").log({
			evento: "init.ok",
			duracionMs: Date.now() - t0,
		});
		if (hayPrevio) {
			// The new workspace is complete: a failure here must not undo it.
			const borrado = await rm(previo, RM_RETRY).then(
				() => true,
				() => false,
			);
			if (borrado) {
				await dropGitignoreLine(dest, `${PREVIO}/`).catch(() => undefined);
			} else {
				avisos.push({ mensaje: m.previoQueda, accion: m.accionPrevio });
			}
		}
		if (configOrigen) {
			// The validated object, not a second read of the path (no TOCTOU); "wx" never overwrites.
			await writeFile(
				join(dest, CONFIG_FILE),
				`${JSON.stringify(config, null, "\t")}\n`,
				{ flag: "wx" },
			);
			avisos.push({ mensaje: m.configCopiada });
		}
		return {
			workspace: ws,
			adapter: adapter.id,
			confianza,
			archivos: enWork,
			cuarentena: planner.files.length - enWork,
			avisos,
		};
	} catch (e) {
		const limpio = await rm(raiz, RM_RETRY).then(
			() => true,
			() => false,
		);
		const restaurado =
			limpio &&
			(!hayPrevio ||
				(await renameRetry(previo, raiz).then(
					() => true,
					() => false,
				)));
		if (!restaurado) {
			// .gitignore stays as is on purpose: the leftovers are private data.
			const codigo = e instanceof MctError ? e.codigo : "INTERNO";
			throw fail(codigo, m.residuo, m.accionResiduo, { residuo: true });
		}
		await undoGitignore?.().catch(() => undefined);
		await undoIgnorePrevio?.().catch(() => undefined);
		throw e;
	}
}
