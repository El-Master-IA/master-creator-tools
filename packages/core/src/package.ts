import { createHash } from "node:crypto";
import {
	copyFile,
	lstat,
	mkdir,
	open,
	readdir,
	readFile,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { genericAdapter } from "@mct/adapter-generic/index";
import { n8nAdapter } from "@mct/adapter-n8n/index";
import { findRegistryIssues, nodeAdapter } from "@mct/adapter-node/index";
import { pythonAdapter } from "@mct/adapter-python/index";
import { pickPythonImage } from "@mct/adapter-python/verify";
import { staticAdapter } from "@mct/adapter-static/index";
import { MctError } from "@mct/contract/errors";
import type {
	Adapter,
	Analysis,
	Change,
	Finding,
	ReadmeConfig,
	ReadmeContenido,
	Workspace,
} from "@mct/contract/types";
import {
	binaryFindingId,
	classifyContent,
	HEAD_BYTES,
} from "@mct/scanner/binary";
import { detectDictionary, loadDictionary } from "@mct/scanner/dictionary";
import { leerClave } from "@mct/scanner/finding-id";
import { detectPii } from "@mct/scanner/pii";
import type { ScanGitleaksOptions } from "@mct/scanner/scan";
import { scan } from "@mct/scanner/scan";
import { detectSecrets } from "@mct/scanner/secrets";
import { stripMetadata } from "@mct/scanner/strip-metadata";
import { type RepoInput, renderRepo } from "@mct/templates/render";
import { verifyApproval } from "./approval.js";
import { hashTree } from "./hash.js";
import { defaultDictionaryPath } from "./init-guards.js";
import { createLogger } from "./logger.js";
import {
	applyCascade,
	readState,
	reconcileFindings,
	withLock,
	workspacePaths,
	writeState,
} from "./workspace.js";

export interface StagePackageOptions {
	/** Copyright holder for LICENSE (required, already resolved by the caller). */
	holder: string;
	/** Copyright year. */
	year: number;
	/** `mct.config.json` › `readme`, already validated (CFG-003, PKG-008). */
	readme?: ReadmeConfig;
	/** Home that holds `~/.mct/sensible.txt` and the pinned gitleaks. */
	home?: string;
	gitleaks?: Partial<ScanGitleaksOptions>;
	now?: () => string;
	/** Test seam: defaults to the built-in adapters. */
	adapters?: readonly Adapter[];
}

export interface StagePackageResult {
	dist: string;
	archivos: number;
	distSha256: string;
}

const ADAPTERS: readonly Adapter[] = [
	nodeAdapter,
	n8nAdapter,
	pythonAdapter,
	staticAdapter,
	genericAdapter,
];

const TEST_FILE = /^(test_.*|.*_test).py$/;

/** True if the tree has tests/, test/ or test_*.py / *_test.py files (PKG-006). */
async function hasPythonTests(dir: string, depth = 0): Promise<boolean> {
	if (depth > 6) return false;
	for (const e of await readdir(dir, { withFileTypes: true })) {
		if (e.isDirectory()) {
			if (e.name === "tests" || e.name === "test") return true;
			if (e.name === "node_modules" || e.name.startsWith(".")) continue;
			if (await hasPythonTests(join(dir, e.name), depth + 1)) return true;
		} else if (e.isFile() && TEST_FILE.test(e.name)) return true;
	}
	return false;
}

/** CI data taken from the Analysis and the work tree (PKG-006). */
async function ciData(
	adapterId: string,
	analysis: Analysis,
	work: string,
): Promise<NonNullable<RepoInput["ci"]>> {
	if (adapterId !== "python") return {};
	let pythonVersion = "3.13";
	try {
		const m = /^python:(3.d+)-slim/.exec(
			pickPythonImage(analysis.requiresPython),
		);
		if (m?.[1]) pythonVersion = m[1];
	} catch {
		// verify blocks with version-python; the CI keeps the lowest pinned version.
	}
	const cmd = analysis.comandos.install;
	const instalacion =
		cmd === undefined
			? "ninguna"
			: cmd.includes("uv export")
				? "uv"
				: cmd.includes("-r requirements.txt")
					? "requirements"
					: analysis.gestor === "poetry"
						? "poetry"
						: "proyecto";
	return {
		pythonVersion,
		instalacion,
		tests: await hasPythonTests(work),
		poetryLock: await exists(join(work, "poetry.lock")),
	};
}
/**
 * PKG-009: the README content is checked raw, before the template escapes it, so a
 * secret, personal datum or dictionary term written with `&`, `|` or Markdown marks
 * cannot slip past the post-render scan. Never repeats the value.
 */
function revisarContenido(
	contenido: ReadmeContenido,
	terms: readonly string[],
): void {
	const campos: [string, string][] = [];
	for (const [k, v] of Object.entries(contenido)) {
		const textos = (Array.isArray(v) ? v : [v]).flatMap((x) =>
			typeof x === "string" ? [x] : Object.values(x as Record<string, string>),
		);
		campos.push([k, textos.join("\n")]);
	}
	for (const [campo, texto] of campos) {
		const sucio = texto.replace(/[*_`\\~]/g, "");
		const hay =
			detectSecrets(texto).length > 0 ||
			detectPii(texto).length > 0 ||
			(terms.length > 0 &&
				(detectDictionary(texto, terms).length > 0 ||
					detectDictionary(sucio, terms).length > 0));
		if (hay) {
			throw new MctError(
				"PUERTA_BLOQUEADA",
				`readme.contenido.${campo} tiene un secreto, un dato personal o un término del diccionario`,
				{
					etapa: "package",
					accion: `Quita ese dato de readme.contenido.${campo} en mct.config.json y repite package`,
					detalle: { campo: `readme.contenido.${campo}` },
				},
			);
		}
	}
}

const STAGING = "dist.new";
/** Files the project may already ship: the project copy wins over the template. */
const PROJECT_WINS = (ruta: string): boolean =>
	ruta === ".env.example" || ruta.startsWith(".github/workflows/");

function invalido(
	mensaje: string,
	detalle?: Record<string, unknown>,
): MctError {
	return new MctError("WORKSPACE_INVALIDO", mensaje, {
		etapa: "package",
		accion: "Revisa el workspace o recréalo con init --force",
		...(detalle !== undefined && { detalle }),
	});
}

function fuera(motivo: string): MctError {
	return new MctError("VALIDACION", "Un cambio sale de dist/", {
		etapa: "package",
		accion: "Corrige el adaptador: sus cambios deben quedar dentro de dist/",
		detalle: { motivo },
	});
}

/**
 * PKG-005: normalized relative path that must stay inside `base`.
 * Rejects absolute paths, drive letters, backslashes, `.`/`..`/empty segments
 * and NUL; returns the absolute target.
 */
export function resolveInside(base: string, ruta: unknown): string {
	if (typeof ruta !== "string" || ruta === "") throw fuera("ruta-vacia");
	if (ruta.includes("\0")) throw fuera("nul");
	if (ruta.includes("\\")) throw fuera("barra-invertida");
	if (ruta.startsWith("/") || /^[A-Za-z]:/.test(ruta)) throw fuera("absoluta");
	for (const seg of ruta.split("/")) {
		if (seg === "" || seg === "." || seg === "..") throw fuera("segmento");
	}
	const target = resolve(base, ruta);
	const rel = relative(resolve(base), target);
	if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) {
		throw fuera("fuera");
	}
	return target;
}

async function exists(path: string): Promise<boolean> {
	try {
		await lstat(path);
		return true;
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw invalido("No se pudo inspeccionar una ruta de dist/");
	}
}

/** Rejects a link anywhere along an existing path under `base`. */
async function assertNoLinkAlong(base: string, ruta: string): Promise<void> {
	let cur = base;
	for (const seg of ruta.split("/")) {
		cur = join(cur, seg);
		try {
			if ((await lstat(cur)).isSymbolicLink()) throw fuera("enlace");
		} catch (cause) {
			if (cause instanceof MctError) throw cause;
			if ((cause as NodeJS.ErrnoException).code === "ENOENT") return;
			throw invalido("No se pudo inspeccionar una ruta de dist/");
		}
	}
}

type Edit = Extract<Change, { tipo: "editar" }>;

/**
 * Validates every Change first and only then applies them, so a bad one means
 * nothing is applied (PKG-005). Offsets are over the raw UTF-8 text.
 */
export async function applyChanges(
	base: string,
	changes: readonly Change[],
): Promise<void> {
	const edits = new Map<string, Edit[]>();
	const created = new Set<string>();
	for (const c of changes) {
		if (c === null || typeof c !== "object") throw fuera("cambio");
		const target = resolveInside(base, c.ruta);
		await assertNoLinkAlong(base, c.ruta);
		if (c.tipo === "editar") {
			if (!Number.isInteger(c.desde) || !Number.isInteger(c.hasta)) {
				throw fuera("offsets");
			}
			if (typeof c.texto !== "string") throw fuera("texto");
			const list = edits.get(c.ruta) ?? [];
			list.push(c);
			edits.set(c.ruta, list);
		} else if (c.tipo === "crear") {
			if (typeof c.contenido !== "string") throw fuera("contenido");
			if (created.has(c.ruta) || (await exists(target))) {
				throw new MctError(
					"VALIDACION",
					"Un cambio crea un archivo que ya existe",
					{ etapa: "package" },
				);
			}
			created.add(c.ruta);
		} else if (c.tipo === "borrar") {
			const info = await lstat(target).catch(() => null);
			if (info === null || !info.isFile()) throw fuera("inexistente");
		} else {
			throw fuera("tipo");
		}
	}
	const texts = new Map<string, string>();
	for (const [ruta, list] of edits) {
		const target = resolveInside(base, ruta);
		const info = await lstat(target).catch(() => null);
		if (info === null || !info.isFile()) throw fuera("inexistente");
		let text = (await readFile(target)).toString("utf8");
		let limit = text.length;
		for (const e of [...list].sort((a, b) => b.desde - a.desde)) {
			if (e.desde < 0 || e.hasta < e.desde || e.hasta > limit) {
				throw fuera("offsets");
			}
			text = text.slice(0, e.desde) + e.texto + text.slice(e.hasta);
			limit = e.desde;
		}
		texts.set(ruta, text);
	}
	for (const [ruta, text] of texts) {
		await writeFile(resolveInside(base, ruta), text);
	}
	for (const c of changes) {
		const target = resolveInside(base, c.ruta);
		if (c.tipo === "crear") {
			await mkdir(dirname(target), { recursive: true });
			await writeFile(target, c.contenido);
		} else if (c.tipo === "borrar") {
			await rm(target);
		}
	}
}

async function readHead(path: string): Promise<Uint8Array> {
	const handle = await open(path, "r");
	try {
		const buf = Buffer.alloc(HEAD_BYTES);
		const { bytesRead } = await handle.read(buf, 0, HEAD_BYTES, 0);
		return buf.subarray(0, bytesRead);
	} finally {
		await handle.close();
	}
}

function startsWithBytes(head: Uint8Array, sig: readonly number[]): boolean {
	return sig.every((byte, i) => head[i] === byte);
}

function isJpegOrPng(head: Uint8Array): boolean {
	return (
		startsWithBytes(head, [0xff, 0xd8, 0xff]) ||
		startsWithBytes(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
	);
}

/** HEIF/HEIC and AVIF major or compatible brands: ISO-BMFF images that carry EXIF/GPS. */
const ISO_IMAGE_BRANDS = new Set([
	"heic",
	"heix",
	"hevc",
	"hevx",
	"heim",
	"heis",
	"hevm",
	"hevs",
	"mif1",
	"mif2",
	"msf1",
	"avif",
	"avis",
	// Canon CR3 raw: ISO-BMFF with EXIF and GPS.
	"crx ",
]);
const JP2_SIGNATURE = [
	0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];
/** TIFF-like and layered formats with EXIF/XMP that classifyContent does not know. */
const OTHER_IMAGE_HEADS: readonly (readonly number[])[] = [
	[0x49, 0x49, 0x2b, 0x00], // BigTIFF little endian
	[0x4d, 0x4d, 0x00, 0x2b], // BigTIFF big endian
	[0x49, 0x49, 0x52, 0x4f], // Olympus ORF
	[0x49, 0x49, 0x52, 0x53], // Olympus ORF
	[0x4d, 0x4d, 0x4f, 0x52], // Olympus ORF big endian
	[0x49, 0x49, 0x55, 0x00], // Panasonic RW2
	[0x38, 0x42, 0x50, 0x53], // Photoshop PSD/PSB
];
const JXL_CODESTREAM = [0xff, 0x0a];
const JXL_BOX = [
	0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];

/**
 * Images the scanner does not classify as such (HEIC, AVIF, CR3, JPEG 2000,
 * JPEG XL, BigTIFF, ORF, RW2, PSD): they keep EXIF/GPS and there is no stripper
 * for them, so they must not reach dist/. MP4/MOV share ftyp but not the brands.
 */
export function isUnstrippableImage(head: Uint8Array): boolean {
	if (
		startsWithBytes(head, JXL_CODESTREAM) ||
		startsWithBytes(head, JXL_BOX) ||
		startsWithBytes(head, JP2_SIGNATURE) ||
		OTHER_IMAGE_HEADS.some((sig) => startsWithBytes(head, sig))
	) {
		return true;
	}
	const ascii = (from: number, to: number): string =>
		String.fromCharCode(...head.subarray(from, to));
	if (head.length < 12 || ascii(4, 8) !== "ftyp") return false;
	const declared =
		(((head[0] ?? 0) << 24) |
			((head[1] ?? 0) << 16) |
			((head[2] ?? 0) << 8) |
			(head[3] ?? 0)) >>>
		0;
	// size 1: a 64-bit size follows the type; size 0: the box runs to the end.
	const brandAt = declared === 1 ? 16 : 8;
	const boxEnd =
		declared === 0 || declared === 1
			? head.length
			: Math.min(head.length, declared);
	if (ISO_IMAGE_BRANDS.has(ascii(brandAt, brandAt + 4))) return true;
	// Compatible brands follow the 4-byte minor version.
	for (let at = brandAt + 8; at + 4 <= boxEnd; at += 4) {
		if (ISO_IMAGE_BRANDS.has(ascii(at, at + 4))) return true;
	}
	return false;
}

/**
 * The id of a binary finding carries the hash of its content, and stripping
 * EXIF/XMP changes the bytes. `stripped` maps each cleaned file to the SHA-256
 * of its ORIGINAL bytes: a cleaned image inherits a decision only when the
 * donor's id is the one that original would have (same rule, same path, same
 * bytes). A replaced image with the same name keeps its finding open.
 */
export function inheritStripped(
	previos: readonly Finding[],
	final: readonly Finding[],
	stripped: ReadonlyMap<string, string>,
	clave: Uint8Array,
): Finding[] {
	const donors = new Map<string, Finding>();
	for (const f of previos) {
		if (f.tipo !== "binario" || f.zona !== "work") continue;
		if (!INHERITABLE.has(f.estado)) continue;
		donors.set(f.id, f);
	}
	return final.map((f) => {
		if (f.estado !== "abierto" || f.tipo !== "binario" || f.zona !== "work") {
			return f;
		}
		const original = stripped.get(f.archivo);
		if (original === undefined) return f;
		const donor = donors.get(
			binaryFindingId(f.regla, f.archivo, original, clave),
		);
		if (donor === undefined) return f;
		return {
			...f,
			estado: donor.estado,
			...(donor.motivo !== undefined && { motivo: donor.motivo }),
			...(donor.decidio !== undefined && { decidio: donor.decidio }),
			...(donor.decididoEn !== undefined && { decididoEn: donor.decididoEn }),
		};
	});
}

/** Copies work/ into staging; images lose EXIF/XMP (SCAN-011). Links are rejected. */
async function copyTree(
	from: string,
	to: string,
	stripped: Map<string, string>,
	rel = "",
): Promise<void> {
	await mkdir(join(to, rel), { recursive: true });
	for (const entry of await readdir(join(from, rel), { withFileTypes: true })) {
		const child = rel === "" ? entry.name : `${rel}/${entry.name}`;
		if (entry.isSymbolicLink()) {
			throw invalido("Hay un enlace simbólico en work/", { ruta: child });
		}
		if (entry.isDirectory()) {
			await copyTree(from, to, stripped, child);
		} else if (entry.isFile()) {
			const src = join(from, child);
			const dst = join(to, child);
			const head = await readHead(src);
			if (isUnstrippableImage(head)) {
				throw invalido("Formato de imagen sin limpieza de metadatos", {
					ruta: child,
					accion: "Convierte la imagen a PNG o JPEG, o quítala de work/",
				});
			}
			if (classifyContent(head) === "image") {
				if (isJpegOrPng(head)) {
					const original = await readFile(src);
					const clean = stripMetadata(original);
					stripped.set(
						child,
						createHash("sha256").update(original).digest("hex"),
					);
					await writeFile(dst, clean, {
						mode: (await lstat(src)).mode & 0o777,
					});
				} else {
					// ICO (embedded PNG with eXIf/XMP), BMP (bytes after the pixels), GIF,
					// WebP and TIFF can carry metadata we cannot strip: fail closed.
					throw invalido("Formato de imagen sin limpieza de metadatos", {
						ruta: child,
						accion: "Convierte la imagen a PNG o JPEG, o quítala de work/",
					});
				}
			} else {
				await copyFile(src, dst);
			}
		} else {
			throw invalido("Hay un archivo especial en work/", { ruta: child });
		}
	}
}

const INHERITABLE = new Set(["aceptado", "falso-positivo"]);

/**
 * generalize can shift lines in edited files, and the id includes the line. An
 * open finding in an edited file inherits the human decision of a pre-edit
 * finding only when engine, rule, file and the digest of the detected value are
 * equal: a different secret behind the same mask never inherits, and a value
 * that only moved or was reformatted keeps its decision (PKG-003). Findings
 * without a digest never inherit. One decision per pre-edit finding.
 */
export function inheritDecisions(
	pre: readonly Finding[],
	preDigests: ReadonlyMap<string, string>,
	final: readonly Finding[],
	finalDigests: ReadonlyMap<string, string>,
	edited: ReadonlySet<string>,
): Finding[] {
	const keyOf = (f: Finding, digests: ReadonlyMap<string, string>) => {
		const digest = digests.get(f.id);
		return digest === undefined
			? null
			: [f.motor, f.regla, f.archivo, digest].join("\n");
	};
	const pool = new Map<string, Finding[]>();
	const finalIds = new Set(
		final.filter((f) => INHERITABLE.has(f.estado)).map((f) => f.id),
	);
	for (const f of pre) {
		if (!INHERITABLE.has(f.estado) || !edited.has(f.archivo)) continue;
		if (finalIds.has(f.id)) continue;
		const key = keyOf(f, preDigests);
		if (key === null) continue;
		const list = pool.get(key) ?? [];
		list.push(f);
		pool.set(key, list);
	}
	return final.map((f) => {
		if (f.estado !== "abierto" || !edited.has(f.archivo)) return f;
		const key = keyOf(f, finalDigests);
		const donor = key === null ? undefined : pool.get(key)?.shift();
		if (donor === undefined) return f;
		return {
			...f,
			estado: donor.estado,
			...(donor.motivo !== undefined && { motivo: donor.motivo }),
			...(donor.decidio !== undefined && { decidio: donor.decidio }),
			...(donor.decididoEn !== undefined && { decididoEn: donor.decididoEn }),
		};
	});
}

async function countFiles(dir: string): Promise<number> {
	let n = 0;
	for (const e of await readdir(dir, { withFileTypes: true })) {
		n += e.isDirectory() ? await countFiles(join(dir, e.name)) : 1;
	}
	return n;
}

async function readPrevious(raiz: string): Promise<Finding[]> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(await readFile(join(raiz, "findings.json"), "utf8"));
	} catch {
		throw invalido("findings.json no existe o no es legible");
	}
	const obj = parsed as { schemaVersion?: unknown; hallazgos?: unknown };
	if (
		parsed === null ||
		typeof parsed !== "object" ||
		obj.schemaVersion !== 2 ||
		!Array.isArray(obj.hallazgos)
	) {
		throw invalido("findings.json trae una forma o schemaVersion inválidos");
	}
	return obj.hallazgos as Finding[];
}

async function projectName(work: string, ref: string): Promise<string> {
	try {
		const pkg: unknown = JSON.parse(
			await readFile(join(work, "package.json"), "utf8"),
		);
		const name = (pkg as { name?: unknown } | null)?.name;
		if (typeof name === "string" && /^[\w@./-]{1,100}$/.test(name)) return name;
	} catch {
		// Falls back to the origin name.
	}
	const base = basename(ref.replace(/[\\/]+$/, "")).replace(/\.[^.]*$/, "");
	return /^[\w.-]{1,100}$/.test(base) ? base : "project";
}

/**
 * Package stage (api.md › package): verifies the approval, builds dist/ from
 * work/ in a staging directory, strips image metadata, generalizes only inside
 * dist/ (PKG-005), renders the standard files and re-scans dist/ (PKG-003).
 * dist/ is replaced only when everything before the swap succeeded.
 */
export async function stagePackage(
	raiz: string,
	options: StagePackageOptions,
): Promise<StagePackageResult> {
	const now = options.now ?? (() => new Date().toISOString());
	const home = options.home ?? homedir();
	const ws = workspacePaths(raiz);
	const staging = join(raiz, STAGING);
	const t0 = Date.now();

	let abiertos = 0;
	const result = await withLock(raiz, async () => {
		const state = await readState(raiz);
		await verifyApproval(raiz, state);
		const adapter = (options.adapters ?? ADAPTERS).find(
			(a) => a.id === state.adapter,
		);
		if (adapter === undefined) {
			throw invalido("El adaptador del workspace no existe");
		}
		try {
			for (const p of [ws.dist, staging]) {
				if ((await exists(p)) && (await lstat(p)).isSymbolicLink()) {
					throw invalido("dist/ no puede ser un enlace simbólico");
				}
			}
			await rm(staging, { recursive: true, force: true });
			const stripped = new Map<string, string>();
			await copyTree(ws.work, staging, stripped);

			const stagedWs: Workspace = { ...ws, dist: staging };
			const analysis = await adapter.analyze(ws);
			const g = options.gitleaks ?? {};
			const terms = await loadDictionary(defaultDictionaryPath(home));
			const runScan = async (dir: string, previos: Finding[]) => {
				const r = await scan({
					work: dir,
					quarantine: join(raiz, "tmp", "no-quarantine"),
					rules: adapter.rules(),
					dictionary: terms,
					registryIssues: await findRegistryIssues({ ...ws, work: dir }),
					previos,
					reconcile: reconcileFindings,
					gitleaks: {
						installDir: join(home, ".mct", "bin"),
						tmpDir: join(raiz, "tmp"),
						...g,
					},
				});
				return {
					hallazgos: r.hallazgos,
					digests: r.valueDigests ?? new Map<string, string>(),
				};
			};
			// Pre-edit scan: same bytes as work/, so human decisions keep their ids.
			const previos = await readPrevious(raiz);
			const pre = await runScan(staging, previos);
			const changes: Change[] = adapter.generalize
				? await adapter.generalize(stagedWs)
				: [];
			await applyChanges(staging, changes);

			const nombre = await projectName(ws.work, state.origen.ref);
			if (options.readme?.plantilla === "el-master-ia") {
				revisarContenido(options.readme.contenido, terms);
			}
			const plantillas: Change[] = [];
			const repoInput: RepoInput = {
				hints: adapter.packageHints(analysis),
				adaptador: adapter.id,
				ci: await ciData(adapter.id, analysis, ws.work),
				titular: options.holder,
				nombre,
				anio: options.year,
				...(options.readme !== undefined && { readme: options.readme }),
			};
			let archivosRepo = renderRepo(repoInput);
			if (options.readme?.plantilla === "el-master-ia") {
				// PKG-008 "Qué trae": first level of dist/ = staging plus the template files.
				const primero = new Set<string>();
				for (const e of await readdir(staging, { withFileTypes: true })) {
					primero.add(e.isDirectory() ? `${e.name}/` : e.name);
				}
				for (const f of archivosRepo) {
					const [cabeza, ...resto] = f.ruta.split("/");
					if (cabeza) primero.add(resto.length > 0 ? `${cabeza}/` : cabeza);
				}
				primero.delete("README.es.md");
				archivosRepo = renderRepo({ ...repoInput, queTrae: [...primero] });
				// The pair is README.md + README.en.md: a project README.es.md would contradict it.
				const viejo = join(staging, "README.es.md");
				if (await exists(viejo)) await rm(viejo);
			}
			for (const f of archivosRepo) {
				const target = resolveInside(staging, f.ruta);
				if (await exists(target)) {
					if (PROJECT_WINS(f.ruta)) continue;
					await rm(target);
				}
				plantillas.push({
					tipo: "crear",
					ruta: f.ruta,
					contenido: f.contenido,
				});
			}
			await applyChanges(staging, plantillas);

			const distSha256 = await hashTree(staging);
			const post = await runScan(staging, pre.hallazgos);
			const inherited = inheritDecisions(
				pre.hallazgos,
				pre.digests,
				post.hallazgos,
				post.digests,
				new Set(changes.flatMap((c) => (c.tipo === "editar" ? [c.ruta] : []))),
			);
			const scanned = inheritStripped(
				previos,
				inherited,
				stripped,
				await leerClave(raiz),
			);
			abiertos = scanned.filter((h) => h.estado === "abierto").length;

			await rm(ws.dist, { recursive: true, force: true });
			await rename(staging, ws.dist);
			const archivos = await countFiles(ws.dist);

			const ts = now();
			let next = applyCascade(await readState(raiz), { distSha256 }, ts);
			next = {
				...next,
				etapas: {
					...next.etapas,
					package: { estado: abiertos > 0 ? "bloqueada" : "ok", ts },
				},
			};
			await writeState(raiz, next);
			await createLogger(raiz, "package", { now }).log({
				evento: "package.ok",
				duracionMs: Date.now() - t0,
			});
			return { dist: ws.dist, archivos, distSha256 };
		} catch (error) {
			await rm(staging, { recursive: true, force: true }).catch(() => {});
			await createLogger(raiz, "package", { now })
				.error(error)
				.catch(() => {});
			throw error;
		}
	});

	if (abiertos > 0) {
		throw new MctError(
			"PUERTA_BLOQUEADA",
			`dist/ tiene ${abiertos} hallazgos sin resolver`,
			{
				etapa: "package",
				accion: "Corre: mct sanitize",
				detalle: { abiertos },
			},
		);
	}
	return result;
}
