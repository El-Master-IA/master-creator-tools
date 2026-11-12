#!/usr/bin/env node
// liberar.mjs: parte determinista del plugin /liberar (spec plugin.md, PLG-001..PLG-005).
// Sin dependencias. Cada subcomando escribe un JSON en stdout.
// Códigos de salida: 0 = el flujo puede seguir, 2 = uso o validación inválidos,
// 3 = el flujo se detiene (el JSON trae el motivo y la acción).
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	realpathSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const AQUI = dirname(fileURLToPath(import.meta.url));
const ETAPAS = ["init", "scan", "sanitize", "licenses", "package", "verify"];
const ADAPTADORES = ["n8n", "node", "python", "estatico", "generico"];
const CHEQUEOS = ["gitleaks", "docker", "ssh", "github", "permisos"];
const SINTETICAS_SINLOCK = new Set([
	"(dependencias transitivas sin lockfile)",
	"(instalación sin respetar poetry.lock)",
	"(package.json sin lockfile)",
]);
const SHA = /^[0-9a-f]{64}$/;
const NOMBRE = /^[A-Z][A-Z0-9_]{0,63}$/;

class Salida extends Error {
	constructor(codigo, cuerpo) {
		super("salida");
		this.codigo = codigo;
		this.cuerpo = cuerpo;
	}
}
const detener = (cuerpo) => new Salida(3, { detener: true, ...cuerpo });
const invalido = (mensaje) => new Salida(2, { error: mensaje });

const TXT = {
	es: {
		noSigo: "No sigo: ",
		doctorRoto:
			"No entendí la salida de mct doctor --json (no es JSON válido o le faltan chequeos). No sigo: corre mct doctor en tu terminal y mira qué pasa.",
		sinDocker: (a) =>
			`El adaptador es ${a} y no hay Docker local ni verify.remoto. Instala Docker o elige un alias de ~/.ssh/config para verify.remoto. No sigo.`,
		holder:
			"git config user.name está vacío. ¿Qué nombre va como titular en la LICENSE? No escribo nada hasta tenerlo.",
		rechazada:
			"No escribí mct.config.json. Sigo sin configuración: sin exclude extra y con Docker local para verify.",
		publicar: (repo) =>
			`Todas las puertas pasaron hasta verify. Para publicar, corre tú en tu terminal: mct publish --repo ${repo}`,
		force: (origen, dest) =>
			`El workspace en ${dest} no sirve tal cual (es de otra versión o de otro estado). No uso --force por ti: corre en tu terminal mct init ${origen} --dest ${dest} --force y avísame aquí cuando termine.`,
		terminal: (dest) =>
			`Decídelo tú en tu terminal: mct sanitize --workspace ${join(dest, ".mct")} (y avísame aquí cuando termines)`,
	},
	en: {
		noSigo: "Stopping: ",
		doctorRoto:
			"Could not read the output of mct doctor --json (not valid JSON or checks missing). Stopping: run mct doctor in your terminal and see what happens.",
		sinDocker: (a) =>
			`The adapter is ${a} and there is no local Docker or verify.remoto. Install Docker or pick an alias from ~/.ssh/config for verify.remoto. Stopping.`,
		holder:
			"git config user.name is empty. Which name goes as holder in the LICENSE? Nothing is written until I have it.",
		rechazada:
			"mct.config.json was not written. Continuing without configuration: no extra exclude and local Docker for verify.",
		publicar: (repo) =>
			`All gates passed up to verify. To publish, run it yourself in your terminal: mct publish --repo ${repo}`,
		force: (origen, dest) =>
			`The workspace at ${dest} cannot be used as is (another version or state). I do not use --force for you: run mct init ${origen} --dest ${dest} --force in your terminal and tell me here when it is done.`,
		terminal: (dest) =>
			`Decide it yourself in your terminal: mct sanitize --workspace ${join(dest, ".mct")} (and tell me here when you finish)`,
	},
};

// ---------- utilidades ----------

function parseArgs(argv) {
	const pos = [];
	const op = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a.startsWith("--")) {
			const k = a.slice(2);
			const sig = argv[i + 1];
			if (sig === undefined || (sig.startsWith("--") && sig.length > 2))
				op[k] = true;
			else {
				op[k] = sig;
				i++;
			}
		} else pos.push(a);
	}
	return { pos, op };
}

function leerStdin() {
	try {
		return readFileSync(0, "utf8");
	} catch {
		return "";
	}
}

function leerEntrada(op, clave = "entrada") {
	const v = op[clave];
	if (typeof v === "string" && v !== "-") return readFileSync(v, "utf8");
	return leerStdin();
}

function jsonONulo(texto) {
	try {
		return JSON.parse(texto);
	} catch {
		return null;
	}
}

const lang = (op) => (op.lang === "en" ? "en" : "es");
const homeDir = () => process.env.HOME || process.env.USERPROFILE || homedir();

function destinoDe(origen) {
	const o = resolve(origen);
	return join(homeDir(), ".mct", "liberar", basename(o));
}

function requerirDest(op) {
	if (typeof op.dest !== "string") throw invalido("falta --dest");
	return resolve(op.dest);
}

function pluginVersion() {
	try {
		return JSON.parse(
			readFileSync(join(AQUI, "..", ".claude-plugin", "plugin.json"), "utf8"),
		).version;
	} catch {
		return "0.2.0";
	}
}

// ---------- ejecución de mct ----------

/**
 * Dogfooding only: the origin is this plugin's own source checkout (plugin/ lives in
 * the mct repo). Trust is never decided from data inside the origin (SEG-003).
 */
function esRepoMct(origen) {
	try {
		return (
			realpathSync(resolve(origen)) === realpathSync(join(AQUI, "..", ".."))
		);
	} catch {
		return false;
	}
}

export function resolverMct(origen) {
	const bin = process.env.MCT_BIN;
	if (bin) {
		if (/\.(mjs|js|cjs)$/.test(bin))
			return {
				cmd: process.execPath,
				pre: [bin],
				shell: false,
				explicito: true,
			};
		return { cmd: bin, pre: [], shell: false, explicito: true };
	}
	const win = process.platform === "win32";
	// Un bin local del origen solo vale si el origen es el propio repo de mct (dogfooding).
	if (origen && esRepoMct(origen)) {
		const local = join(
			resolve(origen),
			"node_modules",
			".bin",
			win ? "mct.cmd" : "mct",
		);
		if (existsSync(local)) return { cmd: local, pre: [], shell: win };
	}
	return {
		cmd: win ? "npx.cmd" : "npx",
		pre: ["-p", `master-creator-tools@${pluginVersion()}`, "mct"],
		shell: win,
	};
}

export function versionCoincide(salida, esperada) {
	const m = /\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/.exec(String(salida ?? ""));
	return m !== null && m[0] === esperada;
}

function comillas(a) {
	if (/["%\r\n]/.test(a)) throw invalido("argumento no permitido para mct");
	return /[\s&|<>^()]/.test(a) ? `"${a}"` : a;
}

/** Ejecuta mct sin tocar su entrada estándar; devuelve { code, salida, texto }. */
function correrMct(args, origen) {
	const r = resolverMct(origen);
	const todos = [...r.pre, ...args];
	const res = spawnSync(r.cmd, r.shell ? todos.map(comillas) : todos, {
		encoding: "utf8",
		shell: r.shell,
		stdio: ["ignore", "pipe", "pipe"],
		maxBuffer: 64 * 1024 * 1024,
		windowsHide: true,
	});
	if (res.error) {
		return {
			code: 70,
			salida: null,
			texto: "",
			falloEjecutar: String(res.error.code ?? "ERROR"),
		};
	}
	return {
		code: res.status ?? 1,
		salida: jsonONulo(res.stdout ?? ""),
		texto: res.stdout ?? "",
	};
}

/** Detiene (3) si el mct resuelto no es la versión del plugin; MCT_BIN explícito la omite. */
function exigirVersionMct(origen) {
	const r = resolverMct(origen);
	if (r.explicito) return;
	const esperada = pluginVersion();
	const c = correrMct(["--version"], origen);
	if (c.code !== 0 || !versionCoincide(c.texto, esperada))
		throw detener({
			razon: "version-mct",
			texto: `El mct disponible no es la versión ${esperada} del plugin. No sigo. Acción: instala master-creator-tools@${esperada} o actualiza el plugin.`,
		});
}

const wsDe = (dest) => join(dest ?? ".", ".mct");

function argsEtapa(etapa, origen, dest, extra = []) {
	if (etapa === "init")
		return ["init", origen, "--dest", dest, "--json", ...extra];
	return [etapa, "--workspace", wsDe(dest), "--json", ...extra];
}

// ---------- PLG-001 doctor ----------

function validarDoctor(d) {
	if (!d || typeof d !== "object" || !Array.isArray(d.checks)) return null;
	const mapa = new Map();
	for (const c of d.checks) {
		if (
			!c ||
			typeof c.id !== "string" ||
			!["ok", "aviso", "falla"].includes(c.estado) ||
			typeof c.mensaje !== "string"
		)
			return null;
		mapa.set(c.id, c);
	}
	for (const id of CHEQUEOS) if (!mapa.has(id)) return null;
	return mapa;
}

export function evaluarDoctor(texto, fase, adaptador, l = "es") {
	const t = TXT[l];
	const mapa = validarDoctor(jsonONulo(texto));
	if (!mapa) throw detener({ razon: "doctor-roto", texto: t.doctorRoto });
	const linea = (c) => (c.accion ? `${c.mensaje} (${c.accion})` : c.mensaje);
	if (fase === "inicial") {
		const fallas = ["gitleaks", "github"]
			.map((i) => mapa.get(i))
			.filter((c) => c.estado === "falla");
		if (fallas.length > 0) {
			const lineas = fallas.map(linea);
			throw detener({
				razon: "doctor-falla",
				fallas: fallas.map((c) => ({
					id: c.id,
					mensaje: c.mensaje,
					accion: c.accion ?? null,
				})),
				lineas,
				texto: `${t.noSigo}${lineas.join(" · ")}.`,
			});
		}
		return { sigue: true, fase };
	}
	if (adaptador === "generico")
		return { sigue: true, fase, dockerOmitido: true };
	const docker = mapa.get("docker");
	const ssh = mapa.get("ssh");
	if (docker.estado === "falla" && ssh.estado !== "ok") {
		throw detener({
			razon: "sin-docker",
			fallas: [
				{
					id: "docker",
					mensaje: docker.mensaje,
					accion: docker.accion ?? null,
				},
			],
			lineas: [linea(docker)],
			texto: t.sinDocker(adaptador),
		});
	}
	return { sigue: true, fase };
}

function cmdDoctor({ op }) {
	const fase = op.fase;
	if (fase !== "inicial" && fase !== "post-init")
		throw invalido("--fase inicial|post-init");
	const adaptador = typeof op.adaptador === "string" ? op.adaptador : null;
	if (fase === "post-init" && !ADAPTADORES.includes(adaptador))
		throw invalido(`--adaptador ${ADAPTADORES.join("|")}`);
	let texto;
	if (op.ejecutar) {
		const dest = requerirDest(op);
		const args = ["doctor", "--json"];
		if (fase === "post-init") args.push("--workspace", wsDe(dest));
		const r = correrMct(args, typeof op.origen === "string" ? op.origen : null);
		texto = r.texto;
	} else texto = leerEntrada(op);
	return evaluarDoctor(texto, fase, adaptador, lang(op));
}

// ---------- PLG-002 proponer-config ----------

export function aliasesSsh(contenido) {
	const out = [];
	for (const raw of contenido.split(/\r?\n/)) {
		const m = /^\s*host\s+(.+?)\s*$/i.exec(raw);
		if (!m) continue;
		for (const tok of m[1].split(/\s+/)) {
			if (/[*?!]/.test(tok) || tok.startsWith("#")) continue;
			if (!out.includes(tok)) out.push(tok);
		}
	}
	return out;
}

function detectar(origen) {
	const builds = [];
	const notas = [];
	const BUILD = new Set([
		"dist",
		"build",
		".next",
		"out",
		"__pycache__",
		".venv",
	]);
	const SALTAR = new Set(["node_modules", ".git", ".mct"]);
	const visitar = (dir, prof) => {
		let ents;
		try {
			ents = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		ents.sort((a, b) => (a.name < b.name ? -1 : 1));
		for (const e of ents) {
			if (e.isDirectory()) {
				if (BUILD.has(e.name)) {
					const g = `${e.name}/`;
					if (!builds.includes(g)) builds.push(g);
					continue;
				}
				if (SALTAR.has(e.name)) continue;
				if (e.name === "notes") {
					if (!notas.includes("notes/")) notas.push("notes/");
					continue;
				}
				if (prof < 4) visitar(join(dir, e.name), prof + 1);
			} else if (e.isFile()) {
				if (/\.notas\.md$/.test(e.name) && !notas.includes("*.notas.md"))
					notas.push("*.notas.md");
				if (/^NOTAS.*/.test(e.name) && !notas.includes("NOTAS*.md"))
					notas.push("NOTAS*.md");
			}
		}
	};
	visitar(origen, 0);
	return { builds, notas };
}

function gitNombre(origen) {
	const r = spawnSync("git", ["config", "user.name"], {
		cwd: origen,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
		windowsHide: true,
	});
	return r.status === 0 ? r.stdout.trim() : "";
}

function proponer(op) {
	const origen = resolve(typeof op.origen === "string" ? op.origen : ".");
	const sshPath =
		typeof op["ssh-config"] === "string"
			? op["ssh-config"]
			: join(homeDir(), ".ssh", "config");
	let aliases = [];
	try {
		aliases = aliasesSsh(readFileSync(sshPath, "utf8"));
	} catch {
		aliases = [];
	}
	const holder =
		typeof op.holder === "string" ? op.holder.trim() : gitNombre(origen);
	let remoto;
	if (typeof op.remoto === "string") {
		if (!aliases.includes(op.remoto))
			throw invalido("verify.remoto debe ser un alias Host de ~/.ssh/config");
		remoto = op.remoto;
	}
	const { builds, notas } = detectar(origen);
	const year = op.year ? Number(op.year) : new Date().getFullYear();
	const propuesta = {
		holder,
		year,
		exclude: [
			"CLAUDE.md",
			"AGENTS.md",
			"masterplan/**",
			".claude/**",
			"decisiones.json",
			...builds,
			...notas,
		],
	};
	if (remoto) propuesta.verify = { remoto };
	return { origen, aliases, holder, propuesta };
}

function cmdProponerConfig({ op }) {
	const l = lang(op);
	const p = proponer(op);
	const ruta = join(p.origen, "mct.config.json");
	if (existsSync(ruta))
		return { existe: true, propuesta: null, archivo: ruta, aliases: p.aliases };
	if (op.no)
		return { escrito: false, sigueSinConfig: true, texto: TXT[l].rechazada };
	if (!p.holder) {
		const cuerpo = {
			requiereHolder: true,
			escrito: false,
			aliases: p.aliases,
			texto: TXT[l].holder,
		};
		if (op.escribir) throw detener(cuerpo);
		return cuerpo;
	}
	if (!op.escribir)
		return {
			existe: false,
			propuesta: p.propuesta,
			aliases: p.aliases,
			archivo: ruta,
		};
	if (!op.si) throw invalido("escribir exige --si explícito de Alexander");
	writeFileSync(ruta, `${JSON.stringify(p.propuesta, null, 2)}\n`);
	return { escrito: true, archivo: ruta, propuesta: p.propuesta };
}

// ---------- PLG-003 revisión ----------

function agrupar(lista, clave) {
	const mapa = new Map();
	for (const h of lista) {
		const k = clave(h);
		if (!mapa.has(k)) mapa.set(k, []);
		mapa.get(k).push(h);
	}
	return [...mapa.values()];
}

export function agruparCandidatos(salida) {
	const cand = salida?.candidatos;
	if (
		!Array.isArray(cand) ||
		typeof salida.sha256 !== "string" ||
		!SHA.test(salida.sha256)
	)
		throw detener({
			razon: "salida-ilegible",
			texto: "La lista de auto-fixtures no es válida.",
		});
	const grupos = agrupar(cand, (c) => `${c.archivo}\u0000${c.regla}`).map(
		(g) => ({
			archivo: g[0].archivo,
			regla: g[0].regla,
			tipo: g[0].tipo,
			cantidad: g.length,
			lineas: g.map((c) => c.linea),
		}),
	);
	return { total: cand.length, sha256: salida.sha256, grupos };
}

const esSensible = (h) => h.tipo === "secreto" || h.severidad === "critico";
const RANGO = { critico: 4, alto: 3, medio: 2, bajo: 1 };

export function extraerAbiertos(salida) {
	const a =
		salida?.hallazgosAbiertos ?? salida?.error?.detalle?.hallazgosAbiertos;
	if (!Array.isArray(a)) return null;
	return a;
}

export function agruparHallazgos(abiertos, dest) {
	const grupos = agrupar(abiertos, (h) => `${h.archivo}\u0000${h.regla}`).map(
		(g) => {
			const sensible = g.some(esSensible);
			const sev = g
				.map((h) => h.severidad)
				.sort((x, y) => (RANGO[y] ?? 0) - (RANGO[x] ?? 0))[0];
			return {
				archivo: g[0].archivo,
				regla: g[0].regla,
				severidad: sev,
				soloReemplazar: sensible,
				hallazgos: g.map((h) => {
					const o = {
						id: h.id,
						linea: h.linea,
						severidad: h.severidad,
						tipo: h.tipo,
					};
					if (typeof h.fragmento === "string") o.fragmento = h.fragmento;
					return o;
				}),
			};
		},
	);
	return {
		total: abiertos.length,
		grupos,
		comandoTerminal: grupos.some((g) => g.soloReemplazar)
			? `mct sanitize --workspace ${wsDe(dest ?? "<dest>")}`
			: null,
	};
}

function obtener(op, argsMct, origen) {
	if (typeof op.entrada === "string")
		return { salida: jsonONulo(readFileSync(op.entrada, "utf8")), code: 0 };
	const r = correrMct(argsMct, origen);
	return { salida: r.salida, code: r.code, falloEjecutar: r.falloEjecutar };
}

function cmdRevision({ pos, op }) {
	const modo = pos[0];
	const dest = typeof op.dest === "string" ? resolve(op.dest) : null;
	const origen = typeof op.origen === "string" ? op.origen : null;
	if (modo === "fixtures") {
		if (!dest && !op.entrada) throw invalido("falta --dest");
		const r = obtener(
			op,
			[
				"sanitize",
				"--workspace",
				wsDe(dest),
				"--json",
				"--auto-fixtures",
				"--dry-run",
			],
			origen,
		);
		if (r.code !== 0 || !r.salida)
			throw detener({
				razon: "mct-fallo",
				texto: mensajeError(r.salida, r.code),
			});
		return agruparCandidatos(r.salida);
	}
	if (modo === "aplicar-fixtures") {
		if (!dest) throw invalido("falta --dest");
		if (typeof op.sha256 !== "string" || !SHA.test(op.sha256))
			throw invalido("--sha256 inválido");
		if (!op.si) throw invalido("aplicar exige --si explícito de Alexander");
		const r = correrMct(
			[
				"sanitize",
				"--workspace",
				wsDe(dest),
				"--json",
				"--auto-fixtures",
				"--confirmo",
				op.sha256,
			],
			origen,
		);
		return finalizar(
			interpretar("sanitize", r.code, r.salida, {
				origen,
				dest,
				l: lang(op),
				falloEjecutar: r.falloEjecutar,
			}),
		);
	}
	if (modo === "hallazgos") {
		if (!dest && !op.entrada) throw invalido("falta --dest");
		const r = obtener(
			op,
			["scan", "--workspace", wsDe(dest), "--json"],
			origen,
		);
		const a = r.salida ? extraerAbiertos(r.salida) : null;
		if (!a) {
			if (r.code === 0 && r.salida)
				return { total: 0, grupos: [], comandoTerminal: null };
			throw detener({
				razon: "mct-fallo",
				texto: mensajeError(r.salida, r.code),
			});
		}
		return agruparHallazgos(a, dest);
	}
	if (modo === "aplicar-decisiones") {
		if (!dest) throw invalido("falta --dest");
		const archivo = join(dest, "decisiones.json");
		if (!existsSync(archivo))
			throw invalido("no hay decisiones.json en el destino");
		const r = correrMct(
			[
				"sanitize",
				"--workspace",
				wsDe(dest),
				"--json",
				"--decisiones",
				archivo,
			],
			origen,
		);
		return finalizar(
			interpretar("sanitize", r.code, r.salida, {
				origen,
				dest,
				l: lang(op),
				falloEjecutar: r.falloEjecutar,
			}),
		);
	}
	throw invalido(
		"revision fixtures|aplicar-fixtures|hallazgos|aplicar-decisiones",
	);
}

function escribirPrivado(ruta, contenido) {
	writeFileSync(ruta, contenido, { mode: 0o600 });
	if (process.platform !== "win32") chmodSync(ruta, 0o600);
}

export function validarRespuestas(lista) {
	if (!Array.isArray(lista))
		throw invalido("las respuestas deben ser una lista");
	return lista.map((r) => {
		if (!r || typeof r.id !== "string" || r.id === "")
			throw invalido("respuesta sin id");
		if (!["falso-positivo", "reemplazar", "aceptar"].includes(r.accion))
			throw invalido(`acción no admitida: ${String(r.accion)}`);
		const o = { id: r.id, accion: r.accion };
		if (r.accion === "falso-positivo") {
			if (
				typeof r.motivo !== "string" ||
				r.motivo.length < 10 ||
				r.motivo.length > 500
			)
				throw invalido(
					"el motivo del falso positivo mide de 10 a 500 caracteres",
				);
			o.motivo = r.motivo;
		}
		if (r.accion === "reemplazar" && r.nombre !== undefined) {
			if (typeof r.nombre !== "string" || !NOMBRE.test(r.nombre))
				throw invalido("nombre de placeholder inválido");
			o.nombre = r.nombre;
		}
		return o;
	});
}

function cmdEscribirDecisiones({ op }) {
	const dest = requerirDest(op);
	const l = lang(op);
	const brutas = jsonONulo(leerEntrada(op, "respuestas"));
	const respuestas = validarRespuestas(
		Array.isArray(brutas) ? brutas : brutas?.decisiones,
	);
	let abiertos;
	if (typeof op.hallazgos === "string")
		abiertos = extraerAbiertos(jsonONulo(readFileSync(op.hallazgos, "utf8")));
	else {
		const r = correrMct(
			["scan", "--workspace", wsDe(dest), "--json"],
			typeof op.origen === "string" ? op.origen : null,
		);
		abiertos = r.salida ? extraerAbiertos(r.salida) : null;
	}
	if (!abiertos)
		throw detener({
			razon: "mct-fallo",
			texto: "No pude leer los hallazgos abiertos de mct scan --json.",
		});
	const porId = new Map(abiertos.map((h) => [h.id, h]));
	const aEscribir = [];
	const derivadas = [];
	for (const r of respuestas) {
		const h = porId.get(r.id);
		if (!h)
			throw invalido(`id desconocido entre los hallazgos abiertos: ${r.id}`);
		if (r.accion === "aceptar") derivadas.push({ id: r.id, razon: "aceptar" });
		else if (r.accion === "falso-positivo" && esSensible(h))
			derivadas.push({
				id: r.id,
				razon: h.tipo === "secreto" ? "secreto" : "critico",
			});
		else aEscribir.push(r);
	}
	const cuerpo = {
		escritas: aEscribir.length,
		derivadas,
		archivo: null,
		terminal: derivadas.length > 0 ? TXT[l].terminal(dest) : null,
	};
	if (aEscribir.length === 0) return cuerpo;
	mkdirSync(dest, { recursive: true });
	const ruta = join(dest, "decisiones.json");
	const previas = new Map();
	if (existsSync(ruta)) {
		const ant = jsonONulo(readFileSync(ruta, "utf8"));
		if (ant && Array.isArray(ant.decisiones))
			for (const d of ant.decisiones) previas.set(d.id, d);
	}
	for (const r of aEscribir) previas.set(r.id, r);
	escribirPrivado(
		ruta,
		`${JSON.stringify({ schemaVersion: 1, decisiones: [...previas.values()] }, null, 2)}\n`,
	);
	cuerpo.archivo = ruta;
	return cuerpo;
}

// ---------- PLG-005 etapas y licencias ----------

function mensajeError(salida, code) {
	const e = salida?.error;
	if (e) return [e.mensaje, e.accion].filter(Boolean).join(" · ");
	return `mct terminó con código ${code} sin una salida JSON legible.`;
}

export function clasificarRevisar(entradas) {
	return entradas.map((e) => {
		const p = String(e.paquete ?? "");
		if (SINTETICAS_SINLOCK.has(p))
			return { tipo: "sinLock", paquete: p, spdx: null };
		if (p.startsWith("(gestor no soportado:"))
			return { tipo: "gestorNoSoportado", paquete: p, spdx: null };
		return {
			tipo: "allow",
			paquete: p,
			version: e.version ?? "",
			spdx: e.spdx ?? null,
		};
	});
}

function interpretar(etapa, code, salida, ctx) {
	const l = ctx.l ?? "es";
	const base = { etapa, codigo: code };
	if (ctx.falloEjecutar)
		return conBase(base, {
			accion: "detener",
			razon: "no-se-pudo-ejecutar-mct",
			mensaje: `No pude ejecutar mct (${ctx.falloEjecutar}).`,
		});
	const err = salida?.error;
	if (code === 0 && salida && !err)
		return conBase(base, { accion: "seguir", salida });
	if (!salida)
		return conBase(base, {
			accion: "detener",
			razon: "salida-ilegible",
			mensaje: mensajeError(null, code),
		});
	if (etapa === "init" && err?.codigo === "VALIDACION") {
		if (err.detalle?.motivo === "deteccion-ambigua")
			return conBase(base, {
				accion: "preguntar-adaptador",
				candidatos: err.detalle.candidatos ?? [],
				comando: `mct init ${ctx.origen} --dest ${ctx.dest} --type <elegido>`,
			});
		const d =
			JSON.stringify(err.detalle ?? {}) +
			(err.mensaje ?? "") +
			(err.accion ?? "");
		if (/force|workspace|clave/i.test(d))
			return conBase(base, {
				accion: "terminal-force",
				comando: `mct init ${ctx.origen} --dest ${ctx.dest} --force`,
				texto: TXT[l].force(ctx.origen, ctx.dest),
			});
	}
	if (
		(etapa === "scan" && code === 10) ||
		(etapa === "sanitize" &&
			err?.codigo === "PUERTA_BLOQUEADA" &&
			Array.isArray(err.detalle?.hallazgosAbiertos))
	)
		return conBase(base, {
			accion: "revision",
			abiertos:
				extraerAbiertos(salida)?.length ?? err?.detalle?.abiertos ?? null,
		});
	if (etapa === "licenses" && code === 10) {
		// LIC-005/LIC-006: mct --json sale 10 con su Salida y la lista pendientes.
		const pend = Array.isArray(salida.pendientes) ? salida.pendientes : null;
		const bloquea = pend?.filter((e) => e.veredicto === "bloquea") ?? [];
		const revisar = pend?.filter((e) => e.veredicto === "revisar") ?? [];
		if (pend === null || bloquea.length > 0 || revisar.length === 0)
			return conBase(base, {
				accion: "detener",
				razon: "licencias",
				mensaje: mensajeError(salida, code),
			});
		return conBase(base, {
			accion: "licencias",
			casos: clasificarRevisar(revisar),
		});
	}
	return conBase(base, {
		accion: "detener",
		razon: "mct-fallo",
		mensaje: mensajeError(salida, code),
		codigoMct: err?.codigo ?? null,
	});
}

function conBase(base, extra) {
	return { ...base, ...extra };
}

function finalizar(res) {
	if (res.accion === "detener") throw new Salida(3, { detener: true, ...res });
	return res;
}

function leerEstado(dest) {
	try {
		const s = JSON.parse(readFileSync(join(wsDe(dest), "state.json"), "utf8"));
		if (
			!s ||
			typeof s !== "object" ||
			typeof s.etapas !== "object" ||
			!s.origen
		)
			return null;
		return s;
	} catch {
		return null;
	}
}

const mismaRuta = (a, b) =>
	process.platform === "win32"
		? resolve(a).toLowerCase() === resolve(b).toLowerCase()
		: resolve(a) === resolve(b);

function cmdEtapas({ pos, op }) {
	const modo = pos[0];
	if (modo === "plan") {
		const origen = resolve(typeof op.origen === "string" ? op.origen : ".");
		const dest =
			typeof op.dest === "string" ? resolve(op.dest) : destinoDe(origen);
		const est = leerEstado(dest);
		const comandos = Object.fromEntries(
			ETAPAS.map((e) => [e, argsEtapa(e, origen, dest)]),
		);
		if (!est?.origen.ref || !mismaRuta(est.origen.ref, origen))
			return {
				dest,
				reanuda: false,
				otroOrigen: Boolean(est),
				desde: "init",
				saltar: [],
				orden: ETAPAS,
				comandos,
			};
		const saltar = [];
		for (const e of ETAPAS) {
			const ok = e === "init" ? true : est.etapas[e]?.estado === "ok";
			if (!ok) break;
			saltar.push(e);
		}
		const desde = ETAPAS[saltar.length] ?? null;
		return {
			dest,
			reanuda: true,
			adaptador: est.adapter ?? null,
			desde,
			saltar,
			orden: ETAPAS,
			comandos,
		};
	}
	if (modo === "ejecutar") {
		const etapa = op.etapa;
		if (!ETAPAS.includes(etapa)) throw invalido(`--etapa ${ETAPAS.join("|")}`);
		const origen = resolve(typeof op.origen === "string" ? op.origen : ".");
		const dest =
			typeof op.dest === "string" ? resolve(op.dest) : destinoDe(origen);
		const extra = [];
		if (etapa === "init" && typeof op.type === "string") {
			if (![...ADAPTADORES, "auto"].includes(op.type))
				throw invalido("--type inválido");
			extra.push("--type", op.type);
		}
		if (etapa === "licenses" && op.offline) extra.push("--offline");
		mkdirSync(dest, { recursive: true });
		exigirVersionMct(origen);
		const r = correrMct(argsEtapa(etapa, origen, dest, extra), origen);
		const res = interpretar(etapa, r.code, r.salida, {
			origen,
			dest,
			l: lang(op),
			falloEjecutar: r.falloEjecutar,
		});
		if (res.accion === "seguir") guardarSalida(dest, etapa, r.salida);
		const salida = { dest, ...res };
		if (res.accion !== "seguir" && res.accion !== "detener") return salida;
		if (res.accion === "detener")
			throw new Salida(3, { detener: true, ...salida });
		return salida;
	}
	if (modo === "interpretar") {
		const etapa = op.etapa;
		if (!ETAPAS.includes(etapa)) throw invalido("--etapa inválida");
		const origen = resolve(typeof op.origen === "string" ? op.origen : ".");
		const dest =
			typeof op.dest === "string" ? resolve(op.dest) : destinoDe(origen);
		const code = Number(op.codigo ?? 0);
		return interpretar(etapa, code, jsonONulo(leerEntrada(op)), {
			origen,
			dest,
			l: lang(op),
		});
	}
	throw invalido("etapas plan|ejecutar|interpretar");
}

function guardarSalida(dest, etapa, salida) {
	const ruta = join(dest, "liberar-salidas.json");
	const previo = existsSync(ruta)
		? (jsonONulo(readFileSync(ruta, "utf8")) ?? {})
		: {};
	previo[etapa] = salida;
	writeFileSync(ruta, `${JSON.stringify(previo, null, 2)}\n`);
}

function cmdOverrideLicencias({ op }) {
	const dest = requerirDest(op);
	const tipo = op.tipo;
	if (!["sinLock", "gestorNoSoportado", "allow"].includes(tipo))
		throw invalido("--tipo sinLock|gestorNoSoportado|allow");
	const motivo = typeof op.motivo === "string" ? op.motivo : "";
	if (motivo.length < 10 || motivo.length > 500)
		throw invalido("el motivo mide de 10 a 500 caracteres");
	const ruta = join(dest, "mct.config.json");
	const actual = existsSync(ruta) ? jsonONulo(readFileSync(ruta, "utf8")) : {};
	if (!actual || typeof actual !== "object" || Array.isArray(actual))
		throw detener({ razon: "config-ilegible", texto: `No pude leer ${ruta}.` });
	const nuevo = structuredClone(actual);
	nuevo.licenses ??= {};
	let cambio;
	if (tipo === "allow") {
		if (typeof op.spdx !== "string" || op.spdx === "")
			throw invalido("falta --spdx");
		const paquetes =
			typeof op.paquetes === "string"
				? op.paquetes
						.split(",")
						.map((s) => s.trim())
						.filter(Boolean)
				: [];
		if (paquetes.length === 0)
			throw invalido("--tipo allow exige --paquetes <nombre[,nombre]>");
		const entrada = { spdx: op.spdx, motivo, paquetes };
		const lista = Array.isArray(nuevo.licenses.allow)
			? nuevo.licenses.allow
			: [];
		const k = (e) => `${e.spdx}|${(e.paquetes ?? []).join(",")}`;
		nuevo.licenses.allow = [
			...lista.filter((e) => k(e) !== k(entrada)),
			entrada,
		];
		cambio = { clave: "licenses.allow", agregar: entrada };
	} else {
		nuevo.licenses[tipo] = { motivo };
		cambio = { clave: `licenses.${tipo}`, valor: { motivo } };
	}
	if (!op.escribir)
		return {
			archivo: ruta,
			existe: existsSync(ruta),
			cambio,
			resultado: nuevo,
			escrito: false,
		};
	if (!op.si) throw invalido("escribir exige --si explícito de Alexander");
	mkdirSync(dest, { recursive: true });
	writeFileSync(ruta, `${JSON.stringify(nuevo, null, 2)}\n`);
	return { archivo: ruta, cambio, escrito: true };
}

// ---------- PLG-004 resumen ----------

function cmdResumen({ op }) {
	const dest = requerirDest(op);
	const l = lang(op);
	const est = leerEstado(dest);
	if (!est)
		throw detener({
			razon: "sin-estado",
			texto: "No hay un state.json válido en el destino.",
		});
	const faltan = ETAPAS.filter(
		(e) => e !== "init" && est.etapas[e]?.estado !== "ok",
	);
	if (faltan.length > 0) return { listo: false, faltan };
	const salidasRuta = join(dest, "liberar-salidas.json");
	const s = existsSync(salidasRuta)
		? (jsonONulo(readFileSync(salidasRuta, "utf8")) ?? {})
		: {};
	const repo = typeof op.repo === "string" ? op.repo : "<owner/nombre>";
	if (typeof op.repo === "string" && !/^[\w.-]+\/[\w.-]+$/.test(op.repo))
		throw invalido("--repo debe ser owner/nombre");
	const lic = s.licenses ?? {};
	const san = s.sanitize ?? {};
	const ver = s.verify ?? {};
	const avisosLic = Array.isArray(lic.avisos) ? lic.avisos : [];
	const modoVerify =
		ver.destino === "(omitido)"
			? "omitido"
			: (ver.avisos ?? []).includes("verify.pipCheck")
				? "compilar"
				: "completo";
	return {
		listo: true,
		repoDestino: repo,
		adaptador: est.adapter ?? null,
		archivosDist: s.package?.archivos ?? null,
		licencias: {
			paquetes: lic.paquetes ?? null,
			overrides: lic.overrides ?? [],
			sinGestor: avisosLic.includes("sin-gestor"),
		},
		verify: {
			destino: ver.destino ?? est.verificado?.destino ?? null,
			modo: modoVerify,
			avisos: ver.avisos ?? [],
		},
		hallazgosResueltos: {
			decididos: san.decididos ?? null,
			porVia: san.porVia ?? null,
		},
		comando: `mct publish --repo ${repo}`,
		texto: TXT[l].publicar(repo),
	};
}

// ---------- destino y despacho ----------

function cmdDestino({ op }) {
	const origen = resolve(typeof op.origen === "string" ? op.origen : ".");
	const dest = destinoDe(origen);
	mkdirSync(dest, { recursive: true });
	return { origen, dest, nombre: basename(origen) };
}

const COMANDOS = {
	destino: cmdDestino,
	doctor: cmdDoctor,
	"proponer-config": cmdProponerConfig,
	revision: cmdRevision,
	"escribir-decisiones": cmdEscribirDecisiones,
	"override-licencias": cmdOverrideLicencias,
	etapas: cmdEtapas,
	resumen: cmdResumen,
};

export function main(argv) {
	const { pos, op } = parseArgs(argv);
	const fn = COMANDOS[pos[0]];
	try {
		if (!fn) throw invalido(`subcomando: ${Object.keys(COMANDOS).join("|")}`);
		const cuerpo = fn({ pos: pos.slice(1), op });
		process.stdout.write(`${JSON.stringify(cuerpo)}\n`);
		return 0;
	} catch (e) {
		if (e instanceof Salida) {
			process.stdout.write(`${JSON.stringify(e.cuerpo)}\n`);
			return e.codigo;
		}
		process.stdout.write(`${JSON.stringify({ error: "interno" })}\n`);
		return 70;
	}
}

if (
	process.argv[1] &&
	resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
	process.exitCode = main(process.argv.slice(2));
}
