import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolverMct, versionCoincide } from "../scripts/liberar.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const PLUGIN = resolve(AQUI, "..");
const SCRIPT = join(PLUGIN, "scripts", "liberar.mjs");

let tmp = "";
beforeEach(() => {
	tmp = mkdtempSync(join(tmpdir(), "liberar-test-"));
});
afterEach(() => {
	rmSync(tmp, { recursive: true, force: true });
});

const fixture = (n: string): string =>
	readFileSync(join(AQUI, "fixtures", n), "utf8");

// biome-ignore lint/suspicious/noExplicitAny: el JSON de salida se inspecciona campo a campo
type Json = Record<string, any>;
type Res = { code: number; json: Json };

function liberar(
	args: string[],
	opts: { input?: string; env?: Record<string, string> } = {},
): Res {
	const r = spawnSync(process.execPath, [SCRIPT, ...args], {
		encoding: "utf8",
		input: opts.input ?? "",
		env: { ...process.env, HOME: tmp, USERPROFILE: tmp, ...opts.env },
	});
	return { code: r.status ?? -1, json: JSON.parse(r.stdout) as Json };
}

function doctor(base: string, cambios: Record<string, Json>): string {
	const d = JSON.parse(base) as { checks: Array<{ id: string }> };
	d.checks = d.checks.map((c) => ({ ...c, ...(cambios[c.id] ?? {}) }));
	return JSON.stringify(d);
}

// mct simulado: responde según un escenario y registra cada llamada.
function mctFalso(
	escenario: Record<string, { code: number; out: unknown }>,
): Record<string, string> {
	const bin = join(tmp, "mct-falso.mjs");
	const log = join(tmp, "llamadas.log");
	const esc = join(tmp, "escenario.json");
	writeFileSync(
		bin,
		[
			'import { appendFileSync, readFileSync } from "node:fs";',
			"const a = process.argv.slice(2);",
			"appendFileSync(process.env.MCT_LOG, JSON.stringify(a) + '\\n');",
			"const e = JSON.parse(readFileSync(process.env.MCT_ESC, 'utf8'));",
			"const r = e[a[0]] ?? { code: 70, out: { error: { codigo: 'INTERNO', mensaje: 'sin escenario' } } };",
			"process.stdout.write(JSON.stringify(r.out));",
			"process.exit(r.code);",
		].join("\n"),
	);
	writeFileSync(esc, JSON.stringify(escenario));
	return { MCT_BIN: bin, MCT_LOG: log, MCT_ESC: esc };
}

const llamadas = (): string[][] => {
	const p = join(tmp, "llamadas.log");
	if (!existsSync(p)) return [];
	return readFileSync(p, "utf8")
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((l) => JSON.parse(l) as string[]);
};

describe("PLG-001 doctor", () => {
	it("PLG-001 todo ok sigue", () => {
		const r = liberar(["doctor", "--fase", "inicial"], {
			input: fixture("doctor-ok.json"),
		});
		expect(r.code).toBe(0);
		expect(r.json.sigue).toBe(true);
	});

	it("PLG-001 falta gitleaks o la credencial de GitHub: una línea por falla con su acción y no sigue", () => {
		const r = liberar(["doctor", "--fase", "inicial"], {
			input: fixture("doctor-falla.json"),
		});
		expect(r.code).toBe(3);
		expect(r.json.sigue).toBeUndefined();
		expect(r.json.lineas).toHaveLength(2);
		expect(r.json.lineas[0]).toContain("mct doctor --install-gitleaks");
		expect(r.json.lineas[1]).toContain("gh auth login");
		expect(r.json.texto).toContain("No sigo");
	});

	it("PLG-001 primera salida sin Docker no detiene; la segunda con verify.remoto ok sigue", () => {
		const sinDocker = doctor(fixture("doctor-ok.json"), {
			docker: { estado: "falla", accion: "Instala Docker" },
		});
		expect(
			liberar(["doctor", "--fase", "inicial"], { input: sinDocker }).code,
		).toBe(0);
		const conRemoto = doctor(sinDocker, {
			ssh: { estado: "ok", mensaje: "alias responde" },
		});
		const r = liberar(
			["doctor", "--fase", "post-init", "--adaptador", "python"],
			{ input: conRemoto },
		);
		expect(r.code).toBe(0);
	});

	it("PLG-001 segunda salida sin Docker con adaptador node se detiene con la acción", () => {
		const sinDocker = doctor(fixture("doctor-ok.json"), {
			docker: { estado: "falla", accion: "Instala Docker" },
		});
		const r = liberar(
			["doctor", "--fase", "post-init", "--adaptador", "node"],
			{
				input: sinDocker,
			},
		);
		expect(r.code).toBe(3);
		expect(r.json.razon).toBe("sin-docker");
		expect(r.json.lineas[0]).toContain("Instala Docker");
	});

	it("PLG-001 sin Docker con adaptador generico sigue", () => {
		const sinDocker = doctor(fixture("doctor-ok.json"), {
			docker: { estado: "falla", accion: "Instala Docker" },
		});
		const r = liberar(
			["doctor", "--fase", "post-init", "--adaptador", "generico"],
			{ input: sinDocker },
		);
		expect(r.code).toBe(0);
	});

	it("PLG-001 JSON roto o sin chequeos en cualquiera de las dos salidas detiene con error", () => {
		for (const fase of ["inicial", "post-init"]) {
			for (const entrada of [
				"{no es json",
				JSON.stringify({ checks: [] }),
				"{}",
			]) {
				const r = liberar(["doctor", "--fase", fase, "--adaptador", "node"], {
					input: entrada,
				});
				expect(r.code).toBe(3);
				expect(r.json.razon).toBe("doctor-roto");
			}
		}
	});
});

describe("PLG-002 proponer-config", () => {
	const gitCon = (nombre: string): Record<string, string> => {
		const g = join(tmp, nombre ? "gitconfig" : "gitconfig-vacio");
		writeFileSync(g, nombre ? `[user]\n\tname = ${nombre}\n` : "");
		return { GIT_CONFIG_GLOBAL: g, GIT_CONFIG_NOSYSTEM: "1" };
	};
	const origen = (): string => {
		const o = join(tmp, "repo");
		mkdirSync(join(o, "dist"), { recursive: true });
		mkdirSync(join(o, "notes"), { recursive: true });
		writeFileSync(join(o, "plan.notas.md"), "x");
		return o;
	};
	const ssh = (): string => {
		const f = join(tmp, "ssh-config");
		writeFileSync(
			f,
			"Host *\n  User x\nHost servidor-uno\n  HostName h1\nHost caja-dos\n",
		);
		return f;
	};

	it("PLG-002 propone holder de git, año, exclude con lo detectado y alias sin comodines", () => {
		const o = origen();
		const r = liberar(
			["proponer-config", "--origen", o, "--ssh-config", ssh()],
			{
				env: gitCon("Titular Prueba"),
			},
		);
		expect(r.code).toBe(0);
		expect(r.json.aliases).toEqual(["servidor-uno", "caja-dos"]);
		const p = r.json.propuesta as Json;
		expect(p.holder).toBe("Titular Prueba");
		expect(p.year).toBe(new Date().getFullYear());
		for (const e of [
			"CLAUDE.md",
			"AGENTS.md",
			"masterplan/**",
			".claude/**",
			"decisiones.json",
			"dist/",
			"notes/",
			"*.notas.md",
		])
			expect(p.exclude).toContain(e);
		expect(p.verify).toBeUndefined();
		expect(existsSync(join(o, "mct.config.json"))).toBe(false);
	});

	it("PLG-002 verify.remoto solo con un alias de ~/.ssh/config", () => {
		const o = origen();
		const env = gitCon("Titular Prueba");
		const bueno = liberar(
			[
				"proponer-config",
				"--origen",
				o,
				"--ssh-config",
				ssh(),
				"--remoto",
				"caja-dos",
			],
			{ env },
		);
		expect(bueno.json.propuesta.verify).toEqual({ remoto: "caja-dos" });
		const malo = liberar(
			[
				"proponer-config",
				"--origen",
				o,
				"--ssh-config",
				ssh(),
				"--remoto",
				"*",
			],
			{ env },
		);
		expect(malo.code).toBe(2);
	});

	it("PLG-002 sin git config user.name pregunta el holder y no escribe hasta la respuesta", () => {
		const o = origen();
		const env = gitCon("");
		const r = liberar(
			[
				"proponer-config",
				"--origen",
				o,
				"--ssh-config",
				ssh(),
				"--escribir",
				"--si",
			],
			{ env },
		);
		expect(r.code).toBe(3);
		expect(r.json.requiereHolder).toBe(true);
		expect(existsSync(join(o, "mct.config.json"))).toBe(false);
		const ok = liberar(
			[
				"proponer-config",
				"--origen",
				o,
				"--ssh-config",
				ssh(),
				"--holder",
				"Otra Persona",
				"--escribir",
				"--si",
			],
			{ env },
		);
		expect(ok.code).toBe(0);
		expect(
			JSON.parse(readFileSync(join(o, "mct.config.json"), "utf8")).holder,
		).toBe("Otra Persona");
	});

	it("PLG-002 escribe solo con sí explícito y la respuesta no no escribe nada", () => {
		const o = origen();
		const env = gitCon("Titular Prueba");
		const base = ["proponer-config", "--origen", o, "--ssh-config", ssh()];
		expect(liberar([...base, "--escribir"], { env }).code).toBe(2);
		const no = liberar([...base, "--no"], { env });
		expect(no.code).toBe(0);
		expect(no.json.escrito).toBe(false);
		expect(existsSync(join(o, "mct.config.json"))).toBe(false);
		const si = liberar([...base, "--escribir", "--si"], { env });
		expect(si.json.escrito).toBe(true);
		expect(existsSync(join(o, "mct.config.json"))).toBe(true);
	});

	it("PLG-002 no pisa un mct.config.json existente", () => {
		const o = origen();
		writeFileSync(join(o, "mct.config.json"), "{}");
		const r = liberar(
			["proponer-config", "--origen", o, "--escribir", "--si"],
			{
				env: gitCon("Titular Prueba"),
			},
		);
		expect(r.json.existe).toBe(true);
		expect(readFileSync(join(o, "mct.config.json"), "utf8")).toBe("{}");
	});
});

describe("PLG-003 revisión", () => {
	const sha = "a".repeat(64);
	const abiertos = [
		{
			id: "h1",
			regla: "pii-email",
			tipo: "pii",
			severidad: "alto",
			archivo: "src/config.py",
			linea: 14,
		},
		{
			id: "h2",
			regla: "pii-email",
			tipo: "pii",
			severidad: "alto",
			archivo: "src/config.py",
			linea: 20,
		},
		{
			id: "h3",
			regla: "generic-token",
			tipo: "secreto",
			severidad: "alto",
			archivo: "src/db.py",
			linea: 3,
			fragmento: "ab12",
		},
		{
			id: "h4",
			regla: "estructura-x",
			tipo: "estructura",
			severidad: "critico",
			archivo: "src/x.py",
			linea: 1,
		},
	];

	it("PLG-003 agrupa los candidatos de auto-fixtures por archivo y regla", () => {
		const f = join(tmp, "dry.json");
		writeFileSync(
			f,
			JSON.stringify({
				candidatos: [
					{
						id: "c1",
						regla: "pii-email",
						tipo: "pii",
						archivo: "tests/fixtures.py",
						linea: 1,
					},
					{
						id: "c2",
						regla: "pii-email",
						tipo: "pii",
						archivo: "tests/fixtures.py",
						linea: 2,
					},
					{
						id: "c3",
						regla: "generic-token",
						tipo: "secreto",
						archivo: "tests/test_api.py",
						linea: 9,
					},
				],
				sha256: sha,
			}),
		);
		const r = liberar(["revision", "fixtures", "--entrada", f]);
		expect(r.json.total).toBe(3);
		expect(r.json.sha256).toBe(sha);
		expect(r.json.grupos).toHaveLength(2);
		expect(r.json.grupos[0]).toMatchObject({
			archivo: "tests/fixtures.py",
			regla: "pii-email",
			cantidad: 2,
		});
	});

	it("PLG-003 aplicar auto-fixtures exige sí y el sha256 con --confirmo", () => {
		const env = mctFalso({ sanitize: { code: 0, out: { abiertos: 0 } } });
		const dest = join(tmp, "dest");
		const sinSi = liberar(
			["revision", "aplicar-fixtures", "--dest", dest, "--sha256", sha],
			{ env },
		);
		expect(sinSi.code).toBe(2);
		const r = liberar(
			["revision", "aplicar-fixtures", "--dest", dest, "--sha256", sha, "--si"],
			{ env },
		);
		expect(r.code).toBe(0);
		const l = llamadas()[0] ?? [];
		expect(l).toContain("--auto-fixtures");
		expect(l[l.indexOf("--confirmo") + 1]).toBe(sha);
	});

	it("PLG-003 agrupa hallazgosAbiertos por archivo y regla y marca los que solo se reemplazan", () => {
		const f = join(tmp, "scan.json");
		writeFileSync(
			f,
			JSON.stringify({
				error: {
					codigo: "PUERTA_BLOQUEADA",
					detalle: { abiertos: 4, hallazgosAbiertos: abiertos },
				},
			}),
		);
		const r = liberar([
			"revision",
			"hallazgos",
			"--entrada",
			f,
			"--dest",
			join(tmp, "d"),
		]);
		expect(r.json.total).toBe(4);
		const g = r.json.grupos as Json[];
		expect(g).toHaveLength(3);
		expect(g[0]).toMatchObject({
			archivo: "src/config.py",
			soloReemplazar: false,
		});
		expect(g[0]?.hallazgos).toHaveLength(2);
		expect(g[1]).toMatchObject({ archivo: "src/db.py", soloReemplazar: true });
		expect(g[1]?.hallazgos[0].fragmento).toBe("ab12");
		expect(g[0]?.hallazgos[0].fragmento).toBeUndefined();
		expect(g[2]?.soloReemplazar).toBe(true);
	});

	const hallazgosArchivo = (): string => {
		const f = join(tmp, "scan.json");
		writeFileSync(f, JSON.stringify({ hallazgosAbiertos: abiertos }));
		return f;
	};

	it("PLG-003 escribe decisiones.json solo con las respuestas dadas, sin revisadoPor ni fragmentos", () => {
		const dest = join(tmp, "dest");
		const respuestas = [
			{
				id: "h1",
				accion: "falso-positivo",
				motivo: "es un correo de ejemplo del manual",
			},
			{ id: "h2", accion: "reemplazar", nombre: "CONTACT_EMAIL" },
			{ id: "h3", accion: "reemplazar" },
		];
		const r = liberar(
			[
				"escribir-decisiones",
				"--dest",
				dest,
				"--hallazgos",
				hallazgosArchivo(),
			],
			{ input: JSON.stringify(respuestas) },
		);
		expect(r.code).toBe(0);
		expect(r.json.escritas).toBe(3);
		const ruta = join(dest, "decisiones.json");
		const texto = readFileSync(ruta, "utf8");
		const obj = JSON.parse(texto) as Json;
		expect(obj.schemaVersion).toBe(1);
		expect(obj.decisiones).toEqual(respuestas);
		expect(texto).not.toContain("revisadoPor");
		expect(texto).not.toContain("ab12");
		if (process.platform !== "win32")
			expect(statSync(ruta).mode & 0o777).toBe(0o600);
	});

	it("PLG-003 falso positivo de secreto o crítico y aceptar no entran al archivo y van a la terminal", () => {
		const dest = join(tmp, "dest");
		const respuestas = [
			{ id: "h3", accion: "falso-positivo", motivo: "es una clave de ejemplo" },
			{ id: "h4", accion: "falso-positivo", motivo: "crítico pero inofensivo" },
			{ id: "h1", accion: "aceptar" },
		];
		const r = liberar(
			[
				"escribir-decisiones",
				"--dest",
				dest,
				"--hallazgos",
				hallazgosArchivo(),
			],
			{ input: JSON.stringify(respuestas) },
		);
		expect(r.code).toBe(0);
		expect(r.json.escritas).toBe(0);
		expect(r.json.derivadas.map((d: { id: string }) => d.id)).toEqual([
			"h3",
			"h4",
			"h1",
		]);
		expect(r.json.terminal).toContain("mct sanitize --workspace");
		expect(existsSync(join(dest, "decisiones.json"))).toBe(false);
	});

	it("PLG-003 rechaza motivos cortos, nombres inválidos e ids desconocidos sin escribir", () => {
		const dest = join(tmp, "dest");
		for (const mala of [
			[{ id: "h1", accion: "falso-positivo", motivo: "corto" }],
			[{ id: "h1", accion: "reemplazar", nombre: "minuscula" }],
			[{ id: "zz", accion: "reemplazar" }],
		]) {
			const r = liberar(
				[
					"escribir-decisiones",
					"--dest",
					dest,
					"--hallazgos",
					hallazgosArchivo(),
				],
				{ input: JSON.stringify(mala) },
			);
			expect(r.code).toBe(2);
		}
		expect(existsSync(join(dest, "decisiones.json"))).toBe(false);
	});
});

describe("PLG-004 resumen", () => {
	const montar = (dest: string, etapas: Record<string, string>): void => {
		mkdirSync(join(dest, ".mct"), { recursive: true });
		const e = Object.fromEntries(
			Object.entries(etapas).map(([k, v]) => [k, { estado: v, ts: "t" }]),
		);
		writeFileSync(
			join(dest, ".mct", "state.json"),
			JSON.stringify({
				origen: { tipo: "carpeta", ref: "/x" },
				adapter: "python",
				etapas: e,
			}),
		);
		writeFileSync(
			join(dest, "liberar-salidas.json"),
			JSON.stringify({
				package: { archivos: 12 },
				licenses: { paquetes: 5, overrides: [], avisos: ["sin-gestor"] },
				sanitize: { porVia: { tty: 0, archivo: 2, autoFixtures: 3 } },
				verify: { destino: "(omitido)", avisos: ["verify.omitido"] },
			}),
		);
	};
	const todas = {
		scan: "ok",
		sanitize: "ok",
		licenses: "ok",
		package: "ok",
		verify: "ok",
	};

	it("PLG-004 con todo en ok muestra el resumen y el comando para que lo corra Alexander", () => {
		const dest = join(tmp, "dest");
		montar(dest, todas);
		const r = liberar(["resumen", "--dest", dest, "--repo", "dueno/nombre"]);
		expect(r.code).toBe(0);
		expect(r.json).toMatchObject({
			listo: true,
			adaptador: "python",
			archivosDist: 12,
			repoDestino: "dueno/nombre",
			comando: "mct publish --repo dueno/nombre",
		});
		expect(r.json.licencias.sinGestor).toBe(true);
		expect(r.json.verify.modo).toBe("omitido");
		expect(r.json.hallazgosResueltos.porVia.autoFixtures).toBe(3);
		expect(r.json.texto).toContain("corre tú en tu terminal");
	});

	it("PLG-004 con una etapa sin ok no está listo", () => {
		const dest = join(tmp, "dest");
		montar(dest, { ...todas, verify: "pendiente" });
		const r = liberar(["resumen", "--dest", dest]);
		expect(r.json).toMatchObject({ listo: false, faltan: ["verify"] });
	});

	it("PLG-010 mct publish solo se invoca desde cmdPublicar, con --confirmo-repo y tras --si", () => {
		const codigo = readFileSync(SCRIPT, "utf8");
		const usos = [...codigo.matchAll(/["'`]publish["'`]/g)];
		expect(usos).toHaveLength(1);
		const funcion = codigo.slice(
			codigo.indexOf("function cmdPublicar"),
			codigo.indexOf("// ---------- PLG-004 resumen"),
		);
		expect(funcion).toContain('"publish"');
		expect(funcion).toContain('"--confirmo-repo"');
		expect(funcion.indexOf("if (!op.si)")).toBeLessThan(
			funcion.indexOf('"publish"'),
		);
		expect(codigo).not.toMatch(/\.stdin\b|input:/);
		expect(codigo).not.toMatch(/--yes/);
	});
});

describe("PLG-010 publicar", () => {
	const dest = (): string => {
		const d = join(tmp, ".mct", "liberar", "mi-repo");
		mkdirSync(d, { recursive: true });
		return d;
	};
	const llamadas = (env: Record<string, string>): string[][] =>
		readFileSync(env.MCT_LOG as string, "utf8")
			.trim()
			.split("\n")
			.map((l) => JSON.parse(l) as string[]);

	it("PLG-010 sin --si no llama a mct", () => {
		const env = mctFalso({});
		writeFileSync(env.MCT_LOG as string, "");
		const r = liberar(
			["publicar", "--dest", dest(), "--repo", "dueno/nombre"],
			{ env },
		);
		expect(r.code).toBe(2);
		expect(readFileSync(env.MCT_LOG as string, "utf8")).toBe("");
	});

	it("PLG-010 con --si corre publish con el mismo repo en --confirmo-repo y --publico", () => {
		const env = mctFalso({
			publish: {
				code: 0,
				out: {
					url: "https://github.com/dueno/nombre",
					visibilidad: "publico",
					tag: "v0.1.0",
				},
			},
		});
		const d = dest();
		const r = liberar(
			["publicar", "--dest", d, "--repo", "dueno/nombre", "--si"],
			{ env },
		);
		expect(r.code).toBe(0);
		expect(r.json).toEqual({
			url: "https://github.com/dueno/nombre",
			visibilidad: "publico",
			tag: "v0.1.0",
		});
		expect(llamadas(env).at(-1)).toEqual([
			"publish",
			"--workspace",
			join(d, ".mct"),
			"--repo",
			"dueno/nombre",
			"--confirmo-repo",
			"dueno/nombre",
			"--publico",
			"--json",
		]);
	});

	it("PLG-010 si publish falla se detiene con el mensaje de mct", () => {
		const env = mctFalso({
			publish: {
				code: 10,
				out: {
					error: {
						codigo: "PUERTA_BLOQUEADA",
						mensaje: "El escaneo remoto encontró algo",
						accion: "Revisa",
					},
				},
			},
		});
		const r = liberar(
			["publicar", "--dest", dest(), "--repo", "dueno/nombre", "--si"],
			{ env },
		);
		expect(r.code).toBe(3);
		expect(r.json.mensaje).toContain("El escaneo remoto encontró algo");
	});

	it("PLG-010 un repo con forma inválida es uso inválido", () => {
		const env = mctFalso({});
		for (const repo of ["sin-barra", "a/../b", "-x/y", "a/b c"]) {
			const r = liberar(
				["publicar", "--dest", dest(), "--repo", repo, "--si"],
				{ env },
			);
			expect(r.code).toBe(2);
		}
	});
});

describe("PLG-005 etapas", () => {
	const origen = (): string => {
		const o = join(tmp, "mi-repo");
		mkdirSync(o, { recursive: true });
		return o;
	};
	const destDe = (): string => join(tmp, ".mct", "liberar", "mi-repo");
	const ok = { code: 0, out: { ok: true } };

	it("PLG-005 el destino es <home>/.mct/liberar/<carpeta del origen>", () => {
		const r = liberar(["destino", "--origen", origen()]);
		expect(r.json.dest).toBe(destDe());
		expect(existsSync(destDe())).toBe(true);
	});

	it("PLG-005 corre igual cuando el plugin se instala por un enlace (junction o symlink)", () => {
		const enlace = join(tmp, "plugins", "liberar");
		mkdirSync(dirname(enlace), { recursive: true });
		symlinkSync(PLUGIN, enlace, "junction");
		const r = spawnSync(
			process.execPath,
			[join(enlace, "scripts", "liberar.mjs"), "destino", "--origen", origen()],
			{
				encoding: "utf8",
				env: { ...process.env, HOME: tmp, USERPROFILE: tmp },
			},
		);
		expect(r.status).toBe(0);
		expect((JSON.parse(r.stdout) as Json).dest).toBe(destDe());
	});

	it("PLG-005 corre las etapas en orden con --json y el destino fijo, sin --force", () => {
		const o = origen();
		const env = mctFalso({
			init: ok,
			scan: ok,
			sanitize: ok,
			licenses: ok,
			package: ok,
			verify: ok,
		});
		for (const etapa of [
			"init",
			"scan",
			"sanitize",
			"licenses",
			"package",
			"verify",
		]) {
			const r = liberar(
				["etapas", "ejecutar", "--etapa", etapa, "--origen", o],
				{ env },
			);
			expect(r.code).toBe(0);
			expect(r.json.accion).toBe("seguir");
		}
		const ll = llamadas();
		expect(ll.map((l) => l[0])).toEqual([
			"init",
			"scan",
			"sanitize",
			"licenses",
			"package",
			"verify",
		]);
		const dest = destDe();
		for (const l of ll) {
			expect(l).toContain("--json");
			expect(l.some((a) => a === dest || a === join(dest, ".mct"))).toBe(true);
			expect(l).not.toContain("--force");
		}
	});

	it("PLG-005 reanuda desde la primera etapa que no está en ok", () => {
		const o = origen();
		const dest = destDe();
		mkdirSync(join(dest, ".mct"), { recursive: true });
		const est = (ref: string): string =>
			JSON.stringify({
				origen: { tipo: "carpeta", ref },
				adapter: "node",
				etapas: {
					scan: { estado: "ok" },
					sanitize: { estado: "ok" },
					licenses: { estado: "pendiente" },
				},
			});
		writeFileSync(join(dest, ".mct", "state.json"), est(o));
		const r = liberar(["etapas", "plan", "--origen", o]);
		expect(r.json).toMatchObject({
			reanuda: true,
			desde: "licenses",
			saltar: ["init", "scan", "sanitize"],
		});
		writeFileSync(join(dest, ".mct", "state.json"), est(join(tmp, "otro")));
		expect(liberar(["etapas", "plan", "--origen", o]).json).toMatchObject({
			reanuda: false,
			desde: "init",
		});
		writeFileSync(join(dest, ".mct", "state.json"), "{roto");
		expect(liberar(["etapas", "plan", "--origen", o]).json.reanuda).toBe(false);
	});

	it("PLG-005 detección ambigua muestra candidatos y se vuelve a correr con --type", () => {
		const o = origen();
		const env = mctFalso({
			init: {
				code: 2,
				out: {
					error: {
						codigo: "VALIDACION",
						mensaje: "ambigua",
						detalle: {
							motivo: "deteccion-ambigua",
							candidatos: [
								{ adapter: "estatico", confianza: 0.4 },
								{ adapter: "node", confianza: 0.3 },
							],
						},
					},
				},
			},
		});
		const r = liberar(
			["etapas", "ejecutar", "--etapa", "init", "--origen", o],
			{ env },
		);
		expect(r.code).toBe(0);
		expect(r.json.accion).toBe("preguntar-adaptador");
		expect(r.json.candidatos).toHaveLength(2);
		liberar(
			[
				"etapas",
				"ejecutar",
				"--etapa",
				"init",
				"--origen",
				o,
				"--type",
				"node",
			],
			{ env },
		);
		const ultima = llamadas().at(-1) ?? [];
		expect(ultima[ultima.indexOf("--type") + 1]).toBe("node");
	});

	it("PLG-005 init que necesita --force se deriva a la terminal sin usarlo", () => {
		const o = origen();
		const env = mctFalso({
			init: {
				code: 2,
				out: {
					error: {
						codigo: "VALIDACION",
						mensaje: "Ya hay un workspace",
						accion: "Usa --force",
						detalle: { motivo: "workspace-existente" },
					},
				},
			},
		});
		const r = liberar(
			["etapas", "ejecutar", "--etapa", "init", "--origen", o],
			{ env },
		);
		expect(r.json.accion).toBe("terminal-force");
		expect(r.json.comando).toContain("--force");
		expect(r.json.texto).toContain("avísame aquí");
		for (const l of llamadas()) expect(l).not.toContain("--force");
	});

	it("PLG-005 scan con 10 y sanitize con PUERTA_BLOQUEADA van a la revisión", () => {
		const o = origen();
		const detalle = {
			abiertos: 1,
			hallazgosAbiertos: [
				{
					id: "h1",
					regla: "r",
					tipo: "pii",
					severidad: "alto",
					archivo: "a",
					linea: 1,
				},
			],
		};
		const bloqueo = {
			code: 10,
			out: { error: { codigo: "PUERTA_BLOQUEADA", mensaje: "m", detalle } },
		};
		const env = mctFalso({ scan: bloqueo, sanitize: bloqueo });
		for (const etapa of ["scan", "sanitize"]) {
			const r = liberar(
				["etapas", "ejecutar", "--etapa", etapa, "--origen", o],
				{ env },
			);
			expect(r.code).toBe(0);
			expect(r.json.accion).toBe("revision");
		}
	});

	it("PLG-005 licenses con 10 clasifica sinLock, gestor no soportado y SPDX dudoso", () => {
		const o = origen();
		const revisar = [
			{
				paquete: "(dependencias transitivas sin lockfile)",
				version: "",
				spdx: null,
				veredicto: "revisar",
			},
			{
				paquete: "(gestor no soportado: go.mod)",
				version: "",
				spdx: null,
				veredicto: "revisar",
			},
			{
				paquete: "libx",
				version: "1.0.0",
				spdx: "LicenseRef-x",
				veredicto: "revisar",
			},
		];
		const env = mctFalso({
			licenses: {
				code: 10,
				out: {
					paquetes: 3,
					bloquea: 0,
					revisar: 3,
					overrides: 0,
					avisos: [],
					pendientes: revisar,
				},
			},
		});
		const r = liberar(
			["etapas", "ejecutar", "--etapa", "licenses", "--origen", o],
			{ env },
		);
		expect(r.json.accion).toBe("licencias");
		expect(r.json.casos.map((c: { tipo: string }) => c.tipo)).toEqual([
			"sinLock",
			"gestorNoSoportado",
			"allow",
		]);
	});

	it("PLG-005 licenses con bloquea detiene mostrando mensaje y acción de mct", () => {
		const o = origen();
		const env = mctFalso({
			licenses: {
				code: 10,
				out: {
					paquetes: 2,
					bloquea: 1,
					revisar: 1,
					overrides: 0,
					avisos: [],
					pendientes: [
						{
							paquete: "p",
							version: "1",
							veredicto: "bloquea",
							override: "allow",
						},
						{
							paquete: "q",
							version: "1",
							veredicto: "revisar",
							override: "allow",
						},
					],
				},
			},
		});
		const r = liberar(
			["etapas", "ejecutar", "--etapa", "licenses", "--origen", o],
			{ env },
		);
		expect(r.code).toBe(3);
		expect(r.json.razon).toBe("licencias");
	});

	it("PLG-005 un código desconocido o una salida ilegible detiene con mensaje y acción de mct", () => {
		const o = origen();
		const env = mctFalso({
			package: {
				code: 11,
				out: {
					error: {
						codigo: "APROBACION_DESACTUALIZADA",
						mensaje: "El árbol cambió",
						accion: "Corre: mct sanitize",
					},
				},
			},
		});
		const r = liberar(
			["etapas", "ejecutar", "--etapa", "package", "--origen", o],
			{ env },
		);
		expect(r.code).toBe(3);
		expect(r.json.accion).toBe("detener");
		expect(r.json.mensaje).toBe("El árbol cambió · Corre: mct sanitize");
		const sin = liberar(
			["etapas", "ejecutar", "--etapa", "verify", "--origen", o],
			{
				env: mctFalso({}),
			},
		);
		expect(sin.code).toBe(3);
	});

	describe("override de licencias", () => {
		const base = (): string => {
			const dest = join(tmp, "dest");
			mkdirSync(dest, { recursive: true });
			writeFileSync(
				join(dest, "mct.config.json"),
				JSON.stringify({ holder: "T", year: 2026, exclude: [] }),
			);
			return dest;
		};
		const motivo = "no hay lockfile y lo acepto";
		const leer = (dest: string): Json =>
			JSON.parse(readFileSync(join(dest, "mct.config.json"), "utf8")) as Json;

		it("PLG-005 muestra el cambio exacto y escribe sinLock solo tras el sí", () => {
			const dest = base();
			const args = [
				"override-licencias",
				"--dest",
				dest,
				"--tipo",
				"sinLock",
				"--motivo",
				motivo,
			];
			const ver = liberar(args);
			expect(ver.json.cambio).toEqual({
				clave: "licenses.sinLock",
				valor: { motivo },
			});
			expect(leer(dest).licenses).toBeUndefined();
			expect(liberar([...args, "--escribir"]).code).toBe(2);
			expect(leer(dest).licenses).toBeUndefined();
			liberar([...args, "--escribir", "--si"]);
			expect(leer(dest).licenses.sinLock).toEqual({ motivo });
			expect(leer(dest).holder).toBe("T");
		});

		it("PLG-005 sin motivo no escribe", () => {
			const dest = base();
			const r = liberar([
				"override-licencias",
				"--dest",
				dest,
				"--tipo",
				"gestorNoSoportado",
				"--escribir",
				"--si",
			]);
			expect(r.code).toBe(2);
			expect(leer(dest).licenses).toBeUndefined();
		});

		it("PLG-005 un SPDX dudoso agrega una entrada licenses.allow con paquetes", () => {
			const dest = base();
			liberar([
				"override-licencias",
				"--dest",
				dest,
				"--tipo",
				"allow",
				"--spdx",
				"LicenseRef-x",
				"--paquetes",
				"libx",
				"--motivo",
				motivo,
				"--escribir",
				"--si",
			]);
			expect(leer(dest).licenses.allow).toEqual([
				{ spdx: "LicenseRef-x", motivo, paquetes: ["libx"] },
			]);
		});
	});
});

describe("PLG-009 readme", () => {
	const contenido = { promesa: "Libera tu repo sin filtrar secretos." };
	const preparar = () => {
		const origen = join(tmp, "mi-repo");
		const dest = join(tmp, ".mct", "liberar", "mi-repo");
		mkdirSync(origen, { recursive: true });
		mkdirSync(dest, { recursive: true });
		writeFileSync(
			join(dest, "mct.config.json"),
			JSON.stringify({ holder: "El Máster IA", licenses: { allow: [] } }),
		);
		return { origen, dest };
	};
	const cfgDe = (dest: string): Json =>
		JSON.parse(readFileSync(join(dest, "mct.config.json"), "utf8")) as Json;

	it("PLG-009 sin --escribir solo muestra lo que agregaría", () => {
		const { origen, dest } = preparar();
		const r = liberar(["readme", "--dest", dest, "--origen", origen], {
			input: JSON.stringify(contenido),
		});
		expect(r.code).toBe(0);
		expect(r.json).toMatchObject({
			escrito: false,
			readme: { plantilla: "el-master-ia", contenido },
		});
		expect(cfgDe(dest).readme).toBeUndefined();
	});

	it("PLG-009 con --escribir --si agrega readme al config del destino sin tocar lo demás", () => {
		const { origen, dest } = preparar();
		const r = liberar(
			["readme", "--dest", dest, "--origen", origen, "--escribir", "--si"],
			{ input: JSON.stringify(contenido) },
		);
		expect(r.code).toBe(0);
		expect(cfgDe(dest)).toEqual({
			holder: "El Máster IA",
			licenses: { allow: [] },
			readme: { plantilla: "el-master-ia", contenido },
		});
		expect(existsSync(join(origen, "mct.config.json"))).toBe(false);
	});

	it("PLG-009 estandar escribe solo la plantilla", () => {
		const { origen, dest } = preparar();
		const r = liberar([
			"readme",
			"--dest",
			dest,
			"--origen",
			origen,
			"--plantilla",
			"estandar",
			"--escribir",
			"--si",
		]);
		expect(r.code).toBe(0);
		expect(cfgDe(dest).readme).toEqual({ plantilla: "estandar" });
	});

	it("PLG-009 escribir sin --si no escribe", () => {
		const { origen, dest } = preparar();
		const r = liberar(
			["readme", "--dest", dest, "--origen", origen, "--escribir"],
			{ input: JSON.stringify(contenido) },
		);
		expect(r.code).toBe(2);
		expect(cfgDe(dest).readme).toBeUndefined();
	});

	it("PLG-009 nunca escribe en el origen ni dentro de él", () => {
		const { origen } = preparar();
		for (const dest of [origen, join(origen, "sub")]) {
			const r = liberar(
				["readme", "--dest", dest, "--origen", origen, "--escribir", "--si"],
				{ input: JSON.stringify(contenido) },
			);
			expect(r.code).toBe(2);
		}
		expect(existsSync(join(origen, "mct.config.json"))).toBe(false);
		expect(existsSync(join(origen, "sub"))).toBe(false);
	});

	it("PLG-009 sin --origen o con contenido que no es objeto falla", () => {
		const { origen, dest } = preparar();
		expect(liberar(["readme", "--dest", dest], { input: "{}" }).code).toBe(2);
		expect(
			liberar(["readme", "--dest", dest, "--origen", origen], { input: "[1]" })
				.code,
		).toBe(2);
	});

	it("PLG-009 un destino que es un enlace al origen se rechaza", () => {
		const { origen } = preparar();
		const enlace = join(tmp, "enlace-al-origen");
		symlinkSync(origen, enlace, "junction");
		const r = liberar(
			["readme", "--dest", enlace, "--origen", origen, "--escribir", "--si"],
			{ input: JSON.stringify(contenido) },
		);
		expect(r.code).toBe(2);
		expect(existsSync(join(origen, "mct.config.json"))).toBe(false);
	});

	it("PLG-009 un mct.config.json que es un enlace detiene sin escribir", () => {
		const { origen, dest } = preparar();
		const real = join(tmp, "otro.json");
		writeFileSync(real, "{}");
		rmSync(join(dest, "mct.config.json"));
		try {
			symlinkSync(real, join(dest, "mct.config.json"));
		} catch {
			return; // sin permiso de symlink en esta máquina
		}
		const r = liberar(
			["readme", "--dest", dest, "--origen", origen, "--escribir", "--si"],
			{ input: JSON.stringify(contenido) },
		);
		expect(r.code).toBe(3);
		expect(readFileSync(real, "utf8")).toBe("{}");
	});
});

describe("PLG-006 seguridad del plugin", () => {
	const md = (): string =>
		readFileSync(join(PLUGIN, "commands", "liberar.md"), "utf8");

	it("PLG-006 el frontmatter no preaprueba herramientas y el guion prohíbe .mct y comandos ajenos", () => {
		const fm = /^---\n([\s\S]*?)\n---/.exec(md())?.[1] ?? "";
		expect(fm).toContain("description:");
		expect(fm).not.toMatch(/allowed-tools/);
		expect(fm).not.toMatch(/Read|Bash/);
		expect(md()).toMatch(/NUNCA leas ni edites nada bajo `<dest>\/\.mct\/`/);
		expect(md()).toMatch(/fuera de `liberar\.mjs`/);
	});

	it("PLG-007 un node_modules/.bin/mct del origen ajeno no se usa, aunque se llame master-creator-tools", () => {
		const prev = process.env.MCT_BIN;
		process.env.MCT_BIN = "";
		try {
			const o = join(tmp, "ajeno");
			const bin = join(o, "node_modules", ".bin");
			mkdirSync(bin, { recursive: true });
			writeFileSync(join(bin, "mct"), "");
			writeFileSync(join(bin, "mct.cmd"), "");
			writeFileSync(join(o, "package.json"), '{"name":"otro"}');
			const r = resolverMct(o);
			expect(r.pre.join(" ")).toMatch(/^-p master-creator-tools@\d/);
			expect(r.cmd).not.toContain("node_modules");
			writeFileSync(join(o, "package.json"), '{"name":"master-creator-tools"}');
			expect(resolverMct(o).cmd).not.toContain("node_modules");
		} finally {
			if (prev === undefined) delete process.env.MCT_BIN;
			else process.env.MCT_BIN = prev;
		}
	});

	it("PLG-007 MCT_BIN explícito se respeta y la versión distinta no coincide", () => {
		const prev = process.env.MCT_BIN;
		process.env.MCT_BIN = "/x/mct";
		try {
			expect(resolverMct(tmp).explicito).toBe(true);
		} finally {
			if (prev === undefined) delete process.env.MCT_BIN;
			else process.env.MCT_BIN = prev;
		}
		expect(versionCoincide("0.2.0\n", "0.2.0")).toBe(true);
		expect(versionCoincide("mct 0.1.9", "0.2.0")).toBe(false);
		expect(versionCoincide("", "0.2.0")).toBe(false);
	});

	it("PLG-008 override-licencias allow sin --paquetes sale 2 y no escribe", () => {
		const r = liberar([
			"override-licencias",
			"--dest",
			tmp,
			"--tipo",
			"allow",
			"--spdx",
			"LicenseRef-x",
			"--motivo",
			"motivo suficientemente largo",
			"--escribir",
			"--si",
		]);
		expect(r.code).toBe(2);
		expect(existsSync(join(tmp, "mct.config.json"))).toBe(false);
	});
});

describe("plugin formato", () => {
	it("el manifiesto declara name liberar y versión 0.3.0", () => {
		const m = JSON.parse(
			readFileSync(join(PLUGIN, ".claude-plugin", "plugin.json"), "utf8"),
		) as Json;
		expect(m).toMatchObject({ name: "liberar", version: "0.3.0" });
		expect(typeof m.description).toBe("string");
	});

	it("nada del entorno de Alexander está hardcodeado en plugin/", () => {
		const archivos = [
			SCRIPT,
			join(PLUGIN, "commands", "liberar.md"),
			join(PLUGIN, "README.md"),
		];
		for (const f of archivos) {
			const t = readFileSync(f, "utf8");
			expect(t).not.toMatch(/servidor-casa|AlexanderKast|Kreoon|avata/i);
		}
	});
});
