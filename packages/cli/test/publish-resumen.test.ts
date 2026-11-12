import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GithubClient } from "@mct/core/github";
import {
	leerResumenPublish,
	type PublishOptions,
	type PublishResult,
	type PublishResumen,
} from "@mct/core/publish";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { renderReport } from "../../templates/src/report.js";
import {
	overridePublishDeps,
	type PublishPrompter,
	register,
} from "../src/commands/publish.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

const REPO = "AlexanderKast/mi-flujo";

let restore: () => void;
let order: string[];

function makeIo(lang: string): Io {
	return {
		out: (t) => {
			order.push(`out:${t}`);
		},
		err: (t) => {
			order.push(`err:${t}`);
		},
		env: { LANG: lang },
		stdinIsTTY: true,
		stderrIsTTY: false,
	};
}

const prompter: PublishPrompter = {
	text: async () => {
		order.push("prompt:nombre");
		return null; // the person cancels: the summary was already shown
	},
	confirm: async (o) => o.initialValue,
};

function useDeps(resumen: PublishResumen): void {
	restore = overridePublishDeps({
		prompter,
		createClient: async () => ({}) as GithubClient,
		publish: async (o: PublishOptions): Promise<PublishResult> => ({
			url: `https://github.com/${o.repo}`,
			visibilidad: "privado",
			tag: "v0.1.0",
			dryRun: true,
		}),
		resumen: async () => resumen,
	});
}

const vacio: PublishResumen = {
	adaptador: "generico",
	porArchivo: [],
	porAutoFixtures: [],
	avisos: [],
	overrides: [],
};

beforeEach(() => {
	order = [];
	restore = () => {};
});
afterEach(() => {
	restore();
});

function textoAntesDelPrompt(): string {
	const i = order.indexOf("prompt:nombre");
	expect(i).toBeGreaterThan(-1);
	return order.slice(0, i).join("\n");
}

async function correr(lang: string): Promise<void> {
	await runCli(["publish", "--repo", REPO], makeIo(lang), [register]);
}

describe("PUB-013 resumen antes del nombre", () => {
	it("PUB-013 CUANDO verify fue omitido EL SISTEMA DEBE mostrar el aviso antes de pedir el nombre del repo", async () => {
		useDeps({ ...vacio, avisos: ["verify.omitido"] });
		await correr("es_CO.UTF-8");
		const antes = textoAntesDelPrompt();
		expect(antes).toContain("no se probó en un contenedor");
		expect(antes).toContain("Adaptador: generico");
	});

	it("PUB-013 EN: los avisos se muestran en inglés antes del nombre", async () => {
		useDeps({ ...vacio, avisos: ["verify.omitido", "licenses.sinGestor"] });
		await correr("en_US.UTF-8");
		const antes = textoAntesDelPrompt();
		expect(antes).toContain("was not tested in a container");
		expect(antes).toContain("no recognized dependency manager");
	});

	it("PUB-013 EL SISTEMA DEBE mostrar los conteos por archivo y por auto-fixtures con regla y ruta", async () => {
		useDeps({
			...vacio,
			porArchivo: [{ regla: "pii-email", archivo: "src/config.py" }],
			porAutoFixtures: [
				{ regla: "generic-token", archivo: "tests/test_api.py" },
				{ regla: "pii-email", archivo: "tests/fixtures.py" },
			],
		});
		await correr("es_CO.UTF-8");
		const antes = textoAntesDelPrompt();
		expect(antes).toContain(
			"1 hallazgos resueltos por archivo · 2 por auto-fixtures",
		);
		expect(antes).toContain("pii-email · src/config.py");
		expect(antes).toContain("generic-token · tests/test_api.py");
	});

	it("PUB-013 EL SISTEMA DEBE mostrar los overrides aceptados con su motivo", async () => {
		useDeps({
			...vacio,
			overrides: [
				{ clave: "licenses.sinLock", motivo: "no hay lock en el origen" },
			],
		});
		await correr("es_CO.UTF-8");
		expect(textoAntesDelPrompt()).toContain(
			"licenses.sinLock. Motivo: no hay lock en el origen",
		);
	});

	it("PUB-013 EL SISTEMA DEBE quitar caracteres de control de las rutas antes de imprimirlas", async () => {
		const esc = String.fromCharCode(27);
		useDeps({
			...vacio,
			porArchivo: [{ regla: "pii-email", archivo: `a${esc}[31mb.py` }],
		});
		await correr("es_CO.UTF-8");
		expect(textoAntesDelPrompt()).not.toContain(esc);
	});
});

describe("PUB-013 lectura del workspace", () => {
	let dir = "";
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "mct-resumen-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("PUB-013 lee via de findings.json, avisos y overrides del config", async () => {
		const raiz = join(dir, ".mct");
		await mkdir(raiz);
		await writeFile(
			join(raiz, "state.json"),
			JSON.stringify({
				adapter: "generico",
				verificado: { distSha256: "x", destino: "(omitido)", ts: "t" },
			}),
		);
		await writeFile(
			join(raiz, "findings.json"),
			JSON.stringify({
				hallazgos: [
					{ regla: "r1", archivo: "a.txt", estado: "resuelto", via: "archivo" },
					{
						regla: "r2",
						archivo: "t/b.txt",
						estado: "falso-positivo",
						via: "auto-fixtures",
					},
					{ regla: "r3", archivo: "c.txt", estado: "abierto", via: "archivo" },
					{ regla: "r4", archivo: "d.txt", estado: "resuelto" },
				],
			}),
		);
		await writeFile(
			join(raiz, "license-avisos.json"),
			JSON.stringify({ schemaVersion: 1, avisos: ["sin-gestor"] }),
		);
		await writeFile(
			join(dir, "mct.config.json"),
			JSON.stringify({
				verify: { modo: "compilar", motivo: "sin entorno para arrancar" },
			}),
		);
		const r = await leerResumenPublish(raiz);
		expect(r.adaptador).toBe("generico");
		expect(r.porArchivo).toEqual([{ regla: "r1", archivo: "a.txt" }]);
		expect(r.porAutoFixtures).toEqual([{ regla: "r2", archivo: "t/b.txt" }]);
		expect(r.avisos).toEqual(["verify.omitido", "licenses.sinGestor"]);
		expect(r.overrides).toEqual([
			{ clave: "verify.modo: compilar", motivo: "sin entorno para arrancar" },
		]);
	});

	it("PUB-013 sin archivos opcionales devuelve un resumen vacío sin fallar", async () => {
		const r = await leerResumenPublish(join(dir, ".mct"));
		expect(r.porArchivo).toEqual([]);
		expect(r.avisos).toEqual([]);
	});
});

describe("VER-007 y LIC-006 en report.html", () => {
	const base = {
		lang: "es" as const,
		generadoEn: "2026-11-11T10:00:00.000Z",
		puertas: [],
		hallazgos: [],
		licencias: [],
	};

	it("VER-007 el reporte muestra verify.omitido como encabezado nivel 3 antes de los filtros", () => {
		const html = renderReport({
			...base,
			avisos: ["verify.omitido", "licenses.sinGestor"],
		});
		const i = html.indexOf("no se probó en un contenedor");
		expect(i).toBeGreaterThan(-1);
		expect(html.lastIndexOf("<h3", i)).toBeGreaterThan(
			html.indexOf('id="h-puertas"'),
		);
		expect(i).toBeLessThan(html.indexOf('class="nav-filtros"'));
		expect(html.indexOf("no se probó")).toBeLessThan(
			html.indexOf("Sin gestor de dependencias"),
		);
	});

	it("LIC-006 el reporte en inglés trae el aviso de licencias y sigue sin JavaScript", () => {
		const html = renderReport({
			...base,
			lang: "en",
			avisos: ["licenses.sinGestor"],
		});
		expect(html).toContain("No recognized dependency manager");
		expect(html).not.toContain("<script");
	});

	it("VER-007 sin avisos el reporte no trae encabezados de aviso", () => {
		expect(renderReport(base)).not.toContain('class="aviso"');
	});
});
