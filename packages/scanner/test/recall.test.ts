import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@mct/contract/types";
import { afterEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/gitleaks.js";
import { scan } from "../src/scan.js";
import {
	buildFixture,
	FIXTURE_NAMES,
	type TruthSecret,
} from "./fixtures/build.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const c of cleanups.splice(0)) await c();
});

/** gitleaks falso: reporta cada ocurrencia literal de las agujas, con --redact. */
function fakeGitleaks(needles: readonly string[]): Runner {
	return async (_cmd, args) => {
		if (args.includes("version")) {
			return { code: 0, signal: null, stdout: "8.30.1\n", timedOut: false };
		}
		const target = args[args.indexOf("dir") + 1] as string;
		const reportPath = args[args.indexOf("--report-path") + 1] as string;
		const out: unknown[] = [];
		const entries = await readdir(target, {
			recursive: true,
			withFileTypes: true,
		});
		for (const e of entries) {
			if (!e.isFile()) continue;
			const file = join(e.parentPath, e.name);
			const lines = (await readFile(file, "utf8")).split("\n");
			lines.forEach((line, i) => {
				for (const n of needles) {
					const at = line.indexOf(n);
					if (at >= 0) {
						// Semántica real de gitleaks 8.30.1 (detect/location.go): columnas
						// en bytes, base 1, y +1 de desfase fuera de la primera línea.
						const shift = i > 0 ? 1 : 0;
						const start = Buffer.byteLength(line.slice(0, at));
						out.push({
							RuleID: "generic-api-key",
							File: file,
							StartLine: i + 1,
							EndLine: i + 1,
							StartColumn: start + 1 + shift,
							EndColumn: start + Buffer.byteLength(n) + shift,
						});
					}
				}
			});
		}
		await writeFile(reportPath, JSON.stringify(out));
		return {
			code: out.length > 0 ? 2 : 0,
			signal: null,
			stdout: "",
			timedOut: false,
		};
	};
}

async function tmpDirs(): Promise<{ tmpDir: string; installDir: string }> {
	const base = await mkdtemp(join(tmpdir(), "mct-scan-"));
	cleanups.push(() => rm(base, { recursive: true, force: true }));
	await mkdir(join(base, "tmp"), { recursive: true });
	return { tmpDir: join(base, "tmp"), installDir: join(base, "bin") };
}

function probe(s: TruthSecret): string {
	return s.mutation === "split-lines" ? s.value.slice(0, 8) : s.value;
}

interface Spot {
	readonly line: number;
	/** Columna base 1 del inicio de la sonda en esa línea. */
	readonly column: number;
}

async function spotsOf(
	root: string,
	file: string,
	needle: string,
): Promise<Spot[]> {
	const text = await readFile(join(root, file), "utf8");
	const out: Spot[] = [];
	text.split("\n").forEach((l, i) => {
		let at = l.indexOf(needle);
		while (at >= 0) {
			out.push({ line: i + 1, column: at + 1 });
			at = l.indexOf(needle, at + 1);
		}
	});
	return out;
}

/**
 * Cada secreto sembrado exige un hallazgo PROPIO: en su línea (o la siguiente si
 * está partido) y, o bien con la columna dentro de la sonda, o bien con el
 * prefijo del fragmento igual al de la sonda. Un hallazgo no cubre a dos secretos.
 */
function covers(
	hallazgos: readonly Finding[],
	used: Set<string>,
	zona: string,
	file: string,
	spots: readonly Spot[],
	probeValue: string,
): boolean {
	const prefix = probeValue.slice(0, 4);
	const hit = hallazgos.find(
		(f) =>
			!used.has(f.id) &&
			f.tipo === "secreto" &&
			f.zona === zona &&
			f.archivo === file &&
			spots.some(
				(s) =>
					(f.linea === s.line &&
						f.columna >= s.column &&
						f.columna < s.column + probeValue.length) ||
					((f.linea === s.line || f.linea === s.line + 1) &&
						f.fragmento.startsWith(prefix)),
			),
	);
	if (hit === undefined) return false;
	used.add(hit.id);
	return true;
}

describe("recall del escaneo", () => {
	for (const name of FIXTURE_NAMES) {
		it(`SCAN-001 reporta el 100% de los secretos de truth.json en ${name}`, async () => {
			const fx = await buildFixture(name);
			cleanups.push(() => fx.cleanup());
			const dirs = await tmpDirs();
			const { hallazgos } = await scan({
				work: fx.work,
				quarantine: fx.quarantine,
				gitleaks: {
					binary: process.execPath,
					...dirs,
					run: fakeGitleaks(fx.truth.secrets.map((s) => s.value)),
				},
			});
			expect(fx.truth.secrets.length).toBeGreaterThan(0);
			let found = 0;
			const used = new Set<string>();
			for (const s of fx.truth.secrets) {
				const zona = s.mutation === "env-backup" ? "quarantine" : "work";
				const root = zona === "work" ? fx.work : fx.quarantine;
				const spots = await spotsOf(root, s.file, probe(s));
				expect(spots.length).toBeGreaterThan(0);
				if (covers(hallazgos, used, zona, s.file, spots, probe(s))) found++;
			}
			expect(found / fx.truth.secrets.length).toBe(1);
		});

		it(`SCAN-001 el motor propio por sí solo cubre cada secreto de ${name}`, async () => {
			const fx = await buildFixture(name);
			cleanups.push(() => fx.cleanup());
			const dirs = await tmpDirs();
			const { hallazgos } = await scan({
				work: fx.work,
				quarantine: fx.quarantine,
				gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
			});
			const own = hallazgos.filter((f) => f.motor === "mct");
			const used = new Set<string>();
			for (const s of fx.truth.secrets) {
				const zona = s.mutation === "env-backup" ? "quarantine" : "work";
				const root = zona === "work" ? fx.work : fx.quarantine;
				const spots = await spotsOf(root, s.file, probe(s));
				expect(covers(own, used, zona, s.file, spots, probe(s))).toBe(true);
			}
		});
	}

	it("SCAN-001 sin gitleaks utilizable no devuelve resultados", async () => {
		const fx = await buildFixture("node");
		cleanups.push(() => fx.cleanup());
		const dirs = await tmpDirs();
		const run: Runner = async () => ({
			code: null,
			signal: null,
			stdout: "",
			timedOut: false,
			error: Object.assign(new Error("x"), { code: "ENOENT" }),
		});
		await expect(
			scan({
				work: fx.work,
				quarantine: fx.quarantine,
				gitleaks: { binary: process.execPath, ...dirs, run },
			}),
		).rejects.toMatchObject({ codigo: "MOTOR_NO_DISPONIBLE" });
		expect(dirname(dirs.tmpDir)).toBeTruthy();
	});
});
