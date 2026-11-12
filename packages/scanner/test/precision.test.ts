import { createHash } from "node:crypto";
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Runner } from "../src/gitleaks.js";
import { type ScanOptions, scan as scanConClave } from "../src/scan.js";
import { CLAVE_PRUEBA } from "./clave.js";

const scan = (options: ScanOptions) =>
	scanConClave({ clave: CLAVE_PRUEBA, ...options });

import { buildFixture, FIXTURE_NAMES } from "./fixtures/build.js";

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

function seededLines(text: string, needles: readonly string[]): Set<number> {
	const out = new Set<number>();
	text.split("\n").forEach((l, i) => {
		if (needles.some((n) => l.includes(n))) out.add(i + 1);
	});
	return out;
}

describe("precisión del escaneo", () => {
	for (const name of FIXTURE_NAMES) {
		it(`SCAN-002 los falsos positivos son 5% o menos en ${name}`, async () => {
			const fx = await buildFixture(name);
			cleanups.push(() => fx.cleanup());
			const dirs = await tmpDirs();
			const values = [
				...fx.truth.secrets.map((s) =>
					s.mutation === "split-lines" ? s.value.slice(0, 8) : s.value,
				),
				...fx.truth.pii.map((p) => p.value),
			];
			const { hallazgos } = await scan({
				work: fx.work,
				quarantine: fx.quarantine,
				gitleaks: {
					binary: process.execPath,
					...dirs,
					run: fakeGitleaks(fx.truth.secrets.map((s) => s.value)),
				},
			});
			expect(hallazgos.length).toBeGreaterThan(0);
			let falsos = 0;
			for (const f of hallazgos) {
				const root = f.zona === "work" ? fx.work : fx.quarantine;
				const text = await readFile(join(root, f.archivo), "utf8");
				const lines = seededLines(text, values);
				if (!lines.has(f.linea) && !lines.has(f.linea - 1)) falsos++;
			}
			expect(falsos / hallazgos.length).toBeLessThanOrEqual(0.05);
		});
	}

	it("SCAN-002 huellas, UUID y SHA de git no se reportan", async () => {
		const base = await mkdtemp(join(tmpdir(), "mct-prec-"));
		cleanups.push(() => rm(base, { recursive: true, force: true }));
		const work = join(base, "work");
		await mkdir(work, { recursive: true });
		const sha1 = createHash("sha1").update("mct").digest("hex");
		const integrity = [
			"sha",
			"512-",
			createHash("sha512").update("mct").digest("base64"),
		].join("");
		const uuid = [
			sha1.slice(0, 8),
			sha1.slice(8, 12),
			"4" + sha1.slice(13, 16),
			"8" + sha1.slice(17, 20),
			sha1.slice(20, 32),
		].join("-");
		await writeFile(
			join(work, "lock.txt"),
			[
				`integrity ${integrity}`,
				`commit ${sha1}`,
				`id ${uuid}`,
				"const total = items.length;",
			].join("\n") + "\n",
		);
		const dirs = await tmpDirs();
		const { hallazgos } = await scan({
			work,
			quarantine: join(base, "quarantine"),
			gitleaks: { binary: process.execPath, ...dirs, run: fakeGitleaks([]) },
		});
		expect(hallazgos).toEqual([]);
	});
});
