import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, describe, expect, it } from "vitest";
import {
	detectDictionary,
	loadDictionary,
	MAX_DICT_BYTES,
	MAX_DICT_TERMS,
	parseDictionary,
} from "../src/dictionary.js";

// Terms are assembled from fragments so no literal term sits in this file.
const T0 = ["ac", "me", "-", "cli", "ent"].join("");
const T1 = ["pro", "yecto", ".", "x"].join("");
const T2 = ["(a", "+", ")", "+", "$"].join("");

const dirs: string[] = [];
async function tmp(): Promise<string> {
	const d = await mkdtemp(join(tmpdir(), "mct-dic-"));
	dirs.push(d);
	return d;
}
afterEach(async () => {
	for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
});

describe("parseDictionary", () => {
	it("SCAN-005 ignores comments, blank lines, CRLF and BOM", () => {
		const text = `﻿# comment\r\n\r\n${T0}\r\n  ${T1}  \r\n# ${T2}\r\n`;
		expect(parseDictionary(text)).toEqual([T0, T1]);
	});

	it("SCAN-005 returns zero terms for empty or comment-only content", () => {
		expect(parseDictionary("# only\n\n")).toEqual([]);
		expect(parseDictionary("")).toEqual([]);
	});

	it("SCAN-005 fails closed over the term limit", () => {
		const many = Array.from({ length: MAX_DICT_TERMS + 1 }, (_, i) => `t${i}`);
		expect(() => parseDictionary(many.join("\n"))).toThrow(MctError);
	});
});

describe("loadDictionary", () => {
	it("SCAN-005 returns zero terms when the file does not exist", async () => {
		const d = await tmp();
		await expect(loadDictionary(join(d, "nope.txt"))).resolves.toEqual([]);
	});

	it("SCAN-005 reads terms from the file", async () => {
		const d = await tmp();
		const f = join(d, "sensible.txt");
		await writeFile(f, `# c\n${T0}\n`);
		await expect(loadDictionary(f)).resolves.toEqual([T0]);
	});

	it("SCAN-005 fails closed when the path is unreadable", async () => {
		const d = await tmp();
		const dir = join(d, "adir");
		await mkdir(dir);
		await expect(loadDictionary(dir)).rejects.toBeInstanceOf(MctError);
	});

	it("SCAN-005 fails closed over the size limit", async () => {
		const d = await tmp();
		const f = join(d, "big.txt");
		await writeFile(f, "a".repeat(MAX_DICT_BYTES + 1));
		await expect(loadDictionary(f)).rejects.toBeInstanceOf(MctError);
	});

	it("SCAN-005 returns zero terms for an empty or comment-only file", async () => {
		const d = await tmp();
		const f = join(d, "empty.txt");
		await writeFile(f, "");
		await expect(loadDictionary(f)).resolves.toEqual([]);
		const g = join(d, "comments.txt");
		await writeFile(g, "# only\n# comments\n");
		await expect(loadDictionary(g)).resolves.toEqual([]);
	});

	it("SCAN-005 decodes UTF-16LE with BOM and detects the term", async () => {
		const d = await tmp();
		const f = join(d, "u16le.txt");
		const body = Buffer.from(`# c\r\n${T0}\r\n`, "utf16le");
		await writeFile(f, Buffer.concat([Buffer.from([0xff, 0xfe]), body]));
		const terms = await loadDictionary(f);
		expect(terms).toEqual([T0]);
		expect(detectDictionary(`x ${T0} y`, terms)).toHaveLength(1);
	});

	it("SCAN-005 decodes UTF-16BE with BOM", async () => {
		const d = await tmp();
		const f = join(d, "u16be.txt");
		const be = Buffer.from(`${T0}\n`, "utf16le").swap16();
		await writeFile(f, Buffer.concat([Buffer.from([0xfe, 0xff]), be]));
		await expect(loadDictionary(f)).resolves.toEqual([T0]);
	});

	it("SCAN-005 fails closed on invalid bytes without leaking the term", async () => {
		const d = await tmp();
		const f = join(d, "latin1.txt");
		await writeFile(
			f,
			Buffer.concat([Buffer.from(`${T0}-caf`), Buffer.from([0xe9, 0x0a])]),
		);
		const err = await loadDictionary(f).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("VALIDACION");
		expect((err as MctError).message).not.toContain(T0);
	});

	it("SCAN-005 fails closed on NUL and U+FFFD", async () => {
		const d = await tmp();
		const a = join(d, "nul.txt");
		await writeFile(a, Buffer.from(`${T0}\u0000\n`));
		await expect(loadDictionary(a)).rejects.toBeInstanceOf(MctError);
		const b = join(d, "fffd.txt");
		await writeFile(b, Buffer.from(`${T0}\uFFFD\n`));
		await expect(loadDictionary(b)).rejects.toBeInstanceOf(MctError);
	});
});

describe("detectDictionary", () => {
	it("SCAN-005 returns dict-match with index and without the term", () => {
		const text = `line one\nsee ${T1} here\nand ${T0}\n`;
		const hits = detectDictionary(text, [T0, T1]);
		expect(hits).toHaveLength(2);
		const a = hits.find((h) => h.fragmento === "[dic:1]");
		const b = hits.find((h) => h.fragmento === "[dic:0]");
		expect(a).toMatchObject({ regla: "dict-match", linea: 2, columna: 5 });
		expect(b).toMatchObject({ regla: "dict-match", linea: 3, columna: 5 });
		const dump = JSON.stringify(hits);
		expect(dump).not.toContain(T0);
		expect(dump).not.toContain(T1);
	});

	it("SCAN-005 matches case-insensitively and reports offsets", () => {
		const hits = detectDictionary(`x ${T0.toUpperCase()} y`, [T0]);
		expect(hits).toHaveLength(1);
		expect(hits[0]).toMatchObject({ inicio: 2, fin: 2 + T0.length });
	});

	it("SCAN-005 reports every occurrence", () => {
		const hits = detectDictionary(`${T0} ${T0}\n${T0}`, [T0]);
		expect(hits.map((h) => [h.linea, h.columna])).toEqual([
			[1, 1],
			[1, T0.length + 2],
			[2, 1],
		]);
	});

	it("SCAN-005 treats regex metacharacters literally", () => {
		expect(detectDictionary(`aaa ${T2} aaa`, [T2])).toHaveLength(1);
		expect(detectDictionary("aaaaaaaa", [T2])).toEqual([]);
	});

	it("SCAN-005 returns nothing for no terms or no hits", () => {
		expect(detectDictionary("text", [])).toEqual([]);
		expect(detectDictionary("text", [T0])).toEqual([]);
	});

	it("SCAN-005 stays fast with many terms and adversarial text", () => {
		const terms = Array.from(
			{ length: 5000 },
			(_, i) => `${"a".repeat(30)}${i}`,
		);
		const text = "a".repeat(200_000);
		const t0 = Date.now();
		expect(detectDictionary(text, terms)).toEqual([]);
		expect(Date.now() - t0).toBeLessThan(5000);
	});

	it("SCAN-005 fails closed over the text size limit", () => {
		expect(() => detectDictionary("abcdef", [T0], { maxBytes: 3 })).toThrow(
			MctError,
		);
	});

	it("SCAN-005 rejects empty terms", () => {
		expect(() => detectDictionary("abc", [""])).toThrow(MctError);
	});

	it("SCAN-005 error messages never contain the term", async () => {
		let msg = "";
		try {
			detectDictionary(`${T0} ${T0}`, [T0], { maxBytes: 3 });
		} catch (e) {
			msg = String((e as Error).message);
		}
		expect(msg).not.toContain(T0);
	});
});
