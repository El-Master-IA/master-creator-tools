import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, describe, expect, it } from "vitest";
import { detectPii, type PiiMatch } from "../src/pii.js";
import { buildFixture, FIXTURE_NAMES, type Fixture } from "./fixtures/build.js";
import { luhnCheckDigit } from "./fixtures/pii.js";

const LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

function dniLetter(n: number): string {
	return LETTERS[n % 23] ?? "";
}

function cuit(prefix: string, body: string): string {
	const base = prefix + body;
	const weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
	let sum = 0;
	for (let i = 0; i < 10; i++) sum += Number(base[i]) * (weights[i] ?? 0);
	const r = 11 - (sum % 11);
	const dv = r === 11 ? 0 : r === 10 ? 9 : r;
	return `${prefix}-${body}-${dv}`;
}

function rutDv(body: string): string {
	let sum = 0;
	let factor = 2;
	for (let i = body.length - 1; i >= 0; i--) {
		sum += Number(body[i]) * factor;
		factor = factor === 7 ? 2 : factor + 1;
	}
	const r = 11 - (sum % 11);
	return r === 11 ? "0" : r === 10 ? "K" : String(r);
}

function reglas(text: string): string[] {
	return detectPii(text).map((m) => m.regla);
}

function slice(text: string, m: PiiMatch): string {
	return text.slice(m.inicio, m.fin);
}

let fixture: Fixture | undefined;
afterEach(async () => {
	await fixture?.cleanup();
	fixture = undefined;
});

describe("SCAN-006 fixtures", () => {
	for (const name of FIXTURE_NAMES) {
		it(`SCAN-006 reporta el 100% de la PII de truth.json (${name})`, async () => {
			fixture = await buildFixture(name);
			expect(fixture.truth.pii.length).toBeGreaterThan(0);
			for (const item of fixture.truth.pii) {
				const text = await readFile(join(fixture.work, item.file), "utf8");
				const found = detectPii(text).map((m) => slice(text, m));
				expect(found).toContain(item.value);
			}
		});
	}

	it("SCAN-006 los hallazgos llevan posición y fragmento enmascarado", async () => {
		fixture = await buildFixture("node");
		const item = fixture.truth.pii.find((p) => p.kind === "card");
		const text = await readFile(join(fixture.work, item?.file ?? ""), "utf8");
		const m = detectPii(text).find((x) => slice(text, x) === item?.value);
		expect(m?.linea).toBeGreaterThan(0);
		expect(m?.columna).toBeGreaterThan(0);
		expect(m?.fragmento).not.toContain(item?.value ?? "");
		expect(m?.fragmento.replaceAll("*", "").length).toBeLessThanOrEqual(4);
	});
});

describe("SCAN-006 tarjetas", () => {
	it("SCAN-006 un número de 16 dígitos que no pasa Luhn no es tarjeta", () => {
		const prefix = ["4111", "1111", "1111", "111"].join("");
		const good = Number(luhnCheckDigit(prefix));
		const bad = prefix + String((good + 1) % 10);
		expect(reglas(`n=${bad}`)).not.toContain("pii-card");
		expect(reglas(`n=${prefix}${good}`)).toContain("pii-card");
	});

	it("SCAN-006 acepta tarjeta con separadores", () => {
		const prefix = ["5500", "0000", "0000", "000"].join("");
		const n = prefix + luhnCheckDigit(prefix);
		const grouped = [0, 4, 8, 12].map((i) => n.slice(i, i + 4)).join(" ");
		expect(reglas(grouped)).toContain("pii-card");
	});
});

describe("SCAN-006 correo y teléfonos", () => {
	it("SCAN-006 correo", () => {
		const e = ["ana", "@", "ejemplo", ".test"].join("");
		expect(reglas(`x ${e} y`)).toEqual(["pii-email"]);
		expect(reglas("sin arroba.test")).toEqual([]);
	});

	it("SCAN-006 E.164", () => {
		for (const p of [
			["+57", "3005550142"].join(""),
			["+34", " 600", " 123", " 456"].join(""),
			["+1", " 415", " 555", " 0132"].join(""),
		]) {
			expect(reglas(`tel ${p}`)).toContain("pii-phone");
		}
	});

	it("SCAN-006 formatos nacionales", () => {
		const nat = [
			["300", " 555", " 0142"].join(""), // CO
			["55", " 1234", " 5678"].join(""), // MX
			["11", " 5555", "-1234"].join(""), // AR
			["600", " 123", " 456"].join(""), // ES
			["9", " 1234", " 5678"].join(""), // CL
			["987", " 654", " 321"].join(""), // PE
			["(", "415", ") ", "555", "-0132"].join(""), // US
		];
		for (const p of nat) {
			const text = `contacto: ${p}.`;
			const found = detectPii(text).filter((m) => m.regla === "pii-phone");
			expect(found.length).toBe(1);
		}
	});

	it("SCAN-006 no marca números cortos ni versiones", () => {
		expect(reglas("version 1.2.3 build 20240101 puerto 8080")).toEqual([]);
	});
});

describe("SCAN-006 documentos", () => {
	it("SCAN-006 cédula CO con puntos y con contexto", () => {
		expect(reglas(["1.", "020.", "304.", "050"].join(""))).toContain(
			"pii-cedula-co",
		);
		expect(reglas(`cédula: ${["1020", "304050"].join("")}`)).toContain(
			"pii-cedula-co",
		);
		expect(reglas(["1020", "304050"].join(""))).not.toContain("pii-cedula-co");
	});

	it("SCAN-006 CURP y RFC MX", () => {
		const curp = ["GOMA", "800101", "HDF", "RRN", "05"].join("");
		const rfcPf = ["GOMA", "800101", "AB1"].join("");
		const rfcPm = ["ABC", "800101", "XY2"].join("");
		expect(reglas(`c ${curp}`)).toEqual(["pii-curp"]);
		expect(reglas(`r ${rfcPf}`)).toEqual(["pii-rfc-mx"]);
		expect(reglas(`r ${rfcPm}`)).toEqual(["pii-rfc-mx"]);
	});

	it("SCAN-006 DNI y CUIT AR", () => {
		expect(reglas(["DNI ", "30", ".123", ".456"].join(""))).toContain(
			"pii-dni",
		);
		const c = cuit("20", "30123456");
		expect(reglas(`cuit ${c}`)).toContain("pii-cuit-ar");
		const wrong = `${c.slice(0, -1)}${(Number(c.slice(-1)) + 1) % 10}`;
		expect(reglas(`cuit ${wrong}`)).not.toContain("pii-cuit-ar");
	});

	it("SCAN-006 DNI y NIE ES con letra de control", () => {
		const dni = `12345678${dniLetter(12345678)}`;
		expect(reglas(`d ${dni}`)).toContain("pii-dni-es");
		const wrongLetter = LETTERS[(12345678 + 1) % 23] ?? "";
		expect(reglas(`d 12345678${wrongLetter}`)).not.toContain("pii-dni-es");
		const nie = `X1234567${dniLetter(1234567)}`;
		expect(reglas(`n ${nie}`)).toContain("pii-nie-es");
	});

	it("SCAN-006 RUT CL con dígito verificador", () => {
		const body = "12345678";
		const rut = `${body.slice(0, 2)}.${body.slice(2, 5)}.${body.slice(5)}-${rutDv(body)}`;
		expect(reglas(`rut ${rut}`)).toContain("pii-rut-cl");
		const wrong = rutDv(body) === "1" ? "2" : "1";
		expect(reglas(`rut 12.345.678-${wrong}`)).not.toContain("pii-rut-cl");
	});

	it("SCAN-006 DNI PE y SSN US", () => {
		expect(reglas("DNI 45678912")).toContain("pii-dni");
		expect(reglas(["123", "-", "45", "-", "6789"].join(""))).toContain(
			"pii-ssn",
		);
		expect(reglas(["000", "-", "45", "-", "6789"].join(""))).not.toContain(
			"pii-ssn",
		);
	});
});

describe("SCAN-006 función pura", () => {
	it("SCAN-006 es determinista y no se solapa", () => {
		const text = [
			"a@b",
			".test 300 555 0142 ",
			"cc ",
			["1.", "020.", "304.", "050"].join(""),
		].join("");
		const a = detectPii(text);
		expect(detectPii(text)).toEqual(a);
		for (let i = 1; i < a.length; i++) {
			expect(a[i]?.inicio ?? 0).toBeGreaterThanOrEqual(a[i - 1]?.fin ?? 0);
		}
	});

	it("SCAN-006 línea y columna parten de 1", () => {
		const e = ["ana", "@", "ejemplo", ".test"].join("");
		const [m] = detectPii(`uno\ndos ${e}`);
		expect(m?.linea).toBe(2);
		expect(m?.columna).toBe(5);
	});

	it("SCAN-006 rechaza entrada que no es texto con MctError", () => {
		expect(() => detectPii(42 as unknown as string)).toThrow(MctError);
	});
});

function timed<T>(fn: () => T): { ms: number; out: T } {
	const t0 = performance.now();
	const out = fn();
	return { ms: performance.now() - t0, out };
}

describe("SCAN-006 revisión", () => {
	it("SCAN-006 un paquete@versión de lockfile no es correo", () => {
		for (const line of [
			'"lodash@4.17.21":',
			"lodash@4.17.21, lodash@^4.17.0:",
			"  resolved lodash@4.17.21",
		]) {
			expect(reglas(line)).not.toContain("pii-email");
		}
		const e = ["ana", "@", "ejemplo", ".test"].join("");
		expect(reglas(`"x@1.2.3" ${e}`)).toEqual(["pii-email"]);
	});

	it("SEG-003 400 KB de base64 y 100 KB de '=' no se cuelgan", () => {
		const b64 = randomBytes(300_000).toString("base64");
		const a = timed(() => detectPii(b64));
		expect(a.ms).toBeLessThan(1000);
		const b = timed(() =>
			detectPii(`${"=".repeat(100_000)}@${"a".repeat(1000)}`),
		);
		expect(b.ms).toBeLessThan(1000);
		const c = timed(() => detectPii("@".repeat(100_000)));
		expect(c.ms).toBeLessThan(1000);
	});

	it("SEG-003 respeta maxBytes con MctError", () => {
		expect(() => detectPii("a".repeat(2048), { maxBytes: 1024 })).toThrow(
			MctError,
		);
		expect(detectPii("a".repeat(1024), { maxBytes: 1024 })).toEqual([]);
	});

	it("SCAN-006 encuentra una tarjeta Luhn dentro de un tramo largo de dígitos", () => {
		const prefix = ["4111", "1111", "1111", "111"].join("");
		const card = prefix + luhnCheckDigit(prefix);
		const run = `20240101${card}20240101`;
		const found = detectPii(`id=${run}`).filter((m) => m.regla === "pii-card");
		expect(found.length).toBeGreaterThanOrEqual(1);
		for (const m of found) {
			const digits = `id=${run}`.slice(m.inicio, m.fin).replace(/\D/g, "");
			expect(digits.length).toBeGreaterThanOrEqual(13);
			expect(digits.length).toBeLessThanOrEqual(19);
		}
	});

	it("SEG-007 el fragmento enmascarado usa maskValue sin revelar el final", () => {
		const prefix = ["4111", "1111", "1111", "111"].join("");
		const card = prefix + luhnCheckDigit(prefix);
		const [m] = detectPii(`n ${card}`);
		expect(m?.fragmento).toBe(`${card.slice(0, 4)}****`);
		const e = ["ana", "@", "ejemplo", ".test"].join("");
		const [em] = detectPii(e);
		expect(em?.fragmento).toBe("ana@****");
		expect(em?.fragmento).not.toContain("test");
	});

	it("SCAN-006 CUIT sin guiones", () => {
		const c = cuit("20", "30123456").replaceAll("-", "");
		expect(reglas(`cuit ${c}`)).toEqual(["pii-cuit-ar"]);
		const wrong = `${c.slice(0, -1)}${(Number(c.slice(-1)) + 1) % 10}`;
		expect(reglas(`cuit ${wrong}`)).not.toContain("pii-cuit-ar");
	});

	it("SCAN-006 teléfonos MX de 10 dígitos y con lada entre paréntesis", () => {
		for (const p of [
			["55", "1234", "5678"].join(""),
			["(55)", " 1234", " 5678"].join(""),
			["(55)", " 1234", "-5678"].join(""),
		]) {
			expect(reglas(`tel: ${p}.`)).toEqual(["pii-phone"]);
		}
	});

	it("SCAN-006 teléfono AR con (011) y fijos CL, CO y ES", () => {
		const cases = [
			["(011)", " 4567", "-8901"].join(""), // AR
			["2", " 2345", " 6789"].join(""), // CL fijo
			["(601)", " 234", " 5678"].join(""), // CO fijo
			["(601)", " 2345678"].join(""), // CO fijo
			["91", " 234", " 56", " 78"].join(""), // ES fijo
			["912", " 34", " 56", " 78"].join(""), // ES fijo
		];
		for (const p of cases) {
			expect(reglas(`contacto ${p}.`), p.length.toString()).toEqual([
				"pii-phone",
			]);
		}
	});
});

describe("SCAN-006 parte local larga", () => {
	const mail = ["ana", "@", "ejemplo", ".test"].join("");
	const found = (text: string): PiiMatch[] =>
		detectPii(text).filter((m) => m.regla === "pii-email");

	it("SCAN-006 URL con query larga termina en &email=<correo>", () => {
		const url = `https://sitio.test/ruta?${"a=1&".repeat(30)}email=${mail}`;
		const hits = found(url);
		expect(hits).toHaveLength(1);
		const hit = hits[0] as PiiMatch;
		expect(url.slice(hit.inicio, hit.fin).endsWith(mail)).toBe(true);
		const local = url.slice(hit.inicio, url.indexOf("@", hit.inicio));
		expect(local.length).toBeLessThanOrEqual(64);
		expect(local.endsWith("email=ana")).toBe(true);
	});

	it("SCAN-006 ruta de mas de 64 caracteres antes del correo", () => {
		const text = `/${"dir/".repeat(30)}${mail}`;
		const hits = found(text);
		expect(hits).toHaveLength(1);
		const hit = hits[0] as PiiMatch;
		expect(text.slice(hit.inicio, hit.fin).endsWith(mail)).toBe(true);
		expect(hit.fin - hit.inicio).toBeLessThanOrEqual(64 + 1 + 12);
	});

	it("SCAN-006 65 caracteres pegados se recortan a 64", () => {
		const text = `${"b".repeat(61)}${mail}`;
		const hits = found(text);
		expect(hits).toHaveLength(1);
		const hit = hits[0] as PiiMatch;
		expect(text.indexOf("@") - hit.inicio).toBe(64);
		const text2 = `${"b".repeat(100)}@${"ejemplo.test"}`;
		const h2 = found(text2)[0] as PiiMatch;
		expect(text2.indexOf("@") - h2.inicio).toBe(64);
	});

	it("SEG-003 parte local enorme sigue siendo lineal", () => {
		const text = `${"a@".repeat(1)}${"x".repeat(200_000)}`.repeat(3);
		const t0 = performance.now();
		detectPii(`${"a".repeat(200_000)}@${"b".repeat(50)}.test`);
		detectPii(text);
		expect(performance.now() - t0).toBeLessThan(2000);
	});
});

describe("SCAN-006 tarjeta con dígitos pegados (backlog MAJOR)", () => {
	const prefix = ["4111", "1111", "1111", "111"].join("");
	const card = prefix + luhnCheckDigit(prefix);

	function notLuhn(digits: string): boolean {
		let sum = 0;
		let double = false;
		for (let i = digits.length - 1; i >= 0; i--) {
			let d = Number(digits[i]);
			if (double) {
				d *= 2;
				if (d > 9) d -= 9;
			}
			sum += d;
			double = !double;
		}
		return sum % 10 !== 0;
	}

	/** One glued string of 1, 2 and 3 digits whose union with the card is not Luhn-valid. */
	function gluedOptions(base: string): string[] {
		return [1, 2, 3].map((len) => {
			for (let d = 1; d < 10; d++) {
				const glued = String(d).repeat(len);
				if (notLuhn(base + glued) && notLuhn(glued + base)) return glued;
			}
			throw new Error("no glued option");
		});
	}

	it("SCAN-006 detecta una tarjeta de 16 con 1 a 3 dígitos pegados detrás", () => {
		for (const glued of gluedOptions(card)) {
			const text = `n=${card}${glued}`;
			const found = detectPii(text).filter((m) => m.regla === "pii-card");
			expect(found).toHaveLength(1);
			expect(text.slice(found[0]?.inicio, found[0]?.fin)).toBe(card);
		}
	});

	it("SCAN-006 detecta una tarjeta de 16 con 1 a 3 dígitos pegados delante", () => {
		for (const glued of gluedOptions(card)) {
			const text = `n=${glued}${card}`;
			const found = detectPii(text).filter((m) => m.regla === "pii-card");
			expect(found).toHaveLength(1);
			expect(text.slice(found[0]?.inicio, found[0]?.fin)).toBe(card);
		}
	});

	it("SCAN-006 reconoce UnionPay, Maestro y Mir con dígitos pegados", () => {
		for (const head of ["6212", "5018", "2200"]) {
			const pre = head + "345678901234".slice(0, 11);
			const num = pre + luhnCheckDigit(pre);
			const [glued] = gluedOptions(num);
			const found = detectPii(`n=${num}${glued}`).filter(
				(m) => m.regla === "pii-card",
			);
			expect(found, head).toHaveLength(1);
		}
	});

	it("SCAN-006 un número largo sin prefijo de marca no se marca como tarjeta", () => {
		const noBrand = `9${card.slice(1)}7`;
		expect(reglas(`n=${noBrand}`)).not.toContain("pii-card");
	});
});

describe("SCAN-006 correos de no-reply de GitHub", () => {
	it("SCAN-006 *@users.noreply.github.com no es PII, otro dominio parecido sí", () => {
		const noreply = ["mct", "@", "users.noreply", ".github.com"].join("");
		expect(reglas(`user.email=${noreply}`)).not.toContain("pii-email");
		const lookalike = [
			"mct",
			"@",
			"users.noreply",
			".github.com.ejemplo.test",
		].join("");
		expect(reglas(`user.email=${lookalike}`)).toContain("pii-email");
		const other = ["mct", "@", "noreply", ".ejemplo.test"].join("");
		expect(reglas(`user.email=${other}`)).toContain("pii-email");
	});
});
