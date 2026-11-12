import { createRequire } from "node:module";
import classifiersData from "../data/pypi-classifiers.json" with {
	type: "json",
};
import { type FetchLike, readBody } from "./audit.js";

const require = createRequire(import.meta.url);
const parseSpdx = require("spdx-expression-parse") as (
	expression: string,
) => unknown;

const PYPI = "https://pypi.org/pypi";
const MAX_SPDX_LENGTH = 200;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const PYPI_VERSION = /^[A-Za-z0-9][A-Za-z0-9.+!_-]*$/;
// Generic marker that says nothing about the license: ignored, not ambiguous.
const GENERIC_OSI = "License :: OSI Approved";

/** PEP 503 normalized name: lowercase, runs of `-`, `_`, `.` become `-`. */
export function normalizePypiName(name: string): string {
	return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export function isValidPypiName(name: string): boolean {
	return name.length <= 214 && PYPI_NAME.test(name);
}

export function isValidPypiVersion(version: string): boolean {
	return version.length <= 64 && PYPI_VERSION.test(version);
}

/** Closed classifier -> SPDX table; `null` marks an ambiguous classifier (revisar). */
export function loadClassifierTable(): Record<string, string | null> {
	const data: unknown = classifiersData;
	const table: Record<string, string | null> = {};
	if (data === null || typeof data !== "object" || Array.isArray(data)) {
		throw new Error("pypi-classifiers.json con formato inválido");
	}
	for (const [key, value] of Object.entries(data)) {
		if (value !== null && typeof value !== "string") {
			throw new Error("pypi-classifiers.json con formato inválido");
		}
		table[key] = value;
	}
	return table;
}

/** True when `text` is a well-formed SPDX expression with known identifiers. */
export function isValidSpdx(text: unknown): text is string {
	if (typeof text !== "string") return false;
	const value = text.trim();
	if (value === "" || value.length > MAX_SPDX_LENGTH) return false;
	try {
		const node = parseSpdx(value);
		return node !== null && typeof node === "object";
	} catch {
		return false;
	}
}

/** SPDX from the `License ::` classifiers; ambiguous, unknown or mixed ones give `undefined`. */
export function spdxFromClassifiers(classifiers: unknown): string | undefined {
	if (!Array.isArray(classifiers)) return undefined;
	const table = loadClassifierTable();
	const found = new Set<string>();
	for (const c of classifiers) {
		if (typeof c !== "string" || !c.startsWith("License ::")) continue;
		if (c === GENERIC_OSI) continue;
		const mapped = Object.hasOwn(table, c) ? table[c] : undefined;
		if (mapped === undefined || mapped === null) return undefined;
		found.add(mapped);
	}
	if (found.size !== 1) return undefined;
	return [...found][0];
}

/** SPDX order of LIC-005: `license_expression`, `license` if valid SPDX, classifiers. */
export function spdxFromPypiInfo(info: unknown): string | undefined {
	if (info === null || typeof info !== "object") return undefined;
	const doc = info as Record<string, unknown>;
	if (isValidSpdx(doc.license_expression)) {
		return doc.license_expression.trim();
	}
	if (isValidSpdx(doc.license)) return doc.license.trim();
	return spdxFromClassifiers(doc.classifiers);
}

export interface PypiQueryOptions {
	fetch: FetchLike;
	timeoutMs: number;
	maxBytes: number;
	/** Version shown in the `mct/<version>` User-Agent. */
	mctVersion: string;
	/** Remaining time before the global deadline, in ms. */
	remainingMs: number;
}

/** One credential-less GET per package; any failure is `undefined` (the package stays revisar). */
export async function fetchPypiSpdx(
	name: string,
	version: string,
	options: PypiQueryOptions,
): Promise<string | undefined> {
	if (!isValidPypiName(name) || !isValidPypiVersion(version)) return undefined;
	const url = `${PYPI}/${normalizePypiName(name)}/${encodeURIComponent(version)}/json`;
	try {
		const res = await options.fetch(url, {
			method: "GET",
			headers: {
				accept: "application/json",
				"user-agent": `mct/${options.mctVersion}`,
			},
			redirect: "error",
			credentials: "omit",
			signal: AbortSignal.timeout(
				Math.max(1, Math.min(options.timeoutMs, options.remainingMs)),
			),
		});
		if (!res.ok) return undefined;
		const body = await readBody(res, options.maxBytes);
		if (body === undefined) return undefined;
		const doc: unknown = JSON.parse(body);
		if (doc === null || typeof doc !== "object") return undefined;
		return spdxFromPypiInfo((doc as Record<string, unknown>).info);
	} catch {
		return undefined;
	}
}
