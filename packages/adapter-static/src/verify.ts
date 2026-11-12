import { posix } from "node:path";
import { PYTHON_IMAGE_REFS } from "@mct/contract/pins";
import type { VerifySpec } from "@mct/contract/types";

export const STATIC_PORT = 8080;
export const MAX_EXTRA_ROUTES = 50;
const TIMEOUT_MIN = 5;

const RE_ATTR =
	/\b(?:href|src)\s*=\s*(?:"([^"]{0,2000})"|'([^']{0,2000})'|([^\s>"']{1,2000}))/gi;
const RE_SCHEME = /^[a-z][a-z0-9+.-]*:/i;

/**
 * Local resources (href/src) of an index.html, as absolute URL paths of the
 * served site, in order of appearance, without repeats, at most 50.
 * `indexDir` is the folder (relative to the project) that is served.
 */
export function localResources(html: string): string[] {
	const out: string[] = [];
	for (const m of html.matchAll(RE_ATTR)) {
		const raw = (m[1] ?? m[2] ?? m[3] ?? "").trim();
		if (raw === "" || raw.startsWith("#") || raw.startsWith("//")) continue;
		if (RE_SCHEME.test(raw)) continue;
		const clean = raw.split(/[?#]/)[0] ?? "";
		if (clean === "") continue;
		const rel = posix.normalize(
			clean.startsWith("/") ? clean.slice(1) || "." : clean,
		);
		if (rel === "." || rel === ".." || rel.startsWith("../")) continue;
		const resolved = `/${rel}`;
		if (!out.includes(resolved)) out.push(resolved);
		if (out.length >= MAX_EXTRA_ROUTES) break;
	}
	return out;
}

/** WEB-002: serve the folder of index.html with python's http.server on 8080. */
export function buildVerifySpec(
	entrypoint: string,
	rutas: string[],
): VerifySpec {
	const dir = posix.dirname(entrypoint);
	return {
		imagen: PYTHON_IMAGE_REFS["3.14-slim"],
		start: [
			"python",
			"-m",
			"http.server",
			String(STATIC_PORT),
			"--bind",
			"127.0.0.1",
			"--directory",
			dir,
		],
		healthcheck: {
			tipo: "http",
			puerto: STATIC_PORT,
			ruta: "/",
			aceptar: ["2xx"],
			cuerpoContiene: "<html",
			rutasExtra: rutas.slice(0, MAX_EXTRA_ROUTES),
		},
		timeoutMin: TIMEOUT_MIN,
	};
}
