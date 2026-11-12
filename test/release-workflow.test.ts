import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (p: string): string => readFileSync(p, "utf8");
const ci = read(".github/workflows/ci.yml");
const release = read(".github/workflows/release.yml");
const dependabot = read(".github/dependabot.yml");

/** Returns the text of a top-level job block inside `jobs:`. */
function job(text: string, name: string): string {
	const lines = text.split("\n");
	const start = lines.indexOf(`  ${name}:`);
	if (start === -1) return "";
	let end = lines.length;
	for (let i = start + 1; i < lines.length; i++) {
		if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[i] ?? "")) {
			end = i;
			break;
		}
	}
	return lines.slice(start, end).join("\n");
}

describe("REL-001 CI en pull request", () => {
	it("REL-001 corre en pull_request con permisos minimos", () => {
		expect(ci).toMatch(/^on:\n(?:.*\n)*? {2}pull_request:/m);
		expect(ci).toMatch(/^permissions:\n {2}contents: read\n/m);
		expect(ci).not.toMatch(/write/);
	});

	it("REL-001 matriz Node 22, 24 y 26 con scripts de instalacion desactivados", () => {
		expect(ci).toMatch(/node-version: \[22, 24, 26\]/);
		expect(ci).toContain("pnpm install --frozen-lockfile --ignore-scripts");
	});

	it("REL-001 corre build, tests y ambos escaneres", () => {
		for (const cmd of [
			"pnpm typecheck",
			"pnpm lint",
			"pnpm build",
			"pnpm test",
		]) {
			expect(ci).toContain(cmd);
		}
		expect(ci).toContain("gitleaks");
		expect(ci).toContain(".gitleaks.toml");
		expect(ci).toContain("trufflehog");
	});

	it("REL-001 mp:deriva solo si existe masterplan/", () => {
		expect(ci).toContain("pnpm mp:deriva");
		expect(ci).toMatch(/if: hashFiles\('masterplan\/\*\*'\) != ''/);
	});
});

describe("REL-001 release con smoke del tarball", () => {
	it("REL-001 smoke-tarball hace npm pack, contenedor limpio, --version, doctor y scan", () => {
		const smoke = job(release, "smoke-tarball");
		expect(smoke).not.toBe("");
		expect(smoke).toContain("npm pack");
		expect(smoke).toMatch(/docker run --rm/);
		expect(smoke).toContain("mct --version");
		expect(smoke).toContain("mct doctor");
		expect(smoke).toContain("mct scan");
		expect(smoke).toContain("--ignore-scripts");
	});

	it("REL-001 publish depende de smoke-tarball y usa OIDC con provenance", () => {
		const publish = job(release, "publish");
		expect(publish).toMatch(/needs: smoke-tarball\n/);
		expect(publish).toContain("id-token: write");
		expect(publish).toContain("--provenance");
		expect(publish).toContain("npm publish");
	});

	it("REL-001 los pasos del smoke fallan cerrado y no hay continue-on-error", () => {
		expect(release).not.toContain("continue-on-error");
		expect(job(release, "publish")).not.toMatch(/if:\s*(always|failure)\(\)/);
		expect(release).not.toMatch(/\|\| true/);
	});

	it("REL-001 permisos minimos: lectura global y escritura de id-token solo en publish", () => {
		expect(release).toMatch(/^permissions:\n {2}contents: read\n/m);
		expect(job(release, "smoke-tarball")).not.toContain("id-token");
		expect(release.match(/id-token: write/g)).toHaveLength(1);
	});

	it("REL-001 no contiene NPM_TOKEN ni tokens de npm en ningun workflow", () => {
		for (const text of [ci, release]) {
			expect(text).not.toContain("NPM_TOKEN");
			expect(text).not.toContain("NODE_AUTH_TOKEN");
			expect(text).not.toMatch(/npm_[A-Za-z0-9]{20,}/);
		}
	});
});

describe("REL-001 barreras antes de publicar en npm", () => {
	it("REL-001 el smoke corre typecheck, lint y test y exige tag igual a la versión", () => {
		const smoke = job(release, "smoke-tarball");
		for (const cmd of ["pnpm typecheck", "pnpm lint", "pnpm test"]) {
			expect(smoke).toContain(cmd);
		}
		expect(smoke).toContain('test "${GITHUB_REF_NAME}" = "v${version}"');
	});

	it("REL-001 publish usa entorno protegido, publica a next y el mismo tarball del smoke", () => {
		const publish = job(release, "publish");
		expect(publish).toMatch(/^ {4}environment: npm$/m);
		expect(publish).toContain("--tag next");
		expect(publish).not.toMatch(/--tag latest/);
		expect(publish).toContain("needs.smoke-tarball.outputs.sha256");
		expect(publish).toMatch(/npm publish "\$RUNNER_TEMP"\/pack\/\*\.tgz/);
	});

	it("REL-001 el tarball lleva LICENSE", () => {
		for (const name of ["smoke-tarball", "publish"]) {
			expect(job(release, name)).toContain(
				"cp LICENSE README.md packages/cli/",
			);
		}
		expect(job(release, "smoke-tarball")).toContain("package/LICENSE");
	});

	it("REL-001 los escáneres de CI usan las versiones fijadas", () => {
		expect(ci).toContain("ghcr.io/gitleaks/gitleaks:v8.30.1");
		expect(ci).toContain("trufflesecurity/trufflehog:3.99.8");
		expect(ci).not.toMatch(/:latest\b/);
	});
});

describe("REL-001 dependabot", () => {
	it("REL-001 actualiza npm y github-actions", () => {
		expect(dependabot).toContain("package-ecosystem: npm");
		expect(dependabot).toContain("package-ecosystem: github-actions");
	});
});
