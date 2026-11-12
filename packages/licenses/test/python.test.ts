import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	auditPython,
	POETRY_SIN_LOCK,
	parseRequirementsText,
	SIN_LOCKFILE,
} from "../src/python.js";
import { gateExit } from "../src/verdict.js";

let dir: string;
beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "mct-py-"));
});
afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

const write = (name: string, text: string) => writeFile(join(dir, name), text);

function registry(docs: Record<string, unknown>) {
	return vi.fn(async (url: string, _init?: RequestInit) => {
		const key = url.replace("https://pypi.org/pypi/", "").replace("/json", "");
		const doc = docs[key];
		if (doc === undefined) return new Response("{}", { status: 404 });
		return new Response(JSON.stringify(doc), { status: 200 });
	});
}

const info = (extra: Record<string, unknown>) => ({ info: extra });
const SIN_LOCK = { motivo: "instalo sin lock a proposito" };

describe("LIC-005 uv.lock", () => {
	const uvLock = `
version = 1
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]
[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]
[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "privado"
version = "1.0.0"
source = { registry = "https://pkgs.example.test/simple" }
[[package]]
name = "viaGit"
version = "0.0.1"
source = { git = "https://example.test/x.git" }
`;

	it("LIC-005 reads the full tree with lock versions and queries only the public index", async () => {
		await write("uv.lock", uvLock);
		const fetchFn = registry({
			"requests/2.32.0": info({ license_expression: "Apache-2.0" }),
			"urllib3/2.2.1": info({ license: "MIT" }),
		});
		const r = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			mctVersion: "9.9.9",
		});
		const by = Object.fromEntries(r.entries.map((e) => [e.paquete, e]));
		expect(Object.keys(by).sort()).toEqual([
			"privado",
			"requests",
			"urllib3",
			"viaGit",
		]);
		expect(by.requests).toMatchObject({
			version: "2.32.0",
			spdx: "Apache-2.0",
			origen: "directa",
			veredicto: "ok",
		});
		expect(by.urllib3).toMatchObject({ origen: "transitiva", veredicto: "ok" });
		expect(by.privado?.veredicto).toBe("revisar");
		expect(by.viaGit?.veredicto).toBe("revisar");
		const urls = fetchFn.mock.calls.map((c) => c[0]);
		expect(urls.sort()).toEqual([
			"https://pypi.org/pypi/requests/2.32.0/json",
			"https://pypi.org/pypi/urllib3/2.2.1/json",
		]);
		const init = fetchFn.mock.calls[0]?.[1] as RequestInit;
		expect((init.headers as Record<string, string>)["user-agent"]).toBe(
			"mct/9.9.9",
		);
		expect(init.credentials).toBe("omit");
		expect(r.entries.some((e) => e.paquete.startsWith("("))).toBe(false);
	});

	it("LIC-005 --offline never touches the network", async () => {
		await write("uv.lock", uvLock);
		const fetchFn = registry({});
		const r = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			offline: true,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		expect(r.entries.every((e) => e.veredicto === "revisar")).toBe(true);
	});

	it("LIC-005 a registry that times out leaves the package in revisar", async () => {
		await write("uv.lock", uvLock);
		const slow = vi.fn(
			(_url: string, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () =>
						reject(new Error("aborted")),
					);
				}),
		);
		const r = await auditPython({ workDir: dir, fetch: slow, timeoutMs: 20 });
		expect(r.entries.find((e) => e.paquete === "requests")?.veredicto).toBe(
			"revisar",
		);
		expect(gateExit(r.entries)).toBe(10);
	});

	it("LIC-005 queries at most 8 in parallel", async () => {
		const pkgs = Array.from(
			{ length: 20 },
			(_, i) =>
				`[[package]]\nname = "p${i}"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n`,
		).join("\n");
		await write("uv.lock", pkgs);
		let active = 0;
		let peak = 0;
		const fetchFn = vi.fn(async () => {
			active++;
			peak = Math.max(peak, active);
			await new Promise((r) => setTimeout(r, 5));
			active--;
			return new Response(JSON.stringify(info({ license: "MIT" })));
		});
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(20);
		expect(peak).toBeLessThanOrEqual(8);
	});
});

describe("LIC-005 poetry.lock", () => {
	it("LIC-005 poetry.lock adds the synthetic entry, accepted only with sinLock", async () => {
		await write(
			"poetry.lock",
			`[[package]]\nname = "Flask"\nversion = "3.0.0"\n[[package]]\nname = "click"\nversion = "8.1.0"\n[package.source]\ntype = "legacy"\nurl = "https://pkgs.example.test/simple"\n`,
		);
		await write(
			"pyproject.toml",
			`[tool.poetry.dependencies]\npython = "^3.13"\nflask = "^3"\n`,
		);
		const fetchFn = registry({
			"flask/3.0.0": info({
				classifiers: ["License :: OSI Approved :: BSD License"],
			}),
		});
		const closed = await auditPython({ workDir: dir, fetch: fetchFn });
		const synthetic = closed.entries.find((e) => e.paquete === POETRY_SIN_LOCK);
		expect(synthetic).toMatchObject({
			version: "",
			spdx: null,
			veredicto: "revisar",
		});
		expect(closed.entries.some((e) => e.paquete === SIN_LOCKFILE)).toBe(false);
		expect(closed.entries.find((e) => e.paquete === "Flask")).toMatchObject({
			origen: "directa",
			veredicto: "revisar",
		});
		expect(fetchFn).toHaveBeenCalledTimes(1);
		const open = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			sinLock: SIN_LOCK,
		});
		expect(
			open.entries.find((e) => e.paquete === POETRY_SIN_LOCK),
		).toMatchObject({ veredicto: "ok", override: { motivo: SIN_LOCK.motivo } });
	});
});

describe("LIC-005 requirements", () => {
	it("LIC-005 >=, ~=, VCS, -e, paths and wildcards are revisar without any request", async () => {
		await write(
			"requirements.txt",
			[
				"# comment",
				"flask>=2.0",
				"django~=4.2",
				"numpy==1.*",
				["git+https://user", ":pw", "@example.test/org/lib.git#egg=lib"].join(
					"",
				),
				"-e ./local",
				"./vendor/thing.whl",
				"pkg @ https://example.test/pkg.zip",
			].join("\n"),
		);
		const fetchFn = registry({});
		const r = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			sinLock: SIN_LOCK,
		});
		expect(fetchFn).not.toHaveBeenCalled();
		const real = r.entries.filter((e) => !e.paquete.startsWith("("));
		expect(real.map((e) => e.paquete).sort()).toEqual([
			"-e ./local",
			"./vendor/thing.whl",
			"django",
			"flask",
			"lib",
			"numpy",
			"pkg",
		]);
		expect(
			real.every((e) => e.veredicto === "revisar" && e.spdx === null),
		).toBe(true);
		expect(JSON.stringify(r.entries)).not.toContain("pw@");
	});

	it("LIC-005 only == lines are queried; markers and hashes are ignored", async () => {
		await write(
			"requirements.txt",
			"Flask_Login[async]==0.6.3 ; python_version >= '3.9' \\\n    --hash=sha256:abc\nrich==13.0.0\n",
		);
		const fetchFn = registry({
			"flask-login/0.6.3": info({ license_expression: "MIT" }),
			"rich/13.0.0": info({ license: "MIT" }),
		});
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect(r.entries.filter((e) => e.veredicto === "ok")).toHaveLength(2);
		const sin = r.entries.find((e) => e.paquete === SIN_LOCKFILE);
		expect(sin?.veredicto).toBe("revisar");
	});

	it("LIC-005 a file with --index-url or --extra-index-url sends no names to PyPI", async () => {
		for (const opt of [
			"--index-url https://pkgs.example.test/simple",
			"--extra-index-url=https://pkgs.example.test/simple",
		]) {
			await write("requirements.txt", `${opt}\nsecret-internal==1.0.0\n`);
			const fetchFn = registry({});
			const r = await auditPython({ workDir: dir, fetch: fetchFn });
			expect(fetchFn).not.toHaveBeenCalled();
			expect(
				r.entries.find((e) => e.paquete === "secret-internal")?.veredicto,
			).toBe("revisar");
		}
	});

	it("LIC-005 requirements.txt with >= marks the dependency revisar without querying the network", async () => {
		await write("requirements.txt", "requests>=2.0\n");
		const fetchFn = registry({});
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(r.entries.find((e) => e.paquete === "requests")?.veredicto).toBe(
			"revisar",
		);
	});

	it("LIC-005 parseRequirementsText keeps exact pins queryable", () => {
		const deps = parseRequirementsText("a==1.0\nb>=2\n");
		expect(deps.map((d) => [d.paquete, d.version, d.consultar])).toEqual([
			["a", "1.0", true],
			["b", "", false],
		]);
	});
});

describe("LIC-005 no lockfile", () => {
	it("LIC-005 without lock adds the synthetic entry; sinLock accepts it (exit 0)", async () => {
		await write("requirements.txt", "rich==13.0.0\n");
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		const closed = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(gateExit(closed.entries)).toBe(10);
		const open = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			sinLock: SIN_LOCK,
		});
		expect(gateExit(open.entries)).toBe(0);
		expect(open.resumen.overrides).toBe(1);
		const short = await auditPython({
			workDir: dir,
			fetch: fetchFn,
			sinLock: { motivo: "corto" },
		});
		expect(gateExit(short.entries)).toBe(10);
	});

	it("LIC-005 pyproject [project.dependencies] is the last source", async () => {
		await write(
			"pyproject.toml",
			`[project]\nname = "x"\ndependencies = ["rich==13.0.0", "click>=8"]\n`,
		);
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(r.entries.map((e) => e.paquete).sort()).toEqual([
			SIN_LOCKFILE,
			"click",
			"rich",
		]);
	});

	it("LIC-005 a license from PyPI that blocks stays bloquea", async () => {
		await write("requirements.txt", "gplthing==1.0\n");
		const fetchFn = registry({
			"gplthing/1.0": info({ license_expression: "GPL-3.0-only" }),
		});
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(r.entries.find((e) => e.paquete === "gplthing")?.veredicto).toBe(
			"bloquea",
		);
	});

	it("LIC-005 a symlinked manifest is refused (fail closed)", async () => {
		await mkdir(join(dir, "real"));
		await write("real/r.txt", "a==1\n");
		try {
			await symlink(join(dir, "real/r.txt"), join(dir, "requirements.txt"));
		} catch {
			return; // no symlink permission on this machine
		}
		await expect(
			auditPython({ workDir: dir, offline: true }),
		).rejects.toThrow();
	});
});

describe("LIC-005 no manifest", () => {
	it("LIC-005 a python project with no manifest has 0 packages, no synthetic entry and aviso sin-gestor", async () => {
		await write("main.py", "print('hi')\n");
		const r = await auditPython({ workDir: dir, offline: true });
		expect(r.entries).toEqual([]);
		expect(r.avisos).toEqual(["sin-gestor"]);
		expect(gateExit(r.entries)).toBe(0);
	});

	it("LIC-005 pyproject or requirements that declare zero dependencies get no synthetic entry", async () => {
		await write(
			"pyproject.toml",
			'[project]\nname = "x"\nversion = "0.1.0"\ndependencies = []\n',
		);
		await write("requirements.txt", "# sin dependencias\n");
		const r = await auditPython({ workDir: dir, offline: true });
		expect(r.entries).toEqual([]);
		expect(r.avisos).toEqual([]);
		expect(gateExit(r.entries)).toBe(0);
	});

	it.each([
		['[project]\nname = "x"\ndynamic = ["dependencies"]\n', "dynamic"],
		[
			'[project]\nname = "x"\ndependencies = []\n[project.optional-dependencies]\ndev = ["pytest"]\n',
			"optional",
		],
		['[project]\nname = "x"\n[dependency-groups]\ndev = ["ruff"]\n', "groups"],
		[
			'[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "^2"\n',
			"poetry",
		],
	])("LIC-005 %s (%s) still gets the sin-lockfile entry", async (toml) => {
		await write("pyproject.toml", toml);
		const r = await auditPython({ workDir: dir, offline: true });
		expect(r.entries.some((e) => e.paquete === SIN_LOCKFILE)).toBe(true);
	});

	it("LIC-005 setup.py alone is a manifest: synthetic sin-lockfile entry, no aviso", async () => {
		await write("setup.py", "from setuptools import setup\n");
		const r = await auditPython({ workDir: dir, offline: true });
		expect(r.entries.map((e) => e.paquete)).toEqual([SIN_LOCKFILE]);
		expect(r.avisos).toEqual([]);
	});
});

describe("LIC-005 private sources never reach pypi.org", () => {
	it.each([
		"-i https://pkgs.example.test/simple",
		"-f ./wheels",
		"--find-links=./wheels",
		"--no-index",
	])(
		"LIC-005 option %s makes every dependency revisar without a request",
		async (opt) => {
			await write("requirements.txt", `${opt}\ninternal-lib==1.0.0\n`);
			const fetchFn = registry({});
			const r = await auditPython({ workDir: dir, fetch: fetchFn });
			expect(fetchFn).not.toHaveBeenCalled();
			expect(
				r.entries.find((e) => e.paquete === "internal-lib")?.veredicto,
			).toBe("revisar");
		},
	);

	it("LIC-005 -r and -c are followed and an index in the included file taints the chain", async () => {
		await write(
			"requirements.txt",
			"-r base/common.txt\n-c constraints.txt\nrich==13.0.0\n",
		);
		await mkdir(join(dir, "base"));
		await write(
			"base/common.txt",
			"--extra-index-url https://pkgs.example.test/simple\ninternal-lib==1.0.0\n",
		);
		await write("constraints.txt", "rich<14\n");
		const fetchFn = registry({});
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		const names = r.entries.map((e) => e.paquete);
		expect(names).toContain("internal-lib");
		expect(names).toContain("rich");
	});

	it("LIC-005 an include that escapes the workspace or is missing leaves the chain unqueried", async () => {
		await write("requirements.txt", "-r ../outside.txt\nrich==13.0.0\n");
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		await write("requirements.txt", "-r missing.txt\nrich==13.0.0\n");
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it.each([
		'[tool.uv]\nindex = [{ url = "https://pkgs.example.test/simple" }]\n',
		'[tool.uv.sources]\ninternal = { git = "https://example.test/x.git" }\n',
		'[[tool.poetry.source]]\nname = "p"\nurl = "https://pkgs.example.test/simple"\n',
		'[[tool.pdm.source]]\nname = "p"\nurl = "https://pkgs.example.test/simple"\n',
	])(
		"LIC-005 pyproject source config leaves everything unqueried",
		async (extra) => {
			await write(
				"pyproject.toml",
				`[project]\nname = "x"\ndependencies = ["internal==1.0"]\n${extra}`,
			);
			await write("requirements.txt", "internal==1.0\n");
			const fetchFn = registry({});
			const r = await auditPython({ workDir: dir, fetch: fetchFn });
			expect(fetchFn).not.toHaveBeenCalled();
			expect(r.entries.find((e) => e.paquete === "internal")?.veredicto).toBe(
				"revisar",
			);
		},
	);

	it("LIC-005 labels drop credentials even when the password has @ and /", async () => {
		await write(
			"requirements.txt",
			[
				[
					"git+https://deploy",
					":s3cr",
					"@t/xyz@host.example.test/org/lib.git",
				].join(""),
				[
					"-e git+ssh://bob",
					":p4ss",
					"@w/rd@host.example.test/org/other.git?token=abc#frag",
				].join(""),
				"https://[bad/url.whl",
			].join("\n"),
		);
		const r = await auditPython({ workDir: dir, offline: true });
		const text = JSON.stringify(r.entries);
		for (const leak of [
			"deploy",
			"s3cr",
			"xyz",
			"bob",
			"p4ss",
			"w/rd",
			"token",
			"frag",
		]) {
			expect(text).not.toContain(leak);
		}
		expect(text).toContain("https://host.example.test/org/lib.git");
		expect(text).toContain("(origen no público)");
	});
});

describe("LIC-005 fail closed on unknown options and pyproject keys", () => {
	it.each([
		"--extra-index https://pkgs.example.test/simple",
		"--ind https://pkgs.example.test/simple",
		"--trusted-host pkgs.example.test",
		"--made-up-option",
		"-x",
	])("LIC-005 unknown option %s leaves the file unqueried", async (opt) => {
		await write("requirements.txt", `${opt}\ninternal-lib==1.0.0\n`);
		const fetchFn = registry({});
		const r = await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(r.entries.find((e) => e.paquete === "internal-lib")?.veredicto).toBe(
			"revisar",
		);
	});

	it("LIC-005 the closed list of safe options still allows queries", async () => {
		await write(
			"requirements.txt",
			"--pre\n--prefer-binary\n--only-binary=:all:\n--require-hashes\nrich==13.0.0 --hash=sha256:abc\n",
		);
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it.each([
		'[tool.uv.pip]\nindex-url = "https://pkgs.example.test/simple"\n',
		'[tool.uv.pip]\nextra-index-url = ["https://pkgs.example.test/simple"]\n',
		"[tool.custom.deep.er]\nno-index = true\n",
		'[tool.custom]\nfind-links = ["./w"]\n',
		'[[tool.custom.sources]]\nname = "p"\n',
	])(
		"LIC-005 any tool key with index/source/find-links leaves everything unqueried",
		async (extra) => {
			await write(
				"pyproject.toml",
				`[project]\nname = "x"\ndependencies = ["internal==1.0"]\n${extra}`,
			);
			const fetchFn = registry({});
			await auditPython({ workDir: dir, fetch: fetchFn });
			expect(fetchFn).not.toHaveBeenCalled();
		},
	);

	it("LIC-005 a pyproject without such keys is still queried", async () => {
		await write(
			"pyproject.toml",
			'[project]\nname = "x"\ndependencies = ["rich==13.0.0"]\n[tool.ruff]\nline-length = 88\n',
		);
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});
});

describe("LIC-005 every option token on a line is checked", () => {
	it.each([
		"--pre --index-url https://pkgs.example.test/simple",
		"--prefer-binary --extra-index-url=https://pkgs.example.test/simple",
		"--only-binary=:all: --find-links ./w",
		"--pre extra-argument",
		"--require-hashes=yes",
		"-r base.txt --index-url https://pkgs.example.test/simple",
		"-c base.txt -c other.txt",
		"-e . --index-url https://pkgs.example.test/simple",
		'"--index-url" https://pkgs.example.test/simple',
	])("LIC-005 line %s leaves the file unqueried", async (opt) => {
		await write("requirements.txt", `${opt}\ninternal-lib==1.0.0\n`);
		await write("base.txt", "");
		await write("other.txt", "");
		const fetchFn = registry({});
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-005 an index option after a requirement is not ignored", async () => {
		await write(
			"requirements.txt",
			"internal-lib==1.0.0 --index-url https://pkgs.example.test/simple\n",
		);
		const fetchFn = registry({});
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it("LIC-005 plain safe flags and --hash keep the file queryable", async () => {
		await write(
			"requirements.txt",
			"--pre\n--only-binary :all:\nrich==13.0.0 --hash=sha256:abc\n",
		);
		const fetchFn = registry({ "rich/13.0.0": info({ license: "MIT" }) });
		await auditPython({ workDir: dir, fetch: fetchFn });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});
});

describe("LIC-005 private index outside requirements", () => {
	const pin = "requests==2.0.0\n";
	const fetchOk = () =>
		registry({ "requests/2.0.0": info({ license_expression: "MIT" }) });

	it("LIC-005 pip.conf in work makes every package unqueried with the aviso", async () => {
		await write("requirements.txt", pin);
		await write("pip.conf", "[global]\n");
		const fetch = fetchOk();
		const r = await auditPython({
			workDir: dir,
			sinLock: SIN_LOCK,
			fetch,
		});
		expect(fetch).not.toHaveBeenCalled();
		expect(r.avisos).toEqual(["indice-privado-fuera"]);
		expect(r.entries.find((e) => e.paquete === "requests")?.veredicto).toBe(
			"revisar",
		);
	});

	it("LIC-005 a .pip directory at depth 2 is detected", async () => {
		await write("requirements.txt", pin);
		await mkdir(join(dir, "a", ".pip"), { recursive: true });
		const fetch = fetchOk();
		const r = await auditPython({ workDir: dir, sinLock: SIN_LOCK, fetch });
		expect(fetch).not.toHaveBeenCalled();
		expect(r.avisos).toContain("indice-privado-fuera");
	});

	it.each([
		[
			"Dockerfile.dev",
			"RUN pip install --extra-index-url https://x/simple y\n",
		],
		["ci.yml", "env:\n  PIP_INDEX_URL: https://x/simple\n"],
		["Makefile", "i:\n\tpip install --index-url https://x/simple y\n"],
		["tox.ini", "[testenv]\nsetenv = PIP_EXTRA_INDEX_URL=https://x\n"],
		["setup.cfg", "# --index-url https://x\n"],
		[".env.example", "PIP_INDEX_URL=\n"],
		["pip.ini", "[global]\n"],
	])("LIC-005 %s disables PyPI", async (name, body) => {
		await write("requirements.txt", pin);
		await write(name, body);
		const fetch = fetchOk();
		const r = await auditPython({ workDir: dir, sinLock: SIN_LOCK, fetch });
		expect(fetch).not.toHaveBeenCalled();
		expect(r.avisos).toEqual(["indice-privado-fuera"]);
	});

	it("LIC-005 a variable NAME in quarantine is detected and no value reaches the result", async () => {
		await write("requirements.txt", pin);
		const q = join(dir, "q");
		await mkdir(q);
		await writeFile(
			join(q, ".env"),
			`PIP_INDEX_URL=${"h"}ttps://u${":p"}@x/simple\n`,
		);
		const fetch = fetchOk();
		const r = await auditPython({
			workDir: dir,
			quarantineDir: q,
			sinLock: SIN_LOCK,
			fetch,
		});
		expect(fetch).not.toHaveBeenCalled();
		expect(JSON.stringify(r)).not.toContain("u:p");
		expect(r.avisos).toEqual(["indice-privado-fuera"]);
	});

	it("LIC-005 without any marker PyPI is still queried", async () => {
		await write("requirements.txt", pin);
		await write("ci.yml", "name: ci\n");
		const fetch = fetchOk();
		const r = await auditPython({ workDir: dir, sinLock: SIN_LOCK, fetch });
		expect(fetch).toHaveBeenCalledTimes(1);
		expect(r.avisos).toEqual([]);
	});

	it("LIC-005 ignores node_modules and files over 1 MB", async () => {
		await write("requirements.txt", pin);
		await mkdir(join(dir, "node_modules"));
		await writeFile(join(dir, "node_modules", "ci.yml"), "--index-url x\n");
		await write("big.yml", `${"a".repeat(1_100_000)}\n--index-url x\n`);
		const fetch = fetchOk();
		const r = await auditPython({ workDir: dir, sinLock: SIN_LOCK, fetch });
		expect(fetch).toHaveBeenCalledTimes(1);
		expect(r.avisos).toEqual([]);
	});

	it("LIC-005 does not look deeper than 3 levels", async () => {
		await write("requirements.txt", pin);
		await mkdir(join(dir, "a", "b", "c", "d"), { recursive: true });
		await writeFile(join(dir, "a", "b", "c", "d", "pip.conf"), "x");
		const fetch = fetchOk();
		const r = await auditPython({ workDir: dir, sinLock: SIN_LOCK, fetch });
		expect(fetch).toHaveBeenCalledTimes(1);
		expect(r.avisos).toEqual([]);
	});
});

describe("LIC-005 manifests in subfolders", () => {
	it("LIC-005 a requirements file in a subfolder is a revisar entry, not sin-gestor", async () => {
		await mkdir(join(dir, "api"));
		await writeFile(join(dir, "api", "requirements.txt"), "a==1\n");
		const r = await auditPython({ workDir: dir, offline: true });
		expect(r.avisos).toEqual([]);
		expect(r.entries.map((e) => [e.paquete, e.veredicto])).toEqual([
			["(manifiesto en subcarpeta: api/requirements.txt)", "revisar"],
		]);
		expect(gateExit(r.entries)).not.toBe(0);
	});

	it("LIC-005 the subfolder entry is accepted with sinLock", async () => {
		await mkdir(join(dir, "api"));
		await writeFile(join(dir, "api", "pyproject.toml"), "[project]\n");
		const r = await auditPython({
			workDir: dir,
			offline: true,
			sinLock: SIN_LOCK,
		});
		expect(gateExit(r.entries)).toBe(0);
	});
});
