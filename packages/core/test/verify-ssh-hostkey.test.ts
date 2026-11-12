import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { resolveDocker, sshProbeArgs } from "../src/docker.js";

const UNKNOWN =
	"No ED25519 host key is known for srv.example.test and you have requested strict checking.\r\nHost key verification failed.\r\n";
const CHANGED = [
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
	"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
	"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
	"Host key verification failed.",
	"",
].join("\n");

function sshFails(stderr: string, files: string[] = []): Runner {
	return async (file) => {
		files.push(file);
		return file.endsWith("ssh")
			? { code: 255, stdout: "", stderr }
			: { code: 0, stdout: "27.0.1", stderr: "" };
	};
}

async function errOf(p: Promise<unknown>): Promise<MctError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(MctError);
	return err as MctError;
}

const base = {
	dockerPath: "/usr/bin/docker",
	sshPath: "/usr/bin/ssh",
	env: {},
};

describe("VER-006 SSH host key", () => {
	it("VER-006 ssh runs with StrictHostKeyChecking=yes and never accepts a key", () => {
		const args = sshProbeArgs("servidor-casa");
		expect(args).toContain("StrictHostKeyChecking=yes");
		expect(args.join(" ")).not.toMatch(/accept-new|StrictHostKeyChecking=no/);
		expect(args).toContain("BatchMode=yes");
		expect(args.indexOf("--")).toBeLessThan(args.indexOf("servidor-casa"));
	});

	it("VER-006 an unknown host fails with host-desconocido", async () => {
		const err = await errOf(
			resolveDocker({
				...base,
				configRemote: "servidor-casa",
				run: sshFails(UNKNOWN),
			}),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(err.detalle?.motivo).toBe("host-desconocido");
	});

	it("VER-006 a changed key fails with clave-cambiada", async () => {
		const err = await errOf(
			resolveDocker({
				...base,
				remote: "servidor-casa",
				run: sshFails(CHANGED),
			}),
		);
		expect(err.codigo).toBe("VALIDACION");
		expect(err.detalle?.motivo).toBe("clave-cambiada");
	});

	it("VER-006 a host key failure never falls back to local Docker", async () => {
		const files: string[] = [];
		await errOf(
			resolveDocker({
				...base,
				configRemote: "servidor-casa",
				run: sshFails(CHANGED, files),
			}),
		);
		expect(files.length).toBeGreaterThan(0);
		expect(files.every((f) => f.endsWith("ssh"))).toBe(true);
	});

	it("VER-006 permission denied is DOCKER_NO_DISPONIBLE ssh-denegado", async () => {
		const err = await errOf(
			resolveDocker({
				...base,
				configRemote: "servidor-casa",
				run: sshFails("user@srv: Permission denied (publickey).\r\n"),
			}),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
		expect(err.detalle?.motivo).toBe("ssh-denegado");
	});

	it("VER-006 a trusted host yields a remote target over ssh://", async () => {
		const run: Runner = async () => ({ code: 0, stdout: "27.0.1", stderr: "" });
		const t = await resolveDocker({ ...base, remote: "servidor-casa", run });
		expect(t.kind).toBe("remote");
		expect(t.env.DOCKER_HOST).toBe("ssh://servidor-casa");
	});

	it("VER-006 an alias that looks like an option is refused", async () => {
		const run: Runner = async () => ({ code: 0, stdout: "", stderr: "" });
		const err = await errOf(
			resolveDocker({ ...base, remote: "-oProxyCommand=x", run }),
		);
		expect(err.codigo).toBe("VALIDACION");
	});
});
