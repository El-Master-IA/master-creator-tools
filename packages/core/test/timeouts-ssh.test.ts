import { MctError } from "@mct/contract/errors";
import { describe, expect, it } from "vitest";
import type { Runner } from "../src/clone.js";
import { resolveDocker, SSH_TIMEOUT_MS, sshProbeArgs } from "../src/docker.js";

const base = {
	dockerPath: "/usr/bin/docker",
	sshPath: "/usr/bin/ssh",
	env: {},
	sshTimeoutMs: 40,
};

/** ssh hangs until aborted; docker answers according to `localOk`. */
function hangingSsh(localOk: boolean, files: string[] = []): Runner {
	return (file, _args, o) => {
		files.push(file);
		if (file.endsWith("ssh")) {
			return new Promise((_, reject) => {
				o.signal.addEventListener("abort", () => reject(new Error("aborted")));
			});
		}
		return Promise.resolve({
			code: localOk ? 0 : 1,
			stdout: "",
			stderr: "",
		});
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

describe("TMO-003 SSH timeout", () => {
	it("TMO-003 the limit is 15 s", () => {
		expect(SSH_TIMEOUT_MS).toBe(15_000);
		expect(sshProbeArgs("a")).toContain("ConnectTimeout=15");
	});

	it("TMO-003 a configured alias that does not answer falls back to local Docker", async () => {
		const t = await resolveDocker({
			...base,
			configRemote: "servidor-casa",
			run: hangingSsh(true),
		});
		expect(t.kind).toBe("local");
	});

	it("TMO-003 a configured alias that does not answer, with no local Docker, exits DOCKER_NO_DISPONIBLE", async () => {
		const err = await errOf(
			resolveDocker({
				...base,
				configRemote: "servidor-casa",
				run: hangingSsh(false),
			}),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
	});

	it("TMO-003 --remote that does not answer exits ssh-timeout and never touches local Docker", async () => {
		const files: string[] = [];
		const err = await errOf(
			resolveDocker({
				...base,
				remote: "servidor-casa",
				run: hangingSsh(true, files),
			}),
		);
		expect(err.codigo).toBe("DOCKER_NO_DISPONIBLE");
		expect(err.detalle?.motivo).toBe("ssh-timeout");
		expect(files.every((f) => f.endsWith("ssh"))).toBe(true);
	});

	it("TMO-003 the test hook cannot raise the limit above 15 s", async () => {
		const t = await resolveDocker({
			...base,
			sshTimeoutMs: 10 * SSH_TIMEOUT_MS,
			remote: "servidor-casa",
			run: async () => ({ code: 0, stdout: "27", stderr: "" }),
		});
		expect(t.kind).toBe("remote");
	});
});
