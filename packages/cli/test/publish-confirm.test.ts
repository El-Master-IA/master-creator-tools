import { MctError } from "@mct/contract/errors";
import type { GithubClient } from "@mct/core/github";
import type { PublishOptions, PublishResult } from "@mct/core/publish";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	overridePublishDeps,
	type PublishPrompter,
	register,
} from "../src/commands/publish.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

const REPO = "AlexanderKast/mi-flujo";

interface Calls {
	clients: number;
	publish: PublishOptions[];
	asked: { tipo: "text" | "confirm"; message: string; initial?: boolean }[];
	cleaned: number;
}

let calls: Calls;
let restore: () => void;

function makeIo(tty: boolean, lang = "es_CO.UTF-8") {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: lang },
		stdinIsTTY: tty,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

/** Texts answer in order; confirms answer in order (`undefined` → the default). */
function scripted(
	texts: (string | null)[],
	confirms: (boolean | null | undefined)[] = [],
): PublishPrompter {
	return {
		text: async (o) => {
			calls.asked.push({ tipo: "text", message: o.message });
			return texts.shift() ?? null;
		},
		confirm: async (o) => {
			calls.asked.push({
				tipo: "confirm",
				message: o.message,
				initial: o.initialValue,
			});
			const next = confirms.shift();
			return next === undefined ? o.initialValue : next;
		},
	};
}

const fakeClient = {} as GithubClient;

function useDeps(
	prompter: PublishPrompter,
	publishImpl?: (o: PublishOptions) => Promise<PublishResult>,
): void {
	restore();
	restore = overridePublishDeps({
		prompter,
		createClient: async () => {
			calls.clients++;
			return fakeClient;
		},
		publish: async (o) => {
			calls.publish.push(o);
			if (publishImpl !== undefined) return publishImpl(o);
			if (o.dryRun === true) {
				return {
					url: `https://github.com/${o.repo}`,
					visibilidad: "privado",
					tag: "v0.1.0",
					dryRun: true,
				};
			}
			const publico =
				o.privado !== true && (await o.confirmarPublico()) === true;
			return {
				url: `https://github.com/${o.repo}`,
				visibilidad: publico ? "publico" : "privado",
				tag: "v0.1.0",
			};
		},
		clean: async (o) => {
			calls.cleaned++;
			return { borrado: o.raiz, archivos: 3 };
		},
	});
}

const realPublishes = () => calls.publish.filter((o) => o.dryRun !== true);

function codigoDe(out: string[]): string {
	return (JSON.parse(out.join("")) as { error: { codigo: string } }).error
		.codigo;
}

beforeEach(() => {
	calls = { clients: 0, publish: [], asked: [], cleaned: 0 };
	restore = () => {};
	useDeps(scripted([]));
});

afterEach(() => {
	restore();
});

describe("PUB-002 nombre escrito", () => {
	it("PUB-002 CUANDO el nombre escrito no coincide EL SISTEMA DEBE salir con CANCELADO sin crear el repo", async () => {
		useDeps(scripted(["AlexanderKast/mi-flujo2"]));
		const { io, err } = makeIo(true);
		const code = await runCli(["publish", "--repo", REPO], io, [register]);
		expect(code).toBe(20);
		expect(realPublishes()).toHaveLength(0);
		expect(err.join("")).toContain("No se publicó nada");
	});

	it("PUB-002 CUANDO el nombre difiere solo en mayúsculas EL SISTEMA DEBE cancelar", async () => {
		useDeps(scripted([REPO.toLowerCase()]));
		const code = await runCli(["publish", "--repo", REPO], makeIo(true).io, [
			register,
		]);
		expect(code).toBe(20);
		expect(realPublishes()).toHaveLength(0);
	});

	for (const escrito of ["", ` ${REPO}`]) {
		it(`PUB-002 CUANDO escribe ${JSON.stringify(escrito)} EL SISTEMA DEBE cancelar`, async () => {
			useDeps(scripted([escrito]));
			const code = await runCli(["publish", "--repo", REPO], makeIo(true).io, [
				register,
			]);
			expect(code).toBe(20);
			expect(realPublishes()).toHaveLength(0);
		});
	}

	it("PUB-002 CUANDO la persona cancela el prompt del nombre EL SISTEMA DEBE salir con CANCELADO", async () => {
		useDeps(scripted([null]));
		const code = await runCli(["publish", "--repo", REPO], makeIo(true).io, [
			register,
		]);
		expect(code).toBe(20);
		expect(realPublishes()).toHaveLength(0);
	});

	it("PUB-002 CUANDO el nombre coincide EL SISTEMA DEBE publicar una vez tras las comprobaciones", async () => {
		useDeps(scripted([REPO], [true, false]));
		const { io, err } = makeIo(true);
		const code = await runCli(["publish", "--repo", REPO], io, [register]);
		expect(code).toBe(0);
		expect(calls.publish.map((o) => o.dryRun === true)).toEqual([true, false]);
		expect(calls.asked[0]?.tipo).toBe("text");
		expect(calls.asked[0]?.message).toContain(REPO);
		expect(err.join("")).toContain("Público · release v0.1.0");
	});

	it("PUB-002 CUANDO una comprobación falla EL SISTEMA DEBE salir sin pedir el nombre", async () => {
		useDeps(scripted([REPO]), async () => {
			throw new MctError("PUERTA_BLOQUEADA", "verify pendiente");
		});
		const code = await runCli(["publish", "--repo", REPO], makeIo(true).io, [
			register,
		]);
		expect(code).toBe(10);
		expect(calls.asked).toHaveLength(0);
		expect(realPublishes()).toHaveLength(0);
	});
});

describe("PUB-003 segunda confirmación", () => {
	it("PUB-003 CUANDO pregunta hacerlo público EL SISTEMA DEBE tener No por defecto", async () => {
		useDeps(scripted([REPO], [undefined, undefined]));
		const { io, err } = makeIo(true);
		expect(await runCli(["publish", "--repo", REPO], io, [register])).toBe(0);
		const publico = calls.asked.find((a) => a.message.includes("público"));
		expect(publico?.initial).toBe(false);
		expect(err.join("")).toContain("Privado · release v0.1.0");
	});

	it("PUB-003 CUANDO la persona cancela la segunda confirmación EL SISTEMA DEBE tomarlo como No", async () => {
		useDeps(scripted([REPO], [null, false]));
		const { io, err } = makeIo(true);
		expect(await runCli(["publish", "--repo", REPO], io, [register])).toBe(0);
		expect(err.join("")).toContain("Privado · release v0.1.0");
		expect(calls.asked.filter((a) => a.tipo === "confirm")).toHaveLength(2);
	});

	it("PUB-003 CUANDO se usa --private EL SISTEMA DEBE pasarlo sin preguntar hacerlo público", async () => {
		useDeps(scripted([REPO], [false]));
		expect(
			await runCli(["publish", "--repo", REPO, "--private"], makeIo(true).io, [
				register,
			]),
		).toBe(0);
		expect(realPublishes()[0]?.privado).toBe(true);
		expect(calls.asked.some((a) => a.message.includes("público"))).toBe(false);
	});

	it("PUB-008 CUANDO se usa --resume EL SISTEMA DEBE pasarlo en las comprobaciones y en la publicación", async () => {
		useDeps(scripted([REPO], [true, false]));
		expect(
			await runCli(["publish", "--repo", REPO, "--resume"], makeIo(true).io, [
				register,
			]),
		).toBe(0);
		expect(calls.publish.map((o) => o.resume)).toEqual([true, true]);
	});
});

describe("CLI-005 sin terminal", () => {
	it("PUB-002 CUANDO no hay TTY y no es dry-run EL SISTEMA DEBE salir con CANCELADO", async () => {
		const { io, err } = makeIo(false);
		const code = await runCli(["publish", "--repo", REPO], io, [register]);
		expect(code).toBe(20);
		expect(calls.clients).toBe(0);
		expect(calls.publish).toHaveLength(0);
		expect(calls.asked).toHaveLength(0);
		expect(err.join("")).toContain("terminal interactiva");
	});

	it("PUB-002 CUANDO se pide --json sin dry-run EL SISTEMA DEBE salir con CANCELADO aunque haya TTY", async () => {
		const { io, out } = makeIo(true);
		const code = await runCli(["--json", "publish", "--repo", REPO], io, [
			register,
		]);
		expect(code).toBe(20);
		expect(codigoDe(out)).toBe("CANCELADO");
		expect(calls.publish).toHaveLength(0);
	});

	it("PUB-002 CUANDO no hay TTY EL SISTEMA DEBE explicarlo también en inglés", async () => {
		const { io, err } = makeIo(false, "en_US.UTF-8");
		expect(await runCli(["publish", "--repo", REPO], io, [register])).toBe(20);
		expect(err.join("")).toContain("interactive terminal");
	});

	it("PUB-006 CUANDO se usa --dry-run sin TTY EL SISTEMA DEBE comprobar todo sin preguntar ni publicar", async () => {
		const { io, out } = makeIo(false);
		const code = await runCli(
			["--json", "publish", "--repo", REPO, "--dry-run"],
			io,
			[register],
		);
		expect(code).toBe(0);
		expect(calls.publish).toHaveLength(1);
		expect(calls.publish[0]?.dryRun).toBe(true);
		expect(calls.asked).toHaveLength(0);
		expect(calls.cleaned).toBe(0);
		expect(JSON.parse(out.join(""))).toMatchObject({
			url: `https://github.com/${REPO}`,
			dryRun: true,
		});
	});
});

describe("CLI-008 sin --yes", () => {
	it("CLI-008 CUANDO se pasa --yes EL SISTEMA DEBE rechazarlo sin llamar a GitHub", async () => {
		const { io, out } = makeIo(true);
		const code = await runCli(
			["--json", "publish", "--repo", REPO, "--yes"],
			io,
			[register],
		);
		expect(code).toBe(2);
		expect(codigoDe(out)).toBe("VALIDACION");
		expect(calls.clients).toBe(0);
		expect(calls.publish).toHaveLength(0);
	});

	it("PUB-002 CUANDO falta --repo EL SISTEMA DEBE salir con VALIDACION", async () => {
		const code = await runCli(["publish"], makeIo(true).io, [register]);
		expect(code).toBe(2);
		expect(calls.publish).toHaveLength(0);
	});
});

describe("PUB-014 confirmación por flags (sin TTY)", () => {
	it("PUB-014 con --confirmo-repo igual a --repo y --publico publica sin preguntar y lo hace público", async () => {
		const { io, out } = makeIo(false);
		const code = await runCli(
			[
				"publish",
				"--repo",
				REPO,
				"--confirmo-repo",
				REPO,
				"--publico",
				"--json",
			],
			io,
			[register],
		);
		expect(code).toBe(0);
		expect(calls.asked).toHaveLength(0);
		expect(realPublishes()).toHaveLength(1);
		expect(calls.cleaned).toBe(0);
		expect(
			JSON.parse(out.join("")).visibilidad ??
				JSON.parse(out.join("")).datos?.visibilidad,
		).toBe("publico");
	});

	it("PUB-014 sin --publico queda privado", async () => {
		const { io } = makeIo(false);
		const code = await runCli(
			["publish", "--repo", REPO, "--confirmo-repo", REPO, "--json"],
			io,
			[register],
		);
		expect(code).toBe(0);
		expect(realPublishes()).toHaveLength(1);
		expect(await realPublishes()[0]?.confirmarPublico()).toBe(false);
	});

	for (const otro of [REPO.toLowerCase(), `${REPO} `, "AlexanderKast/otro"]) {
		it(`PUB-014 con --confirmo-repo ${JSON.stringify(otro)} distinto cancela sin publicar`, async () => {
			const code = await runCli(
				[
					"publish",
					"--repo",
					REPO,
					"--confirmo-repo",
					otro,
					"--publico",
					"--json",
				],
				makeIo(false).io,
				[register],
			);
			expect(code).toBe(20);
			expect(realPublishes()).toHaveLength(0);
		});
	}

	it("PUB-014 --publico sin --confirmo-repo no sirve sin TTY", async () => {
		const code = await runCli(
			["publish", "--repo", REPO, "--publico", "--json"],
			makeIo(false).io,
			[register],
		);
		expect(code).toBe(20);
		expect(realPublishes()).toHaveLength(0);
	});

	it("PUB-014 --publico con --private es VALIDACION", async () => {
		const code = await runCli(
			[
				"publish",
				"--repo",
				REPO,
				"--confirmo-repo",
				REPO,
				"--publico",
				"--private",
				"--json",
			],
			makeIo(false).io,
			[register],
		);
		expect(code).toBe(2);
		expect(calls.publish).toHaveLength(0);
	});
});
