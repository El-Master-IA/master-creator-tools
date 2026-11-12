import {
	access,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GithubClient } from "@mct/core/github";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { overrideFlowDeps, type Prompter } from "../src/commands/flow.js";
import {
	overridePublishDeps,
	type PublishPrompter,
	register as publishCommand,
} from "../src/commands/publish.js";
import { runCli } from "../src/main.js";
import type { Io } from "../src/output.js";

const REPO = "AlexanderKast/mi-flujo";

let base: string;
let origen: string;
let dest: string;
let restoreFlow: () => void;
let restorePublish: () => void;
let confirms: { message: string; initial: boolean }[];
let cleaned: string[];

function makeIo(tty: boolean) {
	const out: string[] = [];
	const err: string[] = [];
	const io: Io = {
		out: (t) => out.push(t),
		err: (t) => err.push(t),
		env: { LANG: "es_CO.UTF-8" },
		stdinIsTTY: tty,
		stderrIsTTY: false,
	};
	return { io, out, err };
}

/** Pressing Enter: every confirm returns its own default. */
const enterFlow: Prompter = {
	select: async () => null as never,
	text: async () => null,
	confirm: async (o) => {
		confirms.push({ message: o.message, initial: o.initialValue });
		return o.initialValue;
	},
};

function publishPrompter(
	answers: (boolean | null | undefined)[],
): PublishPrompter {
	return {
		text: async () => REPO,
		confirm: async (o) => {
			confirms.push({ message: o.message, initial: o.initialValue });
			const next = answers.shift();
			return next === undefined ? o.initialValue : next;
		},
	};
}

function usePublish(answers: (boolean | null | undefined)[]): void {
	restorePublish();
	restorePublish = overridePublishDeps({
		prompter: publishPrompter(answers),
		createClient: async () => ({}) as GithubClient,
		publish: async (o) => ({
			url: `https://github.com/${o.repo}`,
			visibilidad: "privado",
			tag: "v0.1.0",
			...(o.dryRun === true && { dryRun: true as const }),
		}),
		clean: async (o) => {
			cleaned.push(o.raiz);
			await rm(o.raiz, { recursive: true, force: true });
			return { borrado: o.raiz, archivos: 1 };
		},
	});
}

const ws = () => join(dest, ".mct");
const borrarPregunta = () =>
	confirms.find((c) => c.message.includes("Borrar el workspace"));

beforeEach(async () => {
	confirms = [];
	cleaned = [];
	base = await mkdtemp(join(tmpdir(), "mct-cli-destructive-"));
	origen = join(base, "origen");
	dest = join(base, "dest");
	const home = join(base, "home");
	await mkdir(join(origen, "src"), { recursive: true });
	await mkdir(home, { recursive: true });
	await writeFile(
		join(origen, "package.json"),
		JSON.stringify({ name: "fx", version: "1.0.0" }),
	);
	await writeFile(join(origen, "src", "index.js"), "module.exports = 1;\n");
	restoreFlow = overrideFlowDeps({ home, prompter: enterFlow });
	restorePublish = () => {};
	await mkdir(ws(), { recursive: true });
	await writeFile(join(ws(), "marca.txt"), "workspace");
});

afterEach(async () => {
	restoreFlow();
	restorePublish();
	await rm(base, { recursive: true, force: true });
});

async function runPublish(): Promise<number> {
	return runCli(
		["publish", "--repo", REPO, "--workspace", ws()],
		makeIo(true).io,
		[publishCommand],
	);
}

describe("CLI-008 borrar workspace al final de publish", () => {
	it("CLI-008 CUANDO pregunta borrar workspace EL SISTEMA DEBE tener No por defecto", async () => {
		usePublish([undefined]);
		expect(await runPublish()).toBe(0);
		expect(borrarPregunta()?.initial).toBe(false);
		expect(cleaned).toHaveLength(0);
		expect(await readFile(join(ws(), "marca.txt"), "utf8")).toBe("workspace");
	});

	it("CLI-008 CUANDO la persona cancela la pregunta EL SISTEMA DEBE conservar el workspace", async () => {
		usePublish([null]);
		expect(await runPublish()).toBe(0);
		expect(cleaned).toHaveLength(0);
		await access(join(ws(), "marca.txt"));
	});

	it("CLI-008 CUANDO la persona responde sí EL SISTEMA DEBE borrar el workspace", async () => {
		usePublish([true]);
		expect(await runPublish()).toBe(0);
		expect(cleaned).toEqual([ws()]);
		await expect(access(ws())).rejects.toThrow();
	});

	it("CLI-008 CUANDO publish no llega al final EL SISTEMA DEBE no preguntar borrar el workspace", async () => {
		usePublish([]);
		restorePublish();
		restorePublish = overridePublishDeps({
			prompter: publishPrompter([]),
			createClient: async () => ({}) as GithubClient,
			publish: async (o) => {
				if (o.dryRun === true) {
					return { url: "u", visibilidad: "privado", tag: "v0.1.0" };
				}
				throw new Error("falla de red");
			},
		});
		expect(await runPublish()).not.toBe(0);
		expect(borrarPregunta()).toBeUndefined();
		await access(join(ws(), "marca.txt"));
	});
});

describe("CLI-008 init --force", () => {
	beforeEach(async () => {
		await rm(ws(), { recursive: true, force: true });
		expect(
			await runCli(["init", origen, "--dest", dest], makeIo(false).io),
		).toBe(0);
		confirms = [];
	});

	it("CLI-008 CUANDO init --force corre sin TTY EL SISTEMA DEBE salir con CANCELADO sin preguntar ni tocar el workspace", async () => {
		const antes = await readFile(join(ws(), "state.json"), "utf8");
		const code = await runCli(
			["init", origen, "--dest", dest, "--force"],
			makeIo(false).io,
		);
		expect(code).toBe(20);
		expect(confirms).toHaveLength(0);
		expect(await readFile(join(ws(), "state.json"), "utf8")).toBe(antes);
	});

	it("CLI-008 CUANDO init --force pregunta EL SISTEMA DEBE listar lo que se pierde con No por defecto y no recrear con Enter", async () => {
		const antes = await readFile(join(ws(), "state.json"), "utf8");
		const code = await runCli(
			["init", origen, "--dest", dest, "--force"],
			makeIo(true).io,
		);
		expect(code).toBe(20);
		const pregunta = confirms.at(-1);
		expect(pregunta?.initial).toBe(false);
		expect(pregunta?.message).toContain("Esto borra el workspace actual");
		expect(pregunta?.message).toContain("dist");
		expect(await readFile(join(ws(), "state.json"), "utf8")).toBe(antes);
	});
});
