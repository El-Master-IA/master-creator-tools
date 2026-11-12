#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { MctError } from "@mct/contract/errors";
import { Command, CommanderError, Option } from "commander";
import pkg from "../package.json" with { type: "json" };
import {
	type CliContext,
	createContext,
	type Io,
	printFirstRun,
	reportError,
	scanGlobals,
} from "./output.js";

/** Every command module exports `register(program)` from src/commands. */
export type Register = (program: Command) => void;

import { register as clean } from "./commands/clean.js";
import { register as doctor } from "./commands/doctor.js";
import { register as flow } from "./commands/flow.js";
import { register as licenses } from "./commands/licenses.js";
import { register as pack } from "./commands/package.js";
import { register as publish } from "./commands/publish.js";
import { register as run } from "./commands/run.js";
import { register as verify } from "./commands/verify.js";

/** The 10 commands: init, scan and sanitize come from flow. */
const COMMANDS: readonly Register[] = [
	flow,
	licenses,
	pack,
	verify,
	publish,
	clean,
	doctor,
	run,
];

const COMMANDER_EXIT_OK = new Set([
	"commander.help",
	"commander.helpDisplayed",
	"commander.version",
]);

function commandNames(register: Register): string[] {
	const scratch = new Command();
	register(scratch);
	return scratch.commands.map((c) => c.name());
}

function buildProgram(io: Io, extra: readonly Register[]): Command {
	const program = new Command();
	program
		.name("mct")
		.description("Convert a private project into a sanitized public repo")
		.version(pkg.version, "-V, --version", "print the version")
		.option("--workspace <dir>", "workspace directory", "./.mct")
		.option("--json", "machine-readable output on stdout")
		.option("--no-color", "disable color (also NO_COLOR)")
		.option("--verbose", "show extra detail on stderr")
		.addOption(
			new Option("--lang <lang>", "output language").choices(["es", "en"]),
		)
		.exitOverride()
		.configureOutput({
			writeOut: (text) => io.out(text),
			writeErr: (text) => io.err(text),
			// Parse errors are reported by runCli in the right format.
			outputError: () => {},
		});
	// An injected module (tests swap `doctor`) replaces the default of the same name.
	const taken = new Set(extra.flatMap(commandNames));
	for (const register of COMMANDS) {
		if (!commandNames(register).some((name) => taken.has(name))) {
			register(program);
		}
	}
	for (const register of extra) register(program);
	return program;
}

/** Runs the CLI and returns the exit code; never touches process state. */
export async function runCli(
	argv: readonly string[],
	io: Io,
	extra: readonly Register[] = [],
	signal?: AbortSignal,
): Promise<number> {
	const flags = scanGlobals(argv);
	const program = buildProgram(io, extra);
	const ctx: CliContext = createContext(program, io, flags, signal);
	program.action(() => {
		printFirstRun(ctx);
	});
	try {
		await program.parseAsync([...argv], { from: "user" });
		if (ctx.signal.aborted) return reportError(ctx, interrumpido(ctx));
		return ctx.exitCode;
	} catch (error) {
		if (error instanceof CommanderError) {
			if (COMMANDER_EXIT_OK.has(error.code)) return 0;
			return reportError(
				ctx,
				new MctError("VALIDACION", error.message.replace(/^error: /, ""), {
					accion: ctx.lang === "en" ? "Run: mct --help" : "Corre: mct --help",
				}),
			);
		}
		// Our own interruption text, and any warning about private leftovers, must reach the person.
		const keep =
			error instanceof MctError &&
			(error.codigo === "INTERRUMPIDO" ||
				(error.detalle as { residuo?: unknown } | undefined)?.residuo === true);
		return reportError(
			ctx,
			ctx.signal.aborted && !keep ? interrumpido(ctx) : error,
		);
	}
}

function interrumpido(ctx: CliContext): MctError {
	return new MctError(
		"INTERRUMPIDO",
		ctx.lang === "en"
			? "Interrupted (Ctrl+C)"
			: "Interrumpido por la persona (Ctrl+C)",
	);
}

function realIo(): Io {
	return {
		out: (text) => {
			process.stdout.write(text);
		},
		err: (text) => {
			process.stderr.write(text);
		},
		env: process.env,
		stdinIsTTY: process.stdin.isTTY === true,
		stderrIsTTY: process.stderr.isTTY === true,
	};
}

async function main(): Promise<void> {
	const io = realIo();
	const argv = process.argv.slice(2);
	const controller = new AbortController();
	// First Ctrl+C aborts so the running command rolls back and exits 130;
	// a second one forces the exit.
	process.on("SIGINT", () => {
		if (controller.signal.aborted) process.exit(130);
		controller.abort();
	});
	const code = await runCli(argv, io, [], controller.signal);
	// runCli only returns once the stage has rolled back, so exiting is safe.
	if (controller.signal.aborted) process.exit(code);
	process.exitCode = code;
}

function isEntry(): boolean {
	const entry = process.argv[1];
	if (!entry) return false;
	try {
		return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
	} catch {
		return false;
	}
}

if (isEntry()) {
	await main();
}
