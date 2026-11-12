import { MctError } from "@mct/contract/errors";
import type { Command } from "commander";
import { createColors } from "picocolors";

export type Lang = "es" | "en";

/** Process boundary, injectable so tests never touch real stdio. */
export interface Io {
	out(text: string): void;
	err(text: string): void;
	env: Readonly<Record<string, string | undefined>>;
	stdinIsTTY: boolean;
	stderrIsTTY: boolean;
}

export interface GlobalFlags {
	json: boolean;
	noColor: boolean;
	verbose: boolean;
	lang: string | undefined;
}

/**
 * Reads the global flags straight from argv so that errors raised while
 * parsing (unknown option, bad --lang) are still reported in the right format.
 */
export function scanGlobals(argv: readonly string[]): GlobalFlags {
	const flags: GlobalFlags = {
		json: false,
		noColor: false,
		verbose: false,
		lang: undefined,
	};
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i] as string;
		if (arg === "--") break;
		if (arg === "--json") flags.json = true;
		else if (arg === "--no-color") flags.noColor = true;
		else if (arg === "--verbose") flags.verbose = true;
		else if (arg === "--lang") flags.lang = argv[i + 1];
		else if (arg.startsWith("--lang=")) flags.lang = arg.slice(7);
	}
	return flags;
}

export function isLang(value: string | undefined): value is Lang {
	return value === "es" || value === "en";
}

function langFromEnv(env: Io["env"]): Lang {
	const raw = env.LC_ALL || env.LANG || "";
	return raw.toLowerCase().startsWith("en") ? "en" : "es";
}

export interface CliContext {
	readonly json: boolean;
	readonly verbose: boolean;
	readonly lang: Lang;
	readonly color: boolean;
	readonly interactive: boolean;
	readonly workspace: string;
	readonly io: Io;
	/** Aborted on Ctrl+C; commands pass it to the core so it can roll back. */
	readonly signal: AbortSignal;
	/** Exit code the process must use once the command finishes. */
	exitCode: number;
	/** Human message on stderr (never stdout). */
	info(text: string): void;
	/**
	 * Result of a command: with --json only the JSON goes to stdout, the human
	 * text always goes to stderr. `exit` is for results such as scan with findings (10).
	 */
	result(data: unknown, human?: string, exit?: number): void;
}

const contexts = new WeakMap<Command, CliContext>();

function rootOf(command: Command): Command {
	let current = command;
	while (current.parent) current = current.parent;
	return current;
}

export function createContext(
	program: Command,
	io: Io,
	flags: GlobalFlags,
	signal: AbortSignal = new AbortController().signal,
): CliContext {
	const lang = isLang(flags.lang) ? flags.lang : langFromEnv(io.env);
	const color =
		!flags.noColor &&
		!io.env.NO_COLOR &&
		io.env.TERM !== "dumb" &&
		io.stderrIsTTY;
	const ctx: CliContext = {
		json: flags.json,
		verbose: flags.verbose,
		lang,
		color,
		interactive: io.stdinIsTTY && !flags.json,
		get workspace(): string {
			const value = program.opts<{ workspace?: string }>().workspace;
			return value ?? "./.mct";
		},
		io,
		signal,
		exitCode: 0,
		info(text) {
			io.err(`${text}\n`);
		},
		result(data, human, exit = 0) {
			if (flags.json) writeJson(io, data);
			if (human !== undefined) io.err(`${human}\n`);
			ctx.exitCode = exit;
		},
	};
	contexts.set(program, ctx);
	return ctx;
}

export function contextOf(command: Command): CliContext {
	const ctx = contexts.get(rootOf(command));
	if (!ctx) {
		throw new MctError("INTERNO", "El contexto de la CLI no está inicializado");
	}
	return ctx;
}

function writeJson(io: Io, data: unknown): void {
	let text: string | undefined;
	try {
		text = JSON.stringify(data);
	} catch (cause) {
		throw new MctError("INTERNO", "El resultado no se pudo serializar a JSON", {
			cause,
		});
	}
	if (text === undefined) {
		throw new MctError("INTERNO", "El resultado no se pudo serializar a JSON");
	}
	io.out(`${text}\n`);
}

/** Anything thrown becomes an MctError; unknown errors never leak their message. */
export function toMctError(error: unknown): MctError {
	if (error instanceof MctError) return error;
	return new MctError("INTERNO", "Error interno no controlado", {
		cause: error,
	});
}

const NO_ARGS: Record<Lang, readonly string[]> = {
	es: [
		"mct · convierte un proyecto privado en un repo público sanitizado",
		"Flujo: init → scan → sanitize → licenses → package → verify → publish",
		"Nada se publica sin tu confirmación escrita.",
		"Primero: mct doctor",
		"Luego:   mct init <carpeta | https://github.com/owner/repo | flujo.json>",
	],
	en: [
		"mct · turns a private project into a sanitized public repo",
		"Flow: init → scan → sanitize → licenses → package → verify → publish",
		"Nothing is published without your written confirmation.",
		"First:  mct doctor",
		"Then:   mct init <folder | https://github.com/owner/repo | flow.json>",
	],
};

export function printFirstRun(ctx: CliContext): void {
	ctx.io.err(`${NO_ARGS[ctx.lang].join("\n")}\n`);
}

/**
 * Reports a failure: JSON error only on stdout with --json, plus one human
 * line on stderr. Returns the exit code of the error.
 */
export function reportError(
	ctx: CliContext,
	error: unknown,
	verbose = ctx.verbose,
): number {
	const err = toMctError(error);
	if (ctx.json) writeJson(ctx.io, err.toJSON());
	const paint = createColors(ctx.color);
	const lines = [
		`${paint.bold(paint.red("Error"))} ${err.codigo}: ${err.message}`,
	];
	if (err.accion) lines.push(err.accion);
	if (verbose && !(error instanceof MctError) && error instanceof Error) {
		// Never error.message: fs errors carry absolute paths that can hold
		// dictionary terms or PII (SEG-203). Only the name and errno code.
		const code = (error as { code?: unknown }).code;
		const safe = typeof code === "string" && /^[A-Z0-9_]{1,40}$/.test(code);
		lines.push(safe ? `${error.name} ${code}` : error.name);
	}
	ctx.io.err(`${lines.join("\n")}\n`);
	return err.exit;
}
