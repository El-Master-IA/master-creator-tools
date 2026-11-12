export const ERROR_EXITS = {
	VALIDACION: 2,
	ORIGEN_NO_ENCONTRADO: 3,
	WORKSPACE_INVALIDO: 4,
	PUERTA_BLOQUEADA: 10,
	APROBACION_DESACTUALIZADA: 11,
	MOTOR_NO_DISPONIBLE: 12,
	DOCKER_NO_DISPONIBLE: 13,
	SIN_CREDENCIAL: 14,
	LIMITE_GITHUB: 15,
	PERMISO_INSUFICIENTE: 16,
	CANCELADO: 20,
	INTERRUMPIDO: 130,
	INTERNO: 70,
} as const;

export type ErrorCode = keyof typeof ERROR_EXITS;

export const REDACTED = "[REDACTADO]";

// GitHub token families: classic/OAuth/user/server/refresh and fine-grained.
const GITHUB_TOKEN =
	/\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g;

export function redactTokens(text: string): string {
	return text.replace(GITHUB_TOKEN, REDACTED);
}

function sanitizeValue(value: unknown, seen: WeakSet<object>): unknown {
	if (typeof value === "string") return redactTokens(value);
	if (typeof value === "bigint") return redactTokens(value.toString());
	if (value === null || typeof value !== "object") {
		if (typeof value === "function" || typeof value === "symbol") {
			return redactTokens(String(value));
		}
		return value;
	}
	if (seen.has(value)) return "[Circular]";
	seen.add(value);
	try {
		if (value instanceof Error) {
			return {
				name: redactTokens(String(value.name)),
				message: redactTokens(String(value.message)),
			};
		}
		if (Array.isArray(value)) return value.map((v) => sanitizeValue(v, seen));
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value)) {
			let item: unknown;
			try {
				item = (value as Record<string, unknown>)[key];
			} catch {
				item = "[Unreadable]";
			}
			out[redactTokens(key)] = sanitizeValue(item, seen);
		}
		return out;
	} finally {
		seen.delete(value);
	}
}

function sanitizeCause(cause: unknown): Error {
	try {
		if (cause instanceof Error) {
			const safe = new Error(redactTokens(String(cause.message)));
			safe.name = redactTokens(String(cause.name));
			safe.stack = `${safe.name}: ${safe.message}`;
			return safe;
		}
		return new Error(redactTokens(String(cause)));
	} catch {
		return new Error("[causa no legible]");
	}
}

export function isErrorCode(code: string): code is ErrorCode {
	return Object.hasOwn(ERROR_EXITS, code);
}

/** Exit code for a code; unknown codes map to INTERNO (70). */
export function exitFor(code: string): number {
	return isErrorCode(code) ? ERROR_EXITS[code] : ERROR_EXITS.INTERNO;
}

export interface MctErrorInit {
	accion?: string;
	etapa?: string;
	detalle?: Record<string, unknown>;
	cause?: unknown;
}

export interface ErrorJson {
	error: {
		codigo: ErrorCode;
		mensaje: string;
		accion?: string;
		etapa?: string;
		detalle?: Record<string, unknown>;
	};
}

export class MctError extends Error {
	readonly codigo: ErrorCode;
	readonly exit: number;
	readonly accion?: string;
	readonly etapa?: string;
	readonly detalle?: Record<string, unknown>;

	constructor(codigo: string, mensaje: string, init: MctErrorInit = {}) {
		super(
			redactTokens(mensaje),
			init.cause === undefined
				? undefined
				: { cause: sanitizeCause(init.cause) },
		);
		this.name = "MctError";
		this.codigo = isErrorCode(codigo) ? codigo : "INTERNO";
		this.exit = exitFor(codigo);
		if (init.accion !== undefined) this.accion = redactTokens(init.accion);
		if (init.etapa !== undefined) this.etapa = init.etapa;
		if (init.detalle !== undefined) {
			this.detalle = sanitizeValue(init.detalle, new WeakSet()) as Record<
				string,
				unknown
			>;
		}
	}

	toJSON(): ErrorJson {
		return {
			error: {
				codigo: this.codigo,
				mensaje: this.message,
				...(this.accion !== undefined && { accion: this.accion }),
				...(this.etapa !== undefined && { etapa: this.etapa }),
				...(this.detalle !== undefined && { detalle: this.detalle }),
			},
		};
	}
}
