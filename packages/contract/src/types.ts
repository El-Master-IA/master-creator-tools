export type Severidad = "critico" | "alto" | "medio" | "bajo";
export type TipoRegla = "secreto" | "pii" | "estructura";

export interface Rule {
	id: string;
	tipo: TipoRegla;
	severidad: Severidad;
	/** Group 1, if present, is the value. */
	patron: RegExp;
}

export type Etapa =
	| "init"
	| "scan"
	| "sanitize"
	| "licenses"
	| "package"
	| "verify"
	| "publish";
export type EstadoEtapa = "pendiente" | "ok" | "bloqueada";

export interface State {
	schemaVersion: number;
	mctVersion: string;
	origen: { tipo: "carpeta" | "github" | "n8n-json"; ref: string };
	adapter: string;
	workSha256: string;
	distSha256: string;
	verificado: { distSha256: string; destino: string; ts: string } | null;
	etapas: Record<Etapa, { estado: EstadoEtapa; ts: string }>;
}

export interface Workspace {
	raiz: string;
	work: string;
	quarantine: string;
	dist: string;
	estado(): Promise<State>;
}

export interface Analysis {
	stack: string[];
	entrypoints: string[];
	envVars: { nombre: string; obligatoria: boolean }[];
	deps: { nombre: string; version: string }[];
	gestor?: "npm" | "pnpm" | "yarn";
	comandos: { install?: string; start?: string; build?: string };
	puerto?: number;
}

export type Change =
	| {
			tipo: "editar";
			ruta: string;
			desde: number;
			hasta: number;
			texto: string;
	  }
	| { tipo: "crear"; ruta: string; contenido: string }
	| { tipo: "borrar"; ruta: string };

export interface VerifySpec {
	imagen: string;
	install?: string[];
	start: string[];
	healthcheck:
		| { tipo: "salida-cero" }
		| { tipo: "http"; puerto: number }
		| { tipo: "n8n-import" };
	timeoutMin: number;
}

export interface PackageHints {
	instalacion: string[];
	uso: string[];
	variables: { nombre: string; descripcion: string; obligatoria: boolean }[];
	requisitos: string[];
}

export interface Adapter {
	id: string;
	detect(dir: string): Promise<number>;
	analyze(ws: Workspace): Promise<Analysis>;
	rules(): Rule[];
	sanitize?(ws: Workspace): Promise<Change[]>;
	generalize?(ws: Workspace): Promise<Change[]>;
	packageHints(a: Analysis): PackageHints;
	verifyCommand(a: Analysis): VerifySpec;
}

export type EstadoHallazgo =
	| "abierto"
	| "resuelto"
	| "falso-positivo"
	| "aceptado"
	| "obsoleto"
	| "aislado";

export interface Finding {
	id: string;
	motor: "mct" | "gitleaks";
	regla: string;
	tipo: "secreto" | "pii" | "estructura" | "binario";
	zona: "work" | "quarantine";
	archivo: string;
	linea: number;
	columna: number;
	/** Masked: at most 4 real characters. */
	fragmento: string;
	severidad: Severidad;
	estado: EstadoHallazgo;
	motivo?: string;
	decidio?: string;
	decididoEn?: string;
}
