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
	/** destino: "local", an SSH alias or "(omitido)". */
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
	gestor?: "npm" | "pnpm" | "yarn" | "uv" | "pip" | "poetry";
	lenguaje?: string;
	requiresPython?: string;
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

/** A step allowed to exit non-zero: it emits avisoSiFalla instead of blocking. */
export interface VerifyStep {
	argv: string[];
	avisoSiFalla: string;
}

export interface VerifySpec {
	imagen: string;
	install?: string[];
	/** One argv, or a sequence (each step runs in order with --network none). */
	start: string[] | Array<string[] | VerifyStep>;
	healthcheck:
		| { tipo: "salida-cero" }
		| {
				tipo: "http";
				puerto: number;
				ruta?: string;
				aceptar?: Array<number | "2xx" | "3xx" | "4xx" | "5xx">;
				cuerpoContiene?: string;
				rutasExtra?: string[];
		  }
		| { tipo: "n8n-import" };
	/** Fixed warning keys shown by verify (e.g. verify.pipCheck). */
	avisos?: string[];
	timeoutMin: number;
}

export interface PackageHints {
	instalacion: string[];
	uso: string[];
	variables: { nombre: string; descripcion: string; obligatoria: boolean }[];
	requisitos: string[];
}

/** `mct.config.json` › `readme.contenido` (CFG-003): text written by a person, rendered by PKG-008. */
export interface ReadmeContenido {
	promesa: string;
	porQueExiste: string;
	queObtienes: string[];
	prompt: string;
	queNecesitas: { que: string; paraQue: string; costo: string }[];
	comoFunciona: string;
	faq: { p: string; r: string }[];
	siAlgoSaleMal: { sintoma: string; solucion: string }[];
	buenasPracticas: string[];
	creditos: string[];
	repo?: string;
	laboratorio?: string;
}

/** `mct.config.json` › `readme` (CFG-003). */
export type ReadmeConfig =
	| { plantilla: "estandar" }
	| { plantilla: "el-master-ia"; contenido: ReadmeContenido };

export interface Adapter {
	id: string;
	detect(dir: string): Promise<number>;
	analyze(ws: Workspace): Promise<Analysis>;
	rules(): Rule[];
	sanitize?(ws: Workspace): Promise<Change[]>;
	generalize?(ws: Workspace): Promise<Change[]>;
	packageHints(a: Analysis): PackageHints;
	verifyCommand(a: Analysis): VerifySpec | null;
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
	via?: "tty" | "archivo" | "auto-fixtures";
	decidio?: string;
	decididoEn?: string;
}
