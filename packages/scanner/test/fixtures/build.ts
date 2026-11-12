import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { makePii, type PiiKind } from "./pii.js";
import { envExpression, makeSecrets, type SecretKind } from "./secretos.js";

export type FixtureName = "node" | "n8n";
export type Mutation =
	| "plain"
	| "base64"
	| "split-lines"
	| "comment"
	| "env-backup";

export interface TruthSecret {
	readonly kind: SecretKind;
	readonly value: string;
	readonly file: string;
	readonly mutation: Mutation;
}

export interface TruthPii {
	readonly kind: PiiKind;
	readonly value: string;
	readonly file: string;
}

export interface Truth {
	readonly fixture: FixtureName;
	readonly secrets: readonly TruthSecret[];
	readonly pii: readonly TruthPii[];
	/** Lecturas de variables de entorno que el escáner debe poder listar. */
	readonly envReads: readonly {
		readonly name: string;
		readonly file: string;
	}[];
}

export interface Fixture {
	readonly name: FixtureName;
	/** Raíz con `work/`, `quarantine/` y `truth.json`. */
	readonly root: string;
	readonly work: string;
	readonly quarantine: string;
	readonly truth: Truth;
	cleanup(): Promise<void>;
}

export const FIXTURE_NAMES: readonly FixtureName[] = ["node", "n8n"];

type Files = Map<string, string>;

function buildContent(name: FixtureName): {
	work: Files;
	quarantine: Files;
	truth: Truth;
} {
	const [aws, gh, stripe, generic] = makeSecrets();
	const [email, phone, card, ssn, cedula] = makePii();
	if (!aws || !gh || !stripe || !generic) {
		throw new Error("secretos sembrados incompletos");
	}
	if (!email || !phone || !card || !ssn || !cedula) {
		throw new Error("PII sembrada incompleta");
	}

	const work: Files = new Map();
	const quarantine: Files = new Map();
	const readName = "SERVICE_URL";
	const mainFile = name === "node" ? "src/index.js" : "workflow.json";
	const half = Math.floor(stripe.value.length / 2);
	const b64 = Buffer.from(gh.value, "utf8").toString("base64");

	const lines = [
		`const awsKey = "${aws.value}";`,
		`// legacy token: ${generic.value}`,
		`const encoded = "${b64}";`,
		`const stripeKey = "${stripe.value.slice(0, half)}" +`,
		`  "${stripe.value.slice(half)}";`,
		`const url = ${envExpression(readName)};`,
		`const owner = "${email.value}"; // ${phone.value}`,
		`const card = "${card.value}";`,
		`const ssn = "${ssn.value}";`,
		`const cedula = "${cedula.value}";`,
	];

	if (name === "node") {
		work.set(mainFile, `${lines.join("\n")}\n`);
		work.set(
			"package.json",
			`${JSON.stringify({ name: "fixture-node", version: "0.0.0", private: true }, null, 2)}\n`,
		);
	} else {
		const workflow = {
			name: "fixture-n8n",
			nodes: [
				{
					name: "Code",
					type: "n8n-nodes-base.code",
					parameters: { jsCode: lines.join("\n") },
				},
			],
			connections: {},
		};
		work.set(mainFile, `${JSON.stringify(workflow, null, 2)}\n`);
	}

	// El JSON de n8n escapa los saltos de línea; el valor partido sigue partido.
	const tSecrets: TruthSecret[] = [
		{ kind: aws.kind, value: aws.value, file: mainFile, mutation: "plain" },
		{
			kind: generic.kind,
			value: generic.value,
			file: mainFile,
			mutation: "comment",
		},
		{ kind: gh.kind, value: b64, file: mainFile, mutation: "base64" },
		{
			kind: stripe.kind,
			value: stripe.value,
			file: mainFile,
			mutation: "split-lines",
		},
	];

	// Mutación .env.backup en cuarentena: se lee solo en memoria.
	const backup = makeSecrets()[3];
	if (!backup) throw new Error("secreto de respaldo ausente");
	const backupValue = `${backup.value}-bk`;
	quarantine.set(".env.backup", `BACKUP_TOKEN=${backupValue}\n`);
	tSecrets.push({
		kind: backup.kind,
		value: backupValue,
		file: ".env.backup",
		mutation: "env-backup",
	});

	const tPii: TruthPii[] = [email, phone, card, ssn, cedula].map((p) => ({
		kind: p.kind,
		value: p.value,
		file: mainFile,
	}));

	return {
		work,
		quarantine,
		truth: {
			fixture: name,
			secrets: tSecrets,
			pii: tPii,
			envReads: [{ name: readName, file: mainFile }],
		},
	};
}

async function writeAll(base: string, files: Files): Promise<void> {
	await mkdir(base, { recursive: true });
	for (const [rel, content] of files) {
		const target = join(base, rel);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, content, "utf8");
	}
}

/** Construye un proyecto falso en un directorio temporal, con su truth.json. */
export async function buildFixture(name: string): Promise<Fixture> {
	if (!(FIXTURE_NAMES as readonly string[]).includes(name)) {
		throw new Error(
			`Fixture inexistente: "${name}". Disponibles: ${FIXTURE_NAMES.join(", ")}`,
		);
	}
	const fixtureName = name as FixtureName;
	const { work, quarantine, truth } = buildContent(fixtureName);
	const root = await mkdtemp(join(tmpdir(), `mct-fixture-${fixtureName}-`));
	await writeAll(join(root, "work"), work);
	await writeAll(join(root, "quarantine"), quarantine);
	// Clave HMAC del workspace falso (SCAN-015): `scan` la lee de `<raiz>/clave`.
	await writeFile(join(root, "clave"), randomBytes(32));
	await writeFile(
		join(root, "truth.json"),
		`${JSON.stringify(truth, null, 2)}\n`,
		"utf8",
	);
	return {
		name: fixtureName,
		root,
		work: join(root, "work"),
		quarantine: join(root, "quarantine"),
		truth,
		cleanup: () => rm(root, { recursive: true, force: true }),
	};
}
