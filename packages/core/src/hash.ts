import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";

/**
 * Tree hash (datos.md): sha256 over sorted relative paths + content + file mode.
 * Symlinks are never followed; they are rejected.
 */
export async function hashTree(dir: string): Promise<string> {
	const files: string[] = [];
	await collect(dir, "", files);
	files.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	const hash = createHash("sha256");
	for (const rel of files) {
		const full = join(dir, rel);
		const info = await lstat(full);
		const content = await readFile(full);
		const mode = (info.mode & 0o777).toString(8).padStart(4, "0");
		hash.update(`${rel.length}:${rel}\0${mode}\0${content.length}\0`);
		hash.update(content);
		hash.update("\0");
	}
	return hash.digest("hex");
}

async function collect(
	root: string,
	rel: string,
	out: string[],
): Promise<void> {
	const entries = await readdir(join(root, rel), { withFileTypes: true });
	for (const entry of entries) {
		const child = rel === "" ? entry.name : `${rel}/${entry.name}`;
		if (entry.isSymbolicLink()) {
			throw new MctError(
				"WORKSPACE_INVALIDO",
				"Hay un enlace simbólico en el árbol",
				{
					accion: "Elimina el enlace simbólico y vuelve a intentarlo",
					detalle: { ruta: child },
				},
			);
		}
		if (entry.isDirectory()) await collect(root, child, out);
		else if (entry.isFile()) out.push(child);
	}
}
