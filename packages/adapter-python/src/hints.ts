import type { Analysis, PackageHints } from "@mct/contract/types";

function requisito(a: Analysis): string {
	const req = a.requiresPython;
	if (!req) return "Python >= 3.13";
	// A `.python-version` pin is appended as ",==X.Y.*": show only the declared range.
	return `Python ${req.replace(/,==\d+\.\d+\.\*$/, "")}`;
}

function usoDe(a: Analysis): string[] {
	const entry = a.entrypoints[0];
	if (entry === undefined) return [];
	if (entry === "manage.py") return ["python manage.py runserver"];
	return [entry.endsWith(".py") ? `python ${entry}` : entry];
}

export function pythonPackageHints(a: Analysis): PackageHints {
	const instalacion: string[] = [];
	const install = a.comandos.install;
	if (a.gestor === "uv") instalacion.push("uv sync");
	else if (a.gestor === "poetry") instalacion.push("pip install .");
	else if (install) instalacion.push(install);
	return {
		instalacion,
		uso: usoDe(a),
		variables: a.envVars.map((v) => ({
			nombre: v.nombre,
			descripcion: v.obligatoria
				? "Obligatoria."
				: "Opcional (tiene valor por defecto o es de ejemplo).",
			obligatoria: v.obligatoria,
		})),
		requisitos: [requisito(a)],
	};
}
