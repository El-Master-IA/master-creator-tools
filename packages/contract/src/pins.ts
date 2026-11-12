// Versions that travel inside the package (source: masterplan/proyecto.json).
export const GITLEAKS_VERSION = "8.30.1";
export const GITLEAKS_MAJOR = 8;

export const N8N_IMAGE = "n8nio/n8n";
export const N8N_VERSION = "2.46.6";
export const N8N_DIGEST = [
	"sha256",
	"256a0fca38c4f0ab02524bcebf77b8ed5acc7aa99a28c4cbca7a4034a76d4b97",
].join(":");
export const N8N_IMAGE_REF = `${N8N_IMAGE}:${N8N_VERSION}`;

/** Python images by manifest-list digest (ERR-005; used by the python and static adapters). */
export const PYTHON_IMAGES = {
	"3.13-slim": [
		"sha256",
		"e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
	].join(":"),
	"3.14-slim": [
		"sha256",
		"9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f",
	].join(":"),
	"3.15-slim": [
		"sha256",
		"65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928",
	].join(":"),
} as const;

export const PYTHON_IMAGE_REFS = {
	"3.13-slim": `python:3.13-slim@${PYTHON_IMAGES["3.13-slim"]}`,
	"3.14-slim": `python:3.14-slim@${PYTHON_IMAGES["3.14-slim"]}`,
	"3.15-slim": `python:3.15-slim@${PYTHON_IMAGES["3.15-slim"]}`,
} as const;

/** Installed by pip inside the python verify container (PY-003). */
export const UV_VERSION = "0.13.7";
