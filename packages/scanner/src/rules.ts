/** Reglas de secretos por proveedor del motor propio. Solo patrones; ningún valor real. */
export interface SecretRule {
	readonly id: string;
	readonly pattern: RegExp;
}

export const PROVIDER_RULES: readonly SecretRule[] = [
	{ id: "aws-access-key", pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/g },
	{ id: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
	{
		id: "github-fine-grained-token",
		pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
	},
	{
		id: "stripe-key",
		pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/g,
	},
	{ id: "slack-token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,72}\b/g },
	{ id: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
	{ id: "npm-token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
	{
		id: "private-key",
		pattern: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
	},
	{
		// Legacy `sk-` + 48 or project/service-account keys; `sk-ant-` is Anthropic.
		id: "openai-key",
		pattern:
			/\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]{0,200}\d)[A-Za-z0-9_-]{20,200}(?![A-Za-z0-9_-])/g,
	},
	{
		id: "anthropic-key",
		pattern:
			/\bsk-ant-[a-z]{2,10}\d{2}-[A-Za-z0-9_-]{32,200}(?![A-Za-z0-9_-])/g,
	},
	{
		id: "jwt",
		pattern:
			/\beyJ[A-Za-z0-9_-]{8,2048}\.eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}(?![A-Za-z0-9_-])/g,
	},
	{
		// 40 or 64 hex characters only with a secret/token/key name right before.
		id: "hex-secret",
		pattern:
			/(?<=(?:secret|token|key|passw(?:or)?d|pwd)[\w.-]{0,24}["']?[ \t]{0,4}[:=][ \t]{0,4}["']?)[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?(?![0-9A-Za-z])/gi,
	},
	{
		id: "generic-api-key",
		pattern: /\bapi[_-]?key[-_][A-Za-z0-9]{24,}(?:-[A-Za-z0-9]{1,8})?\b/gi,
	},
];

/** Cadenas que parecen azar pero son huellas: integrity de lockfile y digests de imagen. */
export const DIGEST_PATTERN =
	/(?:\bsha(?:1|224|256|384|512)[-:@])[A-Za-z0-9+/=_-]{20,}/g;
