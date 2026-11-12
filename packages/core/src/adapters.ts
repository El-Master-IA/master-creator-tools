import { genericAdapter } from "@mct/adapter-generic/index";
import { n8nAdapter } from "@mct/adapter-n8n/index";
import { nodeAdapter } from "@mct/adapter-node/index";
import { pythonAdapter } from "@mct/adapter-python/index";
import { staticAdapter } from "@mct/adapter-static/index";
import type { Adapter } from "@mct/contract/types";

/** Every built-in adapter (DET-001). One registry so no stage forgets one. */
export const ADAPTERS: readonly Adapter[] = [
	nodeAdapter,
	n8nAdapter,
	pythonAdapter,
	staticAdapter,
	genericAdapter,
];

/** The built-in adapter with this id, or undefined. */
export function adapterById(id: string): Adapter | undefined {
	return ADAPTERS.find((a) => a.id === id);
}
