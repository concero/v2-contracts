import type { HTTPPayload } from "@chainlink/cre-sdk";

export function createPayload(data: object): HTTPPayload {
	return {
		input: encodeJsonBody(data),
	} as HTTPPayload;
}

export function encodeJsonBody(data: unknown): Uint8Array {
	return new TextEncoder().encode(JSON.stringify(data));
}
