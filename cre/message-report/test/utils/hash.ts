import { createHash } from "crypto";

// sha256(JSON.stringify(obj)) → "0x<hex>"
export function getObjectHash(obj: unknown): string {
	const hash = createHash("sha256").update(JSON.stringify(obj)).digest("hex");
	return `0x${hash}`;
}
