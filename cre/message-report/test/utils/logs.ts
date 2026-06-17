import type { TestRuntime } from "@chainlink/cre-sdk/test";

// Prints only when DEBUG env var is set: DEBUG=1 bun test
export function printRuntimeLogs(runtime: TestRuntime, label?: string): void {
	if (process.env.DEBUG) {
		console.log(label ?? "Runtime logs:", runtime.getLogs().join("\n\n"));
	}
}
