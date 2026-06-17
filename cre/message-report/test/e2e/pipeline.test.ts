import { describe, expect } from "bun:test";
import { test } from "@chainlink/cre-sdk/test";
import { pipeline } from "../../pipeline";
import {
	CHAINS_CONFIG_FIXTURE,
	TEST_LOG_A,
	TEST_LOG_B,
	VALID_BATCH_INPUT,
	VALID_MSG_ID_A,
	VALID_MSG_ID_B,
} from "../fixtures";
import {
	createPayload,
	setupHttpMock,
	createTestRuntime,
	printRuntimeLogs,
	encodeJsonBody,
} from "../utils";

describe("pipeline e2e", () => {
	test("returns success for valid batch", async () => {
		setupHttpMock({
			chainsJson: () => ({
				statusCode: 200,
				headers: {},
				body: encodeJsonBody(CHAINS_CONFIG_FIXTURE),
			}),
			getLogs: (_url, body) => {
				const logs = [];
				if (body.includes(VALID_MSG_ID_A)) logs.push(TEST_LOG_A);
				if (body.includes(VALID_MSG_ID_B)) logs.push(TEST_LOG_B);
				return {
					statusCode: 200,
					headers: {},
					body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: logs }),
				};
			},
			blockNumber: () => ({
				statusCode: 200,
				headers: {},
				body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: "0xe28ee9c" }),
			}),
			getBlockByNumber: () => ({
				statusCode: 200,
				headers: {},
				body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: "0xe28ee99" }),
			}),
			relayerCallback: () => ({
				statusCode: 200,
				headers: {},
				body: encodeJsonBody({ success: true }),
			}),
		});

		const runtime = createTestRuntime();
		const result = await pipeline(runtime, createPayload(VALID_BATCH_INPUT));

		printRuntimeLogs(runtime);
		expect(result).toBe("success");
	});
});
