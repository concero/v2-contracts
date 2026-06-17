import { HttpActionsMock } from "@chainlink/cre-sdk/test";
import { encodeJsonBody } from "./payload";

type ResponseLike = { statusCode: number; headers: Record<string, string>; body: Uint8Array };
type HandlerFn = (url: string, body: string) => ResponseLike;

export interface MockHandlers {
	chainsJson: HandlerFn;
	getLogs: HandlerFn;
	blockNumber: HandlerFn;
	getBlockByNumber: HandlerFn;
	relayerCallback: HandlerFn;
}

export const defaultMockHandlers: MockHandlers = {
	chainsJson: () => ({ statusCode: 200, headers: {}, body: encodeJsonBody({}) }),
	getLogs: (_url, _) => {
		const logs: any = [];
		return {
			statusCode: 200,
			headers: {},
			body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: logs }),
		};
	},
	blockNumber: () => ({
		statusCode: 200,
		headers: {},
		body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: "0x0" }),
	}),
	getBlockByNumber: () => ({
		statusCode: 200,
		headers: {},
		body: encodeJsonBody({ jsonrpc: "2.0", id: 1, result: "0x0" }),
	}),
	relayerCallback: () => ({
		statusCode: 200,
		headers: {},
		body: encodeJsonBody({}),
	}),
};

export function setupHttpMock(overrides?: Partial<MockHandlers>): HttpActionsMock {
	const handlers = { ...defaultMockHandlers, ...overrides };
	const httpMock = HttpActionsMock.testInstance();

	httpMock.sendRequest = input => {
		const url = input.url;
		const body = input.body ? new TextDecoder().decode(input.body) : "";

		if (url.includes("chains.json")) return handlers.chainsJson(url, body);
		if (body.includes("eth_getLogs")) return handlers.getLogs(url, body);
		if (body.includes("eth_blockNumber")) return handlers.blockNumber(url, body);
		if (body.includes("eth_getBlockByNumber")) return handlers.getBlockByNumber(url, body);
		if (url.includes("relayer-callback")) return handlers.relayerCallback(url, body);

		throw new Error(`Unmocked request: ${url} body: ${body}`);
	};

	return httpMock;
}
