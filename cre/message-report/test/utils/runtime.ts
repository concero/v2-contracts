import { newTestRuntime, type TestRuntime } from "@chainlink/cre-sdk/test";
import type { GlobalConfig } from "../../helpers";
import { getObjectHash } from "./hash";
import { CHAINS_CONFIG_FIXTURE } from "../fixtures";

const DEFAULT_CONFIG: GlobalConfig = {
	authorizedPublicKey: "0x0000000000000000000000000000000000000000",
	relayerCallbackUrl: "https://relayer-callback",
	chainsConfigUrl: "https://chains.json",
	allowedMessageVersions: [1],
	networkType: "stage",
};

export function createTestRuntime(configOverrides?: Partial<GlobalConfig>): TestRuntime {
	const secrets = new Map([
		["default", new Map([["STAGE_CHAINS_CONFIG_HASH", getObjectHash(CHAINS_CONFIG_FIXTURE)]])],
	]);

	const runtime = newTestRuntime(secrets, {});
	runtime.config = { ...DEFAULT_CONFIG, ...configOverrides };
	return runtime;
}
