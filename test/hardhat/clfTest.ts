import { encodeAbiParameters } from "viem";
import { CLFType, runCLFSimulation } from "../../utils/runCLFSimulation";
import { conceroMessageAbi } from "./utils/conceroMessageAbi";
import { IConceroMessageRequest } from "./utils/types";
import { getEnvVar } from "../../utils";

// from clf
// 0xa947cb487701a1bc7b32ab45fcb198d20e941c6ad456465a735e6c1b855b162200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000008f90b8876dee6538000000000000000000000000000000000000000000000000304611b6affba76a000000000000000000000000dddddb8a8e41c194ac6542a0ad7ba663a72741e0000000000000000000000000dddddb8a8e41c194ac6542a0ad7ba663a72741e0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
// 0xa947cb487701a1bc7b32ab45fcb198d20e941c6ad456465a735e6c1b855b162200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000008f90b8876dee6538000000000000000000000000000000000000000000000000304611b6affba76a000000000000000000000000dddddb8a8e41c194ac6542a0ad7ba663a72741e0000000000000000000000000dddddb8a8e41c194ac6542a0ad7ba663a72741e0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
// from contract

describe("Concero Router", () => {
    it("Should deploy the contract and call sendMessage", async function () {
        const { abi: conceroRouterAbi } = await import(
            "../../../v2-operators/src/relayer/a/constants/ConceroRouter.json"
        );

        // const message = {
        //     id: "0xa947cb487701a1bc7b32ab45fcb198d20e941c6ad456465a735e6c1b855b1622",
        //     srcChainSelector: BigInt(process.env.CL_CCIP_CHAIN_SELECTOR_BASE_SEPOLIA),
        //     dstChainSelector: BigInt(process.env.CL_CCIP_CHAIN_SELECTOR_ARBITRUM_SEPOLIA),
        //     receiver: "0xdddddb8a8e41c194ac6542a0ad7ba663a72741e0",
        //     sender: "0xdddddb8a8e41c194ac6542a0ad7ba663a72741e0",
        //     tokenAmounts: [],
        //     relayers: [],
        //     data: "0x01",
        //     extraArgs: "0x",
        // };

        const message: IConceroMessageRequest = {
            id: "0x262f761b31058aa24a07861b230c9c50821ae91574fc94b15e9423160f46addd",
            feeToken: "0x0000000000000000000000000000000000000000",
            srcChainSelector: BigInt(process.env.CL_CCIP_CHAIN_SELECTOR_BASE_SEPOLIA),
            dstChainSelector: getEnvVar("CL_CCIP_CHAIN_SELECTOR_ARBITRUM_SEPOLIA"),
            receiver: getEnvVar("CONCERO_DEMO_CLIENT_ARBITRUM_SEPOLIA"),
            tokenAmounts: [{ token: "0x0000000000000000000000000000000000000000", amount: 10000000n }],
            sender: "0xdddddb8a8e41c194ac6542a0ad7ba663a72741e0",
            relayers: [0],
            data: encodeAbiParameters([{ type: "string", name: "data" }], ["Hello world!"]),
            extraArgs: encodeAbiParameters([{ type: "uint32", name: "extraArgs" }], [300000n]),
        };

        const encodedMessage = encodeAbiParameters(conceroMessageAbi, [
            {
                srcChainSelector: message.srcChainSelector,
                dstChainSelector: message.dstChainSelector,
                receiver: message.receiver,
                sender: message.sender,
                tokenAmounts: message.tokenAmounts,
                relayers: message.relayers,
                data: message.data,
                extraArgs: message.extraArgs,
            },
        ]);

        const results = await runCLFSimulation(CLFType.requestReport, ["0x0", "0x0", message.id, encodedMessage], {
            print: false,
            rebuild: true,
        });

        console.log(results);
    });
});
