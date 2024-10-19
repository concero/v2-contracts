import {
    ConceroMainnetNetworkNames,
    type ConceroNetwork,
    ConceroNetworkNames,
    ConceroTestnetNetworkNames,
    ConceroTestNetworkNames,
    NetworkType,
} from "../types/ConceroNetwork";
import {
    arbitrum,
    arbitrumSepolia,
    avalanche,
    avalancheFuji,
    base,
    baseSepolia,
    mainnet,
    optimism,
    optimismSepolia,
    polygon,
    polygonAmoy,
    sepolia,
} from "viem/chains";
import { rpcUrl, urls } from "./rpcUrls";
import { getEnvVar } from "../utils";
import { localhostViemChain } from "../utils/localhostViemChain";

const DEFAULT_BLOCK_CONFIRMATIONS = 2;
const proxyDeployerPK = getEnvVar("PROXY_DEPLOYER_PRIVATE_KEY");
const deployerPK = getEnvVar("DEPLOYER_PRIVATE_KEY");

export const networkTypes: Record<NetworkType, NetworkType> = {
    mainnet: "mainnet",
    testnet: "testnet",
};

export const networkEnvKeys: Record<ConceroNetworkNames, string> = {
    // mainnets
    mainnet: "MAINNET",
    arbitrum: "ARBITRUM",
    optimism: "OPTIMISM",
    polygon: "POLYGON",
    polygonZkEvm: "POLYGON_ZKEVM",
    avalanche: "AVALANCHE",
    base: "BASE",

    // testnets
    sepolia: "SEPOLIA",
    optimismSepolia: "OPTIMISM_SEPOLIA",
    arbitrumSepolia: "ARBITRUM_SEPOLIA",
    avalancheFuji: "FUJI",
    baseSepolia: "BASE_SEPOLIA",
    polygonAmoy: "POLYGON_AMOY",

    //test
    localhost: "LOCALHOST",
    hardhat: "LOCALHOST",
};

export const testNetwork: Record<ConceroTestNetworkNames, ConceroNetwork> = {
    hardhat: {
        id: Number(process.env.LOCALHOST_FORK_CHAIN_ID),
        name: "hardhat",
        type: networkTypes.testnet,
        accounts: [
            {
                privateKey: deployerPK,
                balance: "10000000000000000000000",
            },
            {
                privateKey: deployerPK,
                balance: "10000000000000000000000",
            },
        ],
        chainSelector: process.env.CL_CCIP_CHAIN_SELECTOR_LOCALHOST as string,
        confirmations: 1,
        viemChain: localhostViemChain,
        forking: {
            url: `https://base-mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
            enabled: true,
            blockNumber: Number(process.env.LOCALHOST_FORK_LATEST_BLOCK_NUMBER),
        },
    },
    localhost: {
        name: "localhost",
        type: networkTypes.testnet,
        id: Number(process.env.LOCALHOST_FORK_CHAIN_ID),
        viemChain: localhostViemChain,
        url: rpcUrl.localhost,
        rpcUrls: [rpcUrl.localhost],
        confirmations: 1,
        chainSelector: process.env.CL_CCIP_CHAIN_SELECTOR_LOCALHOST as string,
        accounts: [deployerPK, proxyDeployerPK],
    },
};

export const testnetNetworks: Record<ConceroTestnetNetworkNames, ConceroNetwork> = {
    sepolia: {
        name: "sepolia",
        type: networkTypes.testnet,
        id: 11155111,
        url: urls.sepolia[0],
        rpcUrls: urls.sepolia,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "16015286601757825753",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: sepolia,
    },
    avalancheFuji: {
        name: "avalancheFuji",
        type: networkTypes.testnet,
        id: 43113,
        url: urls.avalancheFuji[0],
        rpcUrls: urls.avalancheFuji,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "14767482510784806043",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: avalancheFuji,
    },
    optimismSepolia: {
        name: "optimismSepolia",
        type: networkTypes.testnet,
        id: 11155420,
        url: urls.optimismSepolia[0],
        rpcUrls: urls.optimismSepolia,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "5224473277236331295",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: optimismSepolia,
    },
    arbitrumSepolia: {
        name: "arbitrumSepolia",
        type: networkTypes.testnet,
        id: 421614,
        url: urls.arbitrumSepolia[0],
        rpcUrls: urls.arbitrumSepolia,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "3478487238524512106",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: arbitrumSepolia,
    },
    baseSepolia: {
        name: "baseSepolia",
        type: networkTypes.testnet,
        id: 84532,
        url: urls.baseSepolia[0],
        rpcUrls: urls.baseSepolia,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "10344971235874465080",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: baseSepolia,
    },
    polygonAmoy: {
        name: "polygonAmoy",
        type: networkTypes.testnet,
        id: 80002,
        url: urls.polygonAmoy[0],
        rpcUrls: urls.polygonAmoy,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "16281711391670634445",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: polygonAmoy,
    },
};
export const mainnetNetworks: Record<ConceroMainnetNetworkNames, ConceroNetwork> = {
    mainnet: {
        name: "mainnet",
        type: networkTypes.mainnet,
        id: 1,
        url: urls.mainnet[0],
        rpcUrls: urls.mainnet,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "1",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: mainnet,
    },
    base: {
        name: "base",
        type: networkTypes.mainnet,
        id: 8453,
        url: urls.base[0],
        rpcUrls: urls.base,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "15971525489660198786",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: base,
    },
    arbitrum: {
        name: "arbitrum",
        type: networkTypes.mainnet,
        id: 42161,
        url: urls.arbitrum[0],
        rpcUrls: urls.arbitrum,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "4949039107694359620",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: arbitrum,
    },
    polygon: {
        name: "polygon",
        type: networkTypes.mainnet,
        id: 137,
        url: urls.polygon[0],
        rpcUrls: urls.polygon,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "4051577828743386545",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: polygon,
    },
    avalanche: {
        name: "avalanche",
        type: networkTypes.mainnet,
        id: 43114,
        url: urls.avalanche[0],
        rpcUrls: urls.avalanche,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "6433500567565415381",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: avalanche,
    },
    optimism: {
        name: "optimism",
        type: networkTypes.mainnet,
        id: 10,
        url: urls.optimism[0],
        rpcUrls: urls.optimism,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "10",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: optimism,
    },
    polygonZkEvm: {
        id: 137,
        name: "polygonZkEvm",
        type: networkTypes.mainnet,
        url: urls.polygonZkEvm[0],
        rpcUrls: urls.polygonZkEvm,
        accounts: [proxyDeployerPK, deployerPK],
        chainSelector: "137",
        confirmations: DEFAULT_BLOCK_CONFIRMATIONS,
        viemChain: polygon,
    },
};

export const conceroNetworks: Record<ConceroNetworkNames, ConceroNetwork> = {
    ...testnetNetworks,
    ...mainnetNetworks,
    ...testNetwork,
};