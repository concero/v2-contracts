export const CHAINS_CONFIG_FIXTURE = {
	"421614": {
		id: "421614",
		chainSelector: 421614,
		name: "arbitrumSepolia",
		isTestnet: true,
		finalityTagEnabled: true,
		isFinalitySupported: true,
		minBlockConfirmations: 3,
		rpcUrls: [""],
		blockExplorers: [],
		nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
		deployments: {
			router: "0x85d41c3aEB692e505bEE9820F938b7BD5642e95A",
			relayerLib: "0x00Aa11B566e7d854ADdBFea6E8e27127aD53072e",
			validatorLib: "0x8339f88B26B0a8cDbF2F97A827A1015E11C7c918",
		},
	},
};
