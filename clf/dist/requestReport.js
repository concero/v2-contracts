(() => {
	const chainMap = {
		['14767482510784806043']: {
			urls: ['https://rpc.ankr.com/avalanche_fuji'],
			confirmations: 3n,
			chainId: '0xa869',
		},
		['16015286601757825753']: {
			urls: ['https://ethereum-sepolia-rpc.publicnode.com', 'https://ethereum-sepolia.blockpi.network/v1/rpc/public'],
			confirmations: 3n,
			chainId: '0xaa36a7',
		},
		['3478487238524512106']: {
			urls: ['https://rpc.ankr.com/arbitrum_sepolia', 'https://arbitrum-sepolia-rpc.publicnode.com'],
			confirmations: 3n,
			chainId: '0x66eee',
		},
		['10344971235874465080']: {
			urls: ['https://rpc.ankr.com/base_sepolia', 'https://base-sepolia-rpc.publicnode.com'],
			confirmations: 3n,
			chainId: '0x14a34',
		},
		['5224473277236331295']: {
			urls: ['https://rpc.ankr.com/optimism_sepolia', 'https://optimism-sepolia-rpc.publicnode.com'],
			confirmations: 3n,
			chainId: '0xaa37dc',
		},
		['16281711391670634445']: {
			urls: ['https://polygon-amoy-bor-rpc.publicnode.com', 'https://rpc.ankr.com/polygon_amoy'],
			confirmations: 3n,
			chainId: '0x13882',
		},
		['4051577828743386545']: {
			urls: ['https://polygon-bor-rpc.publicnode.com', 'https://rpc.ankr.com/polygon'],
			confirmations: 3n,
			chainId: '0x89',
		},
		['4949039107694359620']: {
			urls: ['https://arbitrum-rpc.publicnode.com', 'https://rpc.ankr.com/arbitrum'],
			confirmations: 3n,
			chainId: '0xa4b1',
		},
		['15971525489660198786']: {
			urls: ['https://base-rpc.publicnode.com', 'https://rpc.ankr.com/base'],
			confirmations: 3n,
			chainId: '0x2105',
		},
		['6433500567565415381']: {
			urls: ['https://avalanche-c-chain-rpc.publicnode.com', 'https://rpc.ankr.com/avalanche'],
			confirmations: 3n,
			chainId: '0xa86a',
		},
	};
	class FunctionsJsonRpcProvider extends ethers.JsonRpcProvider {
		constructor(url) {
			super(url);
			this.url = url;
		}
		async _send(payload) {
			if (payload.method === 'eth_chainId') {
				return [{jsonrpc: '2.0', id: payload.id, result: chainMap[srcChainSelector].chainId}];
			}
			const resp = await fetch(this.url, {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify(payload),
			});
			const result = await resp.json();
			if (payload.length === undefined) {
				return [result];
			}
			return result;
		}
	}
})();