export const VALID_MSG_ID_A = "0x92398449c1d2c1d147042bf862d5315959d4a341ac7c984ae0283424b2842942";
export const VALID_MSG_ID_B = "0xa46bea5f1fd3bd3a9ba146e5b66c36a5d152b3073218b7a4ca774b4a411bf515";

export const VALID_BATCH_INPUT = {
	batch: [
		{
			messageId: VALID_MSG_ID_A,
			srcChainSelector: 421614,
			blockNumber: "237563545",
		},
		{
			messageId: VALID_MSG_ID_B,
			srcChainSelector: 421614,
			blockNumber: "237563545",
		},
	],
};
