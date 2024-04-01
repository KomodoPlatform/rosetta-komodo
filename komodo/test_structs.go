package komodo

import (
	"github.com/coinbase/rosetta-sdk-go/types"
)

var allTheAboveBlockIdentifier = &types.BlockIdentifier{
	Hash:  "00055f664714ef53c85997bd69188e73c745c15d858add9f0571f409f08df76e",
	Index: 1237997,
}

var allTheAboveBlock = &Block{
	Hash:              "00055f664714ef53c85997bd69188e73c745c15d858add9f0571f409f08df76e",
	Height:            1237997,
	PreviousBlockHash: "000666e8a01c6cc677c56d25d28bfee94f1df6ca00b7c80885bc0f347380013d",
	Time:              1680119627,
	Nonce:             "070000000000000000000000000000000000000000000000000000a8feffff67",
	MerkleRoot:        "a2a7f146ecf8da7fee72b086c2f047f447206c98fb519145d2ae19a925020c5e",
	Version:           3,
	Size:              5999,
	Bits:              "1f0d7168",
	Difficulty:        152.3467332576618,
	Txs: []*Transaction{
		{
			Hex:      "",
			Hash:     "575cd2b02c30cfa5cd37b784c44f73f6fecc6e3ac4fdfdbae090c066a4ce68bb",
			Size:     261,
			Vsize:    0,
			Version:  1,
			Locktime: 0,
			Inputs: []*Input{
				{
					Sequence: 4294967295,
					Coinbase: "03ede3120044656661756c7420732d6e6f6d7020706f6f6c2068747470733a2f2f6769746875622e636f6d2f732d6e6f6d702f732d6e6f6d702f77696b692f496e73696768742d706f6f6c2d6c696e6b",
				},
			},
			Outputs: []*Output{
				{
					Value: 3.75,
					Index: 0,
					ScriptPubKey: &ScriptPubKey{
						ASM:          "OP_DUP OP_HASH160 da5bf5898d9e1bd7a892eeab7dd35354d6ffcd0a OP_EQUALVERIFY OP_CHECKSIG",
						Hex:          "76a914da5bf5898d9e1bd7a892eeab7dd35354d6ffcd0a88ac",
						RequiredSigs: 1,
						Type:         "pubkeyhash",
						Addresses: []string{
							"RVBmYmU2NBGQwfexrnUNwZF6i4HwXYT9Jm",
						},
					},
				},
				{
					Value: 1.25,
					Index: 1,
					ScriptPubKey: &ScriptPubKey{
						ASM:          "OP_HASH160 8c884c4f61a6ad2dced9f820c6976397f7e4095b OP_EQUAL",
						Hex:          "a9148c884c4f61a6ad2dced9f820c6976397f7e4095b87",
						RequiredSigs: 1,
						Type:         "scripthash",
						Addresses: []string{
							"RN6FxXf5bs2zSSkZCTgEpeiFG9xsKBeVVp",
						},
					},
				},
			},
			Joinsplits: []*Joinsplit{},
		},
	},
}

var allTheAboveCoins = map[string]*types.AccountCoin{
	"daf5e1b9aef597d666583e311b5e507d27a6d52adc12842a238fa73d2b22667f:0": {
		Account: &types.AccountIdentifier{
			Address: "RJNSzGwJjeWUt3ihrC4Brvq7taL45dV3wP",
		},
		Coin: &types.Coin{
			CoinIdentifier: &types.CoinIdentifier{
				Identifier: "daf5e1b9aef597d666583e311b5e507d27a6d52adc12842a238fa73d2b22667f:0",
			},
			Amount: &types.Amount{
				Value:    "1700000000",
				Currency: MainnetCurrency,
			},
		},
	},
}

var allTheAboveExpectedBlock = &types.Block{
	BlockIdentifier: allTheAboveBlockIdentifier,
	ParentBlockIdentifier: &types.BlockIdentifier{
		Hash:  "000666e8a01c6cc677c56d25d28bfee94f1df6ca00b7c80885bc0f347380013d",
		Index: 1237996,
	},
	Timestamp: 1680119627000,
	Transactions: []*types.Transaction{
		//normal tx with coinbase
		{
			TransactionIdentifier: &types.TransactionIdentifier{
				Hash: "575cd2b02c30cfa5cd37b784c44f73f6fecc6e3ac4fdfdbae090c066a4ce68bb",
			},
			Operations: []*types.Operation{
				{
					OperationIdentifier: &types.OperationIdentifier{
						Index:        0,
						NetworkIndex: Int64Pointer(0),
					},
					Type:   CoinbaseOpType,
					Status: types.String(SuccessStatus),
					Metadata: MustMarshalMap(&OperationMetadata{
						Coinbase: "03ede3120044656661756c7420732d6e6f6d7020706f6f6c2068747470733a2f2f6769746875622e636f6d2f732d6e6f6d702f732d6e6f6d702f77696b692f496e73696768742d706f6f6c2d6c696e6b",
						Sequence: 4294967295,
					}),
				},
				{
					OperationIdentifier: &types.OperationIdentifier{
						Index:        1,
						NetworkIndex: Int64Pointer(0),
					},
					Type:   OutputOpType,
					Status: types.String(SuccessStatus),
					Account: &types.AccountIdentifier{
						Address: "RVBmYmU2NBGQwfexrnUNwZF6i4HwXYT9Jm", // nolint
					},
					Amount: &types.Amount{
						Value:    "375000000",
						Currency: MainnetCurrency,
					},
					CoinChange: &types.CoinChange{
						CoinAction: types.CoinCreated,
						CoinIdentifier: &types.CoinIdentifier{
							Identifier: "575cd2b02c30cfa5cd37b784c44f73f6fecc6e3ac4fdfdbae090c066a4ce68bb:0",
						},
					},
					Metadata: MustMarshalMap(&OperationMetadata{
						ScriptPubKey: &ScriptPubKey{
							ASM:          "OP_DUP OP_HASH160 da5bf5898d9e1bd7a892eeab7dd35354d6ffcd0a OP_EQUALVERIFY OP_CHECKSIG",
							Hex:          "76a914da5bf5898d9e1bd7a892eeab7dd35354d6ffcd0a88ac",
							RequiredSigs: 1,
							Type:         "pubkeyhash",
							Addresses: []string{
								"RVBmYmU2NBGQwfexrnUNwZF6i4HwXYT9Jm",
							},
						},
					}),
				},
				{
					OperationIdentifier: &types.OperationIdentifier{
						Index:        2,
						NetworkIndex: Int64Pointer(1),
					},
					Type:   OutputOpType,
					Status: types.String(SuccessStatus),
					Account: &types.AccountIdentifier{
						Address: "RN6FxXf5bs2zSSkZCTgEpeiFG9xsKBeVVp", // nolint
					},
					Amount: &types.Amount{
						Value:    "125000000",
						Currency: MainnetCurrency,
					},
					CoinChange: &types.CoinChange{
						CoinAction: types.CoinCreated,
						CoinIdentifier: &types.CoinIdentifier{
							Identifier: "575cd2b02c30cfa5cd37b784c44f73f6fecc6e3ac4fdfdbae090c066a4ce68bb:1",
						},
					},
					Metadata: MustMarshalMap(&OperationMetadata{
						ScriptPubKey: &ScriptPubKey{
							ASM:          "OP_HASH160 8c884c4f61a6ad2dced9f820c6976397f7e4095b OP_EQUAL",
							Hex:          "a9148c884c4f61a6ad2dced9f820c6976397f7e4095b87",
							RequiredSigs: 1,
							Type:         "scripthash",
							Addresses: []string{
								"RN6FxXf5bs2zSSkZCTgEpeiFG9xsKBeVVp",
							},
						},
					}),
				},
			},
			Metadata: MustMarshalMap(&TransactionMetadata{
				Size:    261,
				Version: 1,
			}),
		},
	},
	Metadata: MustMarshalMap(&BlockMetadata{
		Size:       5999,
		Version:    3,
		MerkleRoot: "a2a7f146ecf8da7fee72b086c2f047f447206c98fb519145d2ae19a925020c5e",
		Nonce:      "070000000000000000000000000000000000000000000000000000a8feffff67",
		Bits:       "1f0d7168",
		Difficulty: 152.3467332576618,
	}),
}
