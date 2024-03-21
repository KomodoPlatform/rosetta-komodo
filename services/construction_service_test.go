// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package services

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/DeckerSU/rosetta-komodo/configuration"
	"github.com/DeckerSU/rosetta-komodo/komodo"
	mocks "github.com/DeckerSU/rosetta-komodo/mocks/services"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

func forceHexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %s", s)
	}

	return b
}

func forceMarshalMap(t *testing.T, i interface{}) map[string]interface{} {
	m, err := types.MarshalMap(i)
	if err != nil {
		t.Fatalf("could not marshal map %s", types.PrintStruct(i))
	}

	return m
}

func TestConstructionService(t *testing.T) {
	networkIdentifier = &types.NetworkIdentifier{
		Network:    komodo.TestnetNetwork,
		Blockchain: komodo.Blockchain,
	}

	cfg := &configuration.Configuration{
		Mode:     configuration.Online,
		Network:  networkIdentifier,
		Params:   komodo.TestnetParams,
		Currency: komodo.TestnetCurrency,
	}

	mockIndexer := &mocks.Indexer{}
	mockClient := &mocks.Client{}
	servicer := NewConstructionAPIService(cfg, mockClient, mockIndexer)
	ctx := context.Background()

	// Test Derive
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			"02a854251adfee222bede8396fed0756985d4ea905f72611740867c7a4ad6488c1",
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
		},
	}, deriveResponse)

	// Test Preprocess
	ops := []*types.Operation{
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Type: komodo.InputOpType,
			Account: &types.AccountIdentifier{
				Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
			},
			Amount: &types.Amount{
				Value:    "-7777",
				Currency: komodo.TestnetCurrency,
			},
			CoinChange: &types.CoinChange{
				CoinIdentifier: &types.CoinIdentifier{
					Identifier: "2916417b6e4f81ea0edf75249793b2949cc35aa512f5e4e739d5712385104ee7:0",
				},
				CoinAction: types.CoinSpent,
			},
		},
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 1,
			},
			Type: komodo.OutputOpType,
			Account: &types.AccountIdentifier{
				Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
			},
			Amount: &types.Amount{
				Value:    "7777",
				Currency: komodo.TestnetCurrency,
			},
		},
	}
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
		},
	)
	assert.Nil(t, err)
	options := &preprocessOptions{
		Coins: []*types.Coin{
			{
				CoinIdentifier: &types.CoinIdentifier{
					Identifier: "2916417b6e4f81ea0edf75249793b2949cc35aa512f5e4e739d5712385104ee7:0",
				},
				Amount: &types.Amount{
					Value:    "-7777",
					Currency: komodo.TestnetCurrency,
				},
			},
		},
		EstimatedSize: 211,
	}
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &constructionMetadata{
		ScriptPubKeys: []*komodo.ScriptPubKey{
			{
				ASM:          "OP_DUP OP_HASH160 dc5abb3c56eba571a0910fe18fa8f205d29a06e3 OP_EQUALVERIFY OP_CHECKSIG",
				Hex:          "76a914dc5abb3c56eba571a0910fe18fa8f205d29a06e388ac",
				RequiredSigs: 1,
				Type:         "pubkeyhash",
				Addresses: []string{
					"RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
				},
			},
		},
		ExpiryHeight: 3854904, //3856307
	}

	// Normal Fee
	mockIndexer.On(
		"GetScriptPubKeys",
		ctx,
		options.Coins,
	).Return(
		metadata.ScriptPubKeys,
		nil,
	).Once()
	mockClient.On(
		"SuggestedFeeRate",
		ctx,
		defaultConfirmationTarget,
	).Return(
		komodo.MinFeeRate*10,
		nil,
	).Once()
	mockClient.On(
		"GetBestBlock",
		ctx).Return(
		int64(3854703), nil).Twice()

	// mockClient.On(
	// 	"GetHashFromIndex",
	// 	ctx,
	// 	int64(3854703)).Return(
	// 	"0000000031b29d4e99d737cfcf1f2d09d988498c21c590614e9fd932a65d8d8d", nil).Twice()

	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "2110",
				Currency: komodo.TestnetCurrency,
			},
		},
	}, metadataResponse)

	// Low Fee
	mockIndexer.On(
		"GetScriptPubKeys",
		ctx,
		options.Coins,
	).Return(
		metadata.ScriptPubKeys,
		nil,
	).Once()
	mockClient.On(
		"SuggestedFeeRate",
		ctx,
		defaultConfirmationTarget,
	).Return(
		komodo.MinFeeRate,
		nil,
	).Once()
	metadataResponse, err = servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "211",
				Currency: komodo.TestnetCurrency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	val0 := int64(0)
	parseOps := []*types.Operation{
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        0,
				NetworkIndex: &val0,
			},
			Type: komodo.InputOpType,
			Account: &types.AccountIdentifier{
				Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
			},
			Amount: &types.Amount{
				Value:    "-7777",
				Currency: komodo.TestnetCurrency,
			},
			CoinChange: &types.CoinChange{
				CoinIdentifier: &types.CoinIdentifier{
					Identifier: "2916417b6e4f81ea0edf75249793b2949cc35aa512f5e4e739d5712385104ee7:0",
				},
				CoinAction: types.CoinSpent,
			},
		},
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        1,
				NetworkIndex: &val0,
			},
			Type: komodo.OutputOpType,
			Account: &types.AccountIdentifier{
				Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
			},
			Amount: &types.Amount{
				Value:    "7777",
				Currency: komodo.TestnetCurrency,
			},
		},
	}

	assert.Nil(t, err)

	signingPayload := &types.SigningPayload{
		Bytes: forceHexDecode(
			t,
			"8c192b74568c8ab8435611fd0ddb99dab80e53978046d56de7795cd37a0b5a95",
		),
		AccountIdentifier: &types.AccountIdentifier{
			Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
		},
		SignatureType: types.Ecdsa,
	}

	unsignedRaw := "7b227472616e73616374696f6e223a2230343030303038303835323032663839303165373465313038353233373164353339653765346635313261353561633339633934623239333937323437356466306565613831346636653762343131363239303030303030303030306666666666666666303136313165303030303030303030303030313937366139313464633561626233633536656261353731613039313066653138666138663230356432396130366533383861633030303030303030333864323361303030303030303030303030303030303030303030303030222c227363726970745075624b657973223a5b7b2261736d223a224f505f445550204f505f484153483136302064633561626233633536656261353731613039313066653138666138663230356432396130366533204f505f455155414c564552494659204f505f434845434b534947222c22686578223a223736613931346463356162623363353665626135373161303931306665313866613866323035643239613036653338386163222c2272657153696773223a312c2274797065223a227075626b657968617368222c22616464726573736573223a5b2252564e4b5272327578504d784a654477466e544b6a6474694c74637337557a435a6e225d7d5d2c22696e7075745f616d6f756e7473223a5b222d37373737225d2c22696e7075745f616464726573736573223a5b2252564e4b5272327578504d784a654477466e544b6a6474694c74637337557a435a6e225d7d"

	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            []*types.SigningPayload{signingPayload},
	}, payloadsResponse)

	// Test Parse Unsigned
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
	}, parseUnsignedResponse)

	// Test Combine
	signedRaw := "7b227472616e73616374696f6e223a22303430303030383038353230326638393031653734653130383532333731643533396537653466353132613535616333396339346232393339373234373564663065656138313466366537623431313632393030303030303030366134373330343430323230306631653663653332373864336164383366383764656666656331633036616338333030353930373762333532343634376137373235396361323834616435633032323034306434343833636365666562333636626466633365303632336466353661666262316436396362613435343931303761623863363435336330336363393139303132313032613835343235316164666565323232626564653833393666656430373536393835643465613930356637323631313734303836376337613461643634383863316666666666666666303136313165303030303030303030303030313937366139313464633561626233633536656261353731613039313066653138666138663230356432396130366533383861633030303030303030333864323361303030303030303030303030303030303030303030303030222c22696e7075745f616d6f756e7473223a5b222d37373737225d7d" // nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures: []*types.Signature{
			{
				Bytes: forceHexDecode(
					t,
					"0f1e6ce3278d3ad83f87deffec1c06ac830059077b3524647a77259ca284ad5c40d4483ccefeb366bdfc3e0623df56afbb1d69cba4549107ab8c6453c03cc919", // nolint
				),
				SigningPayload: signingPayload,
				PublicKey:      publicKey,
				SignatureType:  types.Ecdsa,
			},
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn"},
		},
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "4358d73e1d3b596f739a8b36b2e2e5d72f010bcdf506d360dda6b021d06bf0a6",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	bitcoinTransaction := "0400008085202f8901e74e10852371d539e7e4f512a55ac39c94b293972475df0eea814f6e7b411629000000006a47304402200f1e6ce3278d3ad83f87deffec1c06ac830059077b3524647a77259ca284ad5c022040d4483ccefeb366bdfc3e0623df56afbb1d69cba4549107ab8c6453c03cc919012102a854251adfee222bede8396fed0756985d4ea905f72611740867c7a4ad6488c1ffffffff01611e0000000000001976a914dc5abb3c56eba571a0910fe18fa8f205d29a06e388ac0000000038d23a000000000000000000000000" // nolint
	mockClient.On(
		"SendRawTransaction",
		ctx,
		bitcoinTransaction,
	).Return(
		transactionIdentifier.Hash,
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)
	mockIndexer.AssertExpectations(t)
}
