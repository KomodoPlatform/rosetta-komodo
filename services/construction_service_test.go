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
	"fmt"
	"testing"

	"github.com/DeckerSU/rosetta-komodo/configuration"
	"github.com/DeckerSU/rosetta-komodo/komodo"
	"github.com/DeckerSU/rosetta-komodo/komodod/wire"
	"github.com/DeckerSU/rosetta-komodo/komodod/zec"
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

// [decker] just for debug (de)serialisation features, etc.
func TestTransactions(t *testing.T) {

	msg := wire.NewMsgTx(4)
	tx := zec.NewTxFromMsgTx(msg, 0) // Tx
	fmt.Printf("%+v\n%+v\n", tx.MsgTx, tx)

	bytes, err := tx.Bytes()
	if err == nil {
		for _, b := range bytes {
			fmt.Printf("%02x", b)
		}
		fmt.Println()
	}
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
		ExpiryHeight: 3856307,
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
		komodo.MinFeeRate, // * 10
		nil,
	).Once()
	mockClient.On(
		"GetBestBlock",
		ctx).Return(
		int64(3856106), nil).Twice()
	mockClient.On(
		"GetHashFromIndex",
		ctx,
		int64(3856106)).Return(
		"087ae551e951edd04608a00c62b1df618b83ca9abcbf96aec919aa174932ab82", nil).Twice()

	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
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
			"2857097bb7d8bf130f6350e35ac07cd0c45665563e9e0e2c55b48fa45f1f1d94",
		),
		AccountIdentifier: &types.AccountIdentifier{
			Address: "RVNKRr2uxPMxJeDwFnTKjdtiLtcs7UzCZn",
		},
		SignatureType: types.Ecdsa,
	}

	unsignedRaw := "7b227472616e73616374696f6e223a2230343030303038303835323032663839303165373465313038353233373164353339653765346635313261353561633339633934623239333937323437356466306565613831346636653762343131363239303030303030303030306666666666666666303136313165303030303030303030303030313937366139313464633561626233633536656261353731613039313066653138666138663230356432396130366533383861633030303030303030623364373361303030303030303030303030303030303030303030303030222c227363726970745075624b657973223a5b7b2261736d223a224f505f445550204f505f484153483136302064633561626233633536656261353731613039313066653138666138663230356432396130366533204f505f455155414c564552494659204f505f434845434b534947222c22686578223a223736613931346463356162623363353665626135373161303931306665313866613866323035643239613036653338386163222c2272657153696773223a312c2274797065223a227075626b657968617368222c22616464726573736573223a5b2252564e4b5272327578504d784a654477466e544b6a6474694c74637337557a435a6e225d7d5d2c22696e7075745f616d6f756e7473223a5b222d37373737225d2c22696e7075745f616464726573736573223a5b2252564e4b5272327578504d784a654477466e544b6a6474694c74637337557a435a6e225d7d"

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
	signedRaw := "7b227472616e73616374696f6e223a22303130303030303030313038356233303936643638653262646134303432313437633531613330326531353433313237313764336564643161373265373131303432613138326230613230313030303030303661343733303434303232303632343234663837363563386361303936303134316362306566663132386339633639363762636661313632656239626539323637356533396633346639613730323230373434373830323730393239613130303633303762633538663837643366373132376163383635306264393636313036373837633930626339373663366332633031323130333136346637363336306566373965373531336566663330393565386236306135636639383232336265643064333130396161616265356630363162653431343066666666666666663031303063613961336230303030303030303365373661393134383633623435353736613133306463396338343838326436366663656165393235363463656230663838616332306638313638323066323431353062353634376536363262643961653339336638326632633662353662613665343839383363656264373230623361653836303730326434303062343030303030303030222c22696e7075745f616d6f756e7473223a5b222d31303030303030303030225d7d" // nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures: []*types.Signature{
			{
				Bytes: forceHexDecode(
					t,
					"62424f8765c8ca0960141cb0eff128c9c6967bcfa162eb9be92675e39f34f9a7744780270929a1006307bc58f87d3f7127ac8650bd966106787c90bc976c6c2c", // nolint
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
			{Address: "ztcHp2reR5d4AhZLLp5bYELzfZXHQERQogi"},
		},
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "a589c9941da87b15ffbb419569f38a1d44c805aeaafa167088d270de0fd8eed2",
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
	bitcoinTransaction := "0100000001085b3096d68e2bda4042147c51a302e154312717d3edd1a72e711042a182b0a2010000006a473044022062424f8765c8ca0960141cb0eff128c9c6967bcfa162eb9be92675e39f34f9a70220744780270929a1006307bc58f87d3f7127ac8650bd966106787c90bc976c6c2c012103164f76360ef79e7513eff3095e8b60a5cf98223bed0d3109aaabe5f061be4140ffffffff0100ca9a3b000000003e76a914863b45576a130dc9c84882d66fceae92564ceb0f88ac20f816820f24150b5647e662bd9ae393f82f2c6b56ba6e48983cebd720b3ae860702d400b400000000" // nolint
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
