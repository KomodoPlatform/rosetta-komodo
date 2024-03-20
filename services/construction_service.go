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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/DeckerSU/rosetta-komodo/configuration"
	"github.com/DeckerSU/rosetta-komodo/komodo"

	"github.com/DeckerSU/rosetta-komodo/komodod/btcec"
	"github.com/DeckerSU/rosetta-komodo/komodod/txscript"
	"github.com/DeckerSU/rosetta-komodo/komodod/wire"
	"github.com/DeckerSU/rosetta-komodo/komodod/zec"
	"github.com/DeckerSU/rosetta-komodo/komodoutil"
	"github.com/coinbase/rosetta-sdk-go/parser"
	"github.com/coinbase/rosetta-sdk-go/server"
	"github.com/coinbase/rosetta-sdk-go/types"
)

const (
	// bytesInKB is the number of bytes in a KB. In Komodo, this is
	// considered to be 1000.
	bytesInKb = float64(1000) // nolint:gomnd

	// defaultConfirmationTarget is the number of blocks we would
	// like our transaction to be included by.
	defaultConfirmationTarget = int64(2) // nolint:gomnd
)

// ConstructionAPIService implements the server.ConstructionAPIServicer interface.
type ConstructionAPIService struct {
	config *configuration.Configuration
	client Client
	i      Indexer
}

// NewConstructionAPIService creates a new instance of a ConstructionAPIService.
func NewConstructionAPIService(
	config *configuration.Configuration,
	client Client,
	i Indexer,
) server.ConstructionAPIServicer {
	return &ConstructionAPIService{
		config: config,
		client: client,
		i:      i,
	}
}

// ConstructionDerive implements the /construction/derive endpoint.
func (s *ConstructionAPIService) ConstructionDerive(
	ctx context.Context,
	request *types.ConstructionDeriveRequest,
) (*types.ConstructionDeriveResponse, *types.Error) {
	addr, err := komodoutil.NewAddressPubKeyHash(
		komodoutil.Hash160(request.PublicKey.Bytes),
		s.config.Params,
	)
	if err != nil {
		return nil, wrapErr(ErrUnableToDerive, err)
	}

	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.EncodeAddress(),
		},
	}, nil
}

// estimateSize returns the estimated size of a transaction in vBytes.
func (s *ConstructionAPIService) estimateSize(operations []*types.Operation) float64 {
	size := komodo.TransactionOverhead
	for _, operation := range operations {
		switch operation.Type {
		case komodo.InputOpType:
			size += komodo.InputSize
		case komodo.OutputOpType:
			size += komodo.OutputOverhead
			addr, err := komodoutil.DecodeAddress(operation.Account.Address, s.config.Params)
			if err != nil {
				size += komodo.P2PKHScriptPubkeySize
				continue
			}
			// addr here can be AddressPubKeyHash, AddressScriptHash, AddressPubKey
			script, err := txscript.PayToAddrScript(addr)
			if err != nil {
				size += komodo.P2PKHScriptPubkeySize
				continue
			}
			size += len(script)
		}
	}

	return float64(size)
}

// ConstructionPreprocess implements the /construction/preprocess
// endpoint.
func (s *ConstructionAPIService) ConstructionPreprocess(
	ctx context.Context,
	request *types.ConstructionPreprocessRequest,
) (*types.ConstructionPreprocessResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: komodo.InputOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: s.config.Currency,
				},
				CoinAction:   types.CoinSpent,
				AllowRepeats: true,
			},
		},
	}

	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}

	coins := make([]*types.Coin, len(matches[0].Operations))
	for i, input := range matches[0].Operations {
		if input.CoinChange == nil {
			return nil, wrapErr(ErrUnclearIntent, errors.New("CoinChange cannot be nil"))
		}

		coins[i] = &types.Coin{
			CoinIdentifier: input.CoinChange.CoinIdentifier,
			Amount:         input.Amount,
		}
	}

	options, err := types.MarshalMap(&preprocessOptions{
		Coins:         coins,
		EstimatedSize: s.estimateSize(request.Operations),
		FeeMultiplier: request.SuggestedFeeMultiplier,
	})
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPreprocessResponse{
		Options: options,
	}, nil
}

// ConstructionMetadata implements the /construction/metadata endpoint.
func (s *ConstructionAPIService) ConstructionMetadata(
	ctx context.Context,
	request *types.ConstructionMetadataRequest,
) (*types.ConstructionMetadataResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, wrapErr(ErrUnavailableOffline, nil)
	}

	var options preprocessOptions
	if err := types.UnmarshalMap(request.Options, &options); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Determine feePerKB and ensure it is not below the minimum fee
	// relay rate.
	feePerKB, err := s.client.SuggestedFeeRate(ctx, defaultConfirmationTarget)
	if err != nil {
		return nil, wrapErr(ErrCouldNotGetFeeRate, err)
	}
	if options.FeeMultiplier != nil {
		feePerKB *= *options.FeeMultiplier
	}
	if feePerKB < komodo.MinFeeRate {
		feePerKB = komodo.MinFeeRate
	}

	// Calculated the estimated fee in Satoshis
	satoshisPerB := (feePerKB * float64(komodo.SatoshisInBitcoin)) / bytesInKb
	estimatedFee := satoshisPerB * options.EstimatedSize
	suggestedFee := &types.Amount{
		Value:    fmt.Sprintf("%d", int64(estimatedFee)),
		Currency: s.config.Currency,
	}

	// GetScriptPubKeys checks the amount as well; it will not allow incorrect
	// amounts to be filled in the operation, as everything is validated through indexer data
	scripts, err := s.i.GetScriptPubKeys(ctx, options.Coins)
	if err != nil {
		return nil, wrapErr(ErrScriptPubKeysMissing, err)
	}

	// Determine nExpiryHeight
	bestblockHeight, err := s.client.GetBestBlock(ctx)
	if err != nil {
		return nil, wrapErr(ErrCouldNotGetBestBlock, err)
	}

	// https://github.com/DeckerSU/KomodoOcean/blob/281f59e32f3ce9914cb21746e1a885549aa8d962/src/main.cpp#L8866
	nExpiryHeight := (bestblockHeight + 1) + 200 // nextBlockHeight + DEFAULT_TX_EXPIRY_DELTA (200)

	if nExpiryHeight < 0 || nExpiryHeight > zec.MaxExpiryHeight {
		return nil, wrapErr(ErrUnclearIntent, errors.New("Invalid nExpiryHeight"))
	}

	var expiryHeightUint32 uint32 = uint32(nExpiryHeight)

	metadata, err := types.MarshalMap(
		&constructionMetadata{
			ScriptPubKeys: scripts,
			ExpiryHeight:  expiryHeightUint32})
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionMetadataResponse{
		Metadata:     metadata,
		SuggestedFee: []*types.Amount{suggestedFee},
	}, nil
}

// ConstructionPayloads implements the /construction/payloads endpoint.
func (s *ConstructionAPIService) ConstructionPayloads(
	ctx context.Context,
	request *types.ConstructionPayloadsRequest,
) (*types.ConstructionPayloadsResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: komodo.InputOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: s.config.Currency,
				},
				AllowRepeats: true,
				CoinAction:   types.CoinSpent,
			},
			{
				Type: komodo.OutputOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.PositiveAmountSign,
					Currency: s.config.Currency,
				},
				AllowRepeats: true,
			},
		},
		ErrUnmatched: true,
	}

	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}
	var metadata constructionMetadata
	if err := types.UnmarshalMap(request.Metadata, &metadata); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	txBase := wire.NewMsgTx(wire.TxVersion)
	expiryHeight := metadata.ExpiryHeight
	tx := zec.NewTxFromMsgTx(txBase, expiryHeight)
	println(tx)

	for _, input := range matches[0].Operations {
		if input.CoinChange == nil {
			return nil, wrapErr(ErrUnclearIntent, errors.New("CoinChange cannot be nil"))
		}

		transactionHash, index, err := komodo.ParseCoinIdentifier(input.CoinChange.CoinIdentifier)
		if err != nil {
			return nil, wrapErr(ErrInvalidCoin, err)
		}

		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *transactionHash,
				Index: index,
			},
			SignatureScript: nil,
			Sequence:        wire.MaxTxInSequenceNum,
		})
	}

	for i, output := range matches[1].Operations {
		addr, err := komodoutil.DecodeAddress(output.Account.Address, s.config.Params)
		if err != nil {
			return nil, wrapErr(ErrUnableToDecodeAddress, fmt.Errorf(
				"%w unable to decode address %s",
				err,
				output.Account.Address,
			),
			)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to construct payToAddrScript", err),
			)
		}

		tx.AddTxOut(&wire.TxOut{
			Value:    matches[1].Amounts[i].Int64(),
			PkScript: pkScript,
		})
	}

	// fill the prevScripts and inputAmountsVal slices before, based on the provided metadata
	prevScripts := make([][]byte, len(tx.TxIn))
	inputAmountsVal := make([]int64, len(tx.TxIn))
	for i := range tx.TxIn {
		amount := matches[0].Amounts[i]
		// TODO: may be perform an amount check as in GetScriptPubKeys,
		// with i.blockStorage.FindTransaction, etc.?
		if amount.Sign() < 0 {
			amount.Neg(amount) // make amount positive
		}
		inputAmountStr := amount.String()
		inputAmount, err := strconv.ParseInt(inputAmountStr, 10, 64)
		if err != nil {
			return nil, wrapErr(ErrUnclearIntent, errors.New("Can't convert amount")) // or ErrUnableToParseIntermediateResult?
		}
		inputAmountsVal[i] = inputAmount

		pkScript, err := hex.DecodeString(metadata.ScriptPubKeys[i].Hex)
		if err != nil {
			return nil, wrapErr(ErrUnableToDecodeScriptPubKey, err)
		}
		prevScripts[i] = pkScript
	}

	// Create Signing Payloads (must be done after entire tx is constructed
	// or hash will not be correct).
	inputAmounts := make([]string, len(tx.TxIn))
	inputAddresses := make([]string, len(tx.TxIn))
	payloads := make([]*types.SigningPayload, len(tx.TxIn))

	for i := range tx.TxIn {
		address := matches[0].Operations[i].Account.Address
		script, err := hex.DecodeString(metadata.ScriptPubKeys[i].Hex)
		if err != nil {
			return nil, wrapErr(ErrUnableToDecodeScriptPubKey, err)
		}
		class, _, err := komodo.ParseSingleAddress(s.config.Params, script)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to parse address for utxo %d", err, i),
			)
		}

		inputAddresses[i] = address
		inputAmounts[i] = matches[0].Amounts[i].String()

		allowedClasses := map[txscript.ScriptClass]bool{
			txscript.PubKeyHashTy: true,
			txscript.ScriptHashTy: false,
			txscript.MultiSigTy:   false,
		}
		if !allowedClasses[class] {
			return nil, wrapErr(
				ErrUnsupportedScriptType,
				fmt.Errorf("unupported script type: %s", class),
			)
		}

		// calculate signature digest
		digest, err := tx.SignatureDigest(i, txscript.SigHashAll, script, inputAmountsVal, prevScripts)
		if err != nil {
			return nil, wrapErr(ErrUnableToCalculateSignatureHash, err)
		}
		hash := digest[:]

		// hash, err := txscript.CalcSignatureHash(
		// 	script,
		// 	txscript.SigHashAll,
		// 	tx,
		// 	i,
		// )

		// if err != nil {
		// 	return nil, wrapErr(ErrUnableToCalculateSignatureHash, err)
		// }

		payloads[i] = &types.SigningPayload{
			AccountIdentifier: &types.AccountIdentifier{
				Address: address,
			},
			Bytes:         hash,
			SignatureType: types.Ecdsa,
		}

	}

	// Serialisation via tx.Bytes(), not via tx.Serialize(buf)
	buf := bytes.NewBuffer(make([]byte, 0, zec.CalcTxSize(txBase)))
	rawTxBytes, err := tx.Bytes()
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}
	_, writeErr := buf.Write(rawTxBytes)
	if writeErr != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, writeErr)
	}

	rawTx, err := json.Marshal(&unsignedTransaction{
		Transaction:    hex.EncodeToString(buf.Bytes()),
		ScriptPubKeys:  metadata.ScriptPubKeys,
		InputAmounts:   inputAmounts,
		InputAddresses: inputAddresses,
	})
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}
	return &types.ConstructionPayloadsResponse{
		UnsignedTransaction: hex.EncodeToString(rawTx),
		Payloads:            payloads,
	}, nil
}

func normalizeSignature(signature []byte) []byte {
	sig := btcec.Signature{ // signature is in form of R || S
		R: new(big.Int).SetBytes(signature[:32]),
		S: new(big.Int).SetBytes(signature[32:64]),
	}

	return append(sig.Serialize(), byte(txscript.SigHashAll))
}

// ConstructionCombine implements the /construction/combine
// endpoint.
func (s *ConstructionAPIService) ConstructionCombine(
	ctx context.Context,
	request *types.ConstructionCombineRequest,
) (*types.ConstructionCombineResponse, *types.Error) {
	decodedTx, err := hex.DecodeString(request.UnsignedTransaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w transaction cannot be decoded", err),
		)
	}

	var unsigned unsignedTransaction
	if err := json.Unmarshal(decodedTx, &unsigned); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to unmarshal komodo transaction", err),
		)
	}

	decodedCoreTx, err := hex.DecodeString(unsigned.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w transaction cannot be decoded", err),
		)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(decodedCoreTx)); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to deserialize tx", err),
		)
	}

	for i := range tx.TxIn {
		decodedScript, err := hex.DecodeString(unsigned.ScriptPubKeys[i].Hex)
		if err != nil {
			return nil, wrapErr(ErrUnableToDecodeScriptPubKey, err)
		}

		class, _, err := komodo.ParseSingleAddress(s.config.Params, decodedScript)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to parse address for script", err),
			)
		}

		fullsig := normalizeSignature(request.Signatures[i].Bytes)
		pkData := request.Signatures[i].PublicKey.Bytes

		if class != txscript.PubKeyHashReplayOutTy && class != txscript.PubKeyHashTy {
			return nil, wrapErr(
				ErrUnsupportedScriptType,
				fmt.Errorf("unupported script type: %s", class),
			)
		}

		tx.TxIn[i].SignatureScript, err = txscript.NewScriptBuilder().AddData(fullsig).AddData(pkData).Script()
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, fmt.Errorf("%w calculate input signature", err))
		}
	}

	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, fmt.Errorf("%w serialize tx", err))
	}

	rawTx, err := json.Marshal(&signedTransaction{
		Transaction:  hex.EncodeToString(buf.Bytes()),
		InputAmounts: unsigned.InputAmounts,
	})
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to serialize signed tx", err),
		)
	}

	return &types.ConstructionCombineResponse{
		SignedTransaction: hex.EncodeToString(rawTx),
	}, nil
}

// ConstructionHash implements the /construction/hash endpoint.
func (s *ConstructionAPIService) ConstructionHash(
	ctx context.Context,
	request *types.ConstructionHashRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	decodedTx, err := hex.DecodeString(request.SignedTransaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w signed transaction cannot be decoded", err),
		)
	}
	var signed signedTransaction
	if err := json.Unmarshal(decodedTx, &signed); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to unmarshal signed komodo transaction", err),
		)
	}
	bytesTx, err := hex.DecodeString(signed.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to decode hex transaction", err),
		)
	}

	tx, err := komodoutil.NewTxFromBytes(bytesTx)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to parse transaction", err),
		)
	}

	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: tx.Hash().String(),
		},
	}, nil
}

func (s *ConstructionAPIService) parseUnsignedTransaction(
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	decodedTx, err := hex.DecodeString(request.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w transaction cannot be decoded", err),
		)
	}

	var unsigned unsignedTransaction
	if err := json.Unmarshal(decodedTx, &unsigned); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to unmarshal komodo transaction", err),
		)
	}

	decodedCoreTx, err := hex.DecodeString(unsigned.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w transaction cannot be decoded", err),
		)
	}

	tx, err := zec.DeserializeTx(decodedCoreTx)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to deserialize tx", err),
		)
	}

	ops := []*types.Operation{}
	for i, input := range tx.TxIn {
		networkIndex := int64(i)
		ops = append(ops, &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        int64(len(ops)),
				NetworkIndex: &networkIndex,
			},
			Type: komodo.InputOpType,
			Account: &types.AccountIdentifier{
				Address: unsigned.InputAddresses[i],
			},
			Amount: &types.Amount{
				Value:    unsigned.InputAmounts[i],
				Currency: s.config.Currency,
			},
			CoinChange: &types.CoinChange{
				CoinAction: types.CoinSpent,
				CoinIdentifier: &types.CoinIdentifier{
					Identifier: fmt.Sprintf(
						"%s:%d",
						input.PreviousOutPoint.Hash.String(),
						input.PreviousOutPoint.Index,
					),
				},
			},
		})
	}

	for i, output := range tx.TxOut {
		networkIndex := int64(i)
		_, addr, err := komodo.ParseSingleAddress(s.config.Params, output.PkScript)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to parse output address", err),
			)
		}

		ops = append(ops, &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        int64(len(ops)),
				NetworkIndex: &networkIndex,
			},
			Type: komodo.OutputOpType,
			Account: &types.AccountIdentifier{
				Address: addr.String(),
			},
			Amount: &types.Amount{
				Value:    strconv.FormatInt(output.Value, 10),
				Currency: s.config.Currency,
			},
		})
	}

	return &types.ConstructionParseResponse{
		Operations:               ops,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
	}, nil
}

func (s *ConstructionAPIService) parseSignedTransaction(
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	decodedTx, err := hex.DecodeString(request.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w signed transaction cannot be decoded", err),
		)
	}

	var signed signedTransaction
	if err := json.Unmarshal(decodedTx, &signed); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to unmarshal signed komodo transaction", err),
		)
	}

	serializedTx, err := hex.DecodeString(signed.Transaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to decode hex transaction", err),
		)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(serializedTx)); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to decode msgTx", err),
		)
	}

	ops := []*types.Operation{}
	signers := []*types.AccountIdentifier{}
	for i, input := range tx.TxIn {
		pkScript, err := txscript.ComputePkScript(input.SignatureScript)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToComputePkScript,
				fmt.Errorf("%w: unable to compute pk script", err),
			)
		}
		_, addr, err := komodo.ParseSingleAddress(s.config.Params, pkScript.Script())
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to decode address", err),
			)
		}

		networkIndex := int64(i)
		signers = append(signers, &types.AccountIdentifier{
			Address: addr.EncodeAddress(),
		})
		ops = append(ops, &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        int64(len(ops)),
				NetworkIndex: &networkIndex,
			},
			Type: komodo.InputOpType,
			Account: &types.AccountIdentifier{
				Address: addr.EncodeAddress(),
			},
			Amount: &types.Amount{
				Value:    signed.InputAmounts[i],
				Currency: s.config.Currency,
			},
			CoinChange: &types.CoinChange{
				CoinAction: types.CoinSpent,
				CoinIdentifier: &types.CoinIdentifier{
					Identifier: fmt.Sprintf(
						"%s:%d",
						input.PreviousOutPoint.Hash.String(),
						input.PreviousOutPoint.Index,
					),
				},
			},
		})
	}

	for i, output := range tx.TxOut {
		networkIndex := int64(i)
		_, addr, err := komodo.ParseSingleAddress(s.config.Params, output.PkScript)
		if err != nil {
			return nil, wrapErr(
				ErrUnableToDecodeAddress,
				fmt.Errorf("%w unable to parse output address", err),
			)
		}

		ops = append(ops, &types.Operation{
			OperationIdentifier: &types.OperationIdentifier{
				Index:        int64(len(ops)),
				NetworkIndex: &networkIndex,
			},
			Type: komodo.OutputOpType,
			Account: &types.AccountIdentifier{
				Address: addr.String(),
			},
			Amount: &types.Amount{
				Value:    strconv.FormatInt(output.Value, 10),
				Currency: s.config.Currency,
			},
		})
	}

	return &types.ConstructionParseResponse{
		Operations:               ops,
		AccountIdentifierSigners: signers,
	}, nil
}

// ConstructionParse implements the /construction/parse endpoint.
func (s *ConstructionAPIService) ConstructionParse(
	ctx context.Context,
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	if request.Signed {
		return s.parseSignedTransaction(request)
	}

	return s.parseUnsignedTransaction(request)
}

// ConstructionSubmit implements the /construction/submit endpoint.
func (s *ConstructionAPIService) ConstructionSubmit(
	ctx context.Context,
	request *types.ConstructionSubmitRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, wrapErr(ErrUnavailableOffline, nil)
	}

	decodedTx, err := hex.DecodeString(request.SignedTransaction)
	if err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w signed transaction cannot be decoded", err),
		)
	}

	var signed signedTransaction
	if err := json.Unmarshal(decodedTx, &signed); err != nil {
		return nil, wrapErr(
			ErrUnableToParseIntermediateResult,
			fmt.Errorf("%w unable to unmarshal signed komodo transaction", err),
		)
	}

	txHash, err := s.client.SendRawTransaction(ctx, signed.Transaction)
	if err != nil {
		return nil, wrapErr(ErrBitcoind, fmt.Errorf("%w unable to submit transaction", err))
	}

	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: txHash,
		},
	}, nil
}
