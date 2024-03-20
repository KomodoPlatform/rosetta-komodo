package zec

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/DeckerSU/rosetta-komodo/komodod/txscript"
)

var (
	//go:embed test-data/shielded_sapling_tx.dat
	shieldedSaplingTx []byte
	//go:embed test-data/unshielded_sapling_tx.dat
	unshieldedSaplingTx []byte // mainnet
	//go:embed test-data/unshielded_orchard_tx.dat
	unshieldedOrchardTx []byte // testnet
	//go:embed test-data/v4_sighash_vector_tx.dat
	v4SighashVectorTx []byte
	//go:embed test-data/v3_tx.dat
	v3Tx []byte
	//go:embed test-data/v2_joinsplit_tx.dat
	v2JoinSplit []byte
)

func TestTxDeserializeV2(t *testing.T) {
	// testnet tx 66bd29f14043843327fae377bd47659c6f02efd3aa62992a6ffa15ddd5fcbaff
	tx, err := DeserializeTx(v2JoinSplit)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}
	if len(tx.VJoinSplit) != 1 {
		t.Fatalf("expected 1 vJoinSplit. saw %d", len(tx.VJoinSplit))
	}
	if tx.SerializeSize() != uint64(len(v2JoinSplit)) {
		t.Fatalf("wrong serialized size. wanted %d, got %d", len(v2JoinSplit), tx.SerializeSize())
	}
	js := tx.VJoinSplit[0]
	const expNew = 5338489
	if js.New != expNew {
		t.Fatalf("wrong joinsplit new. expected %d, got %d", expNew, js.New)
	}
}

func TestTxDeserializeV3(t *testing.T) {
	tx, err := DeserializeTx(v3Tx)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}

	const expHash = "fc546132ad9c7bee2a2390ccafc54f29c23bf2f311233f89294665a6c4b7cfa7"
	if tx.TxHash().String() != expHash {
		t.Fatalf("wrong v3 hash")
	}
	if tx.SerializeSize() != uint64(len(v3Tx)) {
		t.Fatalf("wrong serialized size. wanted %d, got %d", len(v3Tx), tx.SerializeSize())
	}
}

func TestTxDeserializeV4(t *testing.T) {
	tx, err := DeserializeTx(unshieldedSaplingTx)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}

	const expHash = "fb70397806afddcc07b9607e844ff29f2fb09e9972a051c3fe4d56fe18147e77"
	if tx.TxHash().String() != expHash {
		t.Fatalf("wrong v4 hash")
	}
	if tx.SerializeSize() != uint64(len(unshieldedSaplingTx)) {
		t.Fatalf("wrong serialized size. wanted %d, got %d", len(unshieldedSaplingTx), tx.SerializeSize())
	}

	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}

	txIn := tx.TxIn[0]
	if txIn.PreviousOutPoint.Hash.String() != "df0547ac001d335441bd621779e8946a1224949a014871b5f2a349352a270d69" {
		t.Fatal("wrong previous outpoint hash")
	}
	if txIn.PreviousOutPoint.Index != 0 {
		t.Fatal("wrong previous outpoint index")
	}
	if hex.EncodeToString(txIn.SignatureScript) != "47304402201656a4834651f39ac52eb866042ca7ede052ac843a914da4790573122c8e2ab302200af617e856abf4f8fb8d8086825dc63766943b4866ad3d6b4c8f222017c9b402012102d547eb1c5672a4d212de3c797a87b2b8fe731c2b502db6d7ad044850fe11d78f" {
		t.Fatal("wrong signature script")
	}
	if txIn.Sequence != 4294967295 {
		t.Fatalf("wrong sequence")
	}

	if len(tx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(tx.TxOut))
	}
	txOut := tx.TxOut[1]
	if txOut.Value != 41408718 {
		t.Fatal("wrong value")
	}
	if hex.EncodeToString(txOut.PkScript) != "76a9144ff496917bae33309a8ad70bec81355bbf92988988ac" {
		t.Fatalf("wrong pk script")
	}

	if sz := CalcTxSize(tx.MsgTx); sz != uint64(len(unshieldedSaplingTx)) {
		t.Fatalf("wrong calculated tx size. wanted %d, got %d", len(unshieldedSaplingTx), sz)
	}

	serializedTx, err := tx.Bytes()
	if err != nil {
		t.Fatalf("error re-serializing: %v", err)
	}
	if !bytes.Equal(serializedTx, unshieldedSaplingTx) {
		t.Fatalf("re-encoding does not match original")
	}
}

func TestTxDeserializeV5(t *testing.T) {
	tx, err := DeserializeTx(unshieldedOrchardTx)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}

	const expHash = "a2a3e99169bad144e490708bbd9d4daf8dc9017397ad11e7a1e75a62f9919324" // testnet
	if tx.TxHash().String() != expHash {
		t.Fatalf("wrong v5 hash")
	}
	if tx.SerializeSize() != uint64(len(unshieldedOrchardTx)) {
		t.Fatalf("wrong serialized size. wanted %d, got %d", len(unshieldedOrchardTx), tx.SerializeSize())
	}

	serializedTx, err := tx.Bytes()
	if err != nil {
		t.Fatalf("error re-serializing: %v", err)
	}
	if !bytes.Equal(serializedTx, unshieldedOrchardTx) {
		fmt.Println("original:", hex.EncodeToString(unshieldedOrchardTx))
		fmt.Println("re-encode:", hex.EncodeToString(serializedTx))
		t.Fatalf("re-encoding does not match original")
	}
}

func TestShieldedTx(t *testing.T) {
	// Just make sure it doesn't error.
	tx, err := DeserializeTx(shieldedSaplingTx)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}
	if tx.SerializeSize() != uint64(len(shieldedSaplingTx)) {
		t.Fatalf("wrong serialized size. wanted %d, got %d", len(shieldedSaplingTx), tx.SerializeSize())
	}
}

func TestV5SigDigest(t *testing.T) {
	// test vector generated with github.com/zcash-hackworks/zcash-testvectors
	txB, _ := hex.DecodeString("050000800a27a726b4d0d6c27a8f739a2d6f2c0201e152a" +
		"8049e294c4d6e66b164939daffa2ef6ee6921481cdd86b3cc4318d9614fc820905d045" +
		"3516aaca3f2498800000000")
	sigDigest, _ := hex.DecodeString("19e9b271cf0b6f9d60b2834eb16802ce1aa41cd8e96f50bd38dd8f4c4c82616f")
	transparentDigest, _ := hex.DecodeString("f31a4521a8d04d8e1f01a614ad0627278c870b7c9a48306cc74587a349dd92b9")

	const vin = 0
	prevScript, _ := hex.DecodeString("650051")
	const prevValue = 1800841178198868

	tx, err := DeserializeTx(txB)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}

	prevs, _ := hex.DecodeString("223b625f83e3cd9c127ad107fdb5402bfcd5f10681867f2fde8bcfb2aa2447ae")
	amts, _ := hex.DecodeString("765008be6611a6e2a6520aa72fb67dc2d944577c26544d924a00d50ea7c58855")
	scripts, _ := hex.DecodeString("1e43079ba1fa40d65beee6dd9b77b48017283b16438a852def75a5096cfea9b7")
	seqs, _ := hex.DecodeString("17de0287f8f0c573fe74c52d1bd0e6b429cc9201390ededf4a625f5769e41716")
	outputs, _ := hex.DecodeString("25f311cc149ecccef0e8ca8c9facd897ef88806008bc15818069470db9f84a37")
	txinDigest, _ := hex.DecodeString("bb4ab0249df12a12df3d0d160f9ca6fbb0658c30dd44fd62d237994e77f2c1c6")

	prevoutsDigest, err := tx.hashPrevOutsSigV5(false)
	if err != nil {
		return
	}
	if !bytes.Equal(prevs, prevoutsDigest[:]) {
		t.Fatalf("wrong prevoutsDigest")
	}

	amtsDigest, err := tx.hashAmountsSig(false, []int64{prevValue})
	if err != nil {
		return
	}
	if !bytes.Equal(amts, amtsDigest[:]) {
		t.Fatalf("wrong amtsDigest")
	}

	prevScriptsDigest, err := tx.hashPrevScriptsSig(false, [][]byte{prevScript})
	if err != nil {
		return
	}
	if !bytes.Equal(scripts, prevScriptsDigest[:]) {
		t.Fatalf("wrong prevScriptsDigest")
	}

	seqsDigest, err := tx.hashSequenceSigV5(false)
	if err != nil {
		return
	}
	if !bytes.Equal(seqs, seqsDigest[:]) {
		t.Fatalf("wrong seqsDigest")
	}

	outputsDigest, err := tx.hashOutputsSigV5(false)
	if err != nil {
		return
	}
	if !bytes.Equal(outputs, outputsDigest[:]) {
		t.Fatalf("wrong outputsDigest")
	}

	txInsDigest, err := tx.hashTxInSig(vin, prevValue, prevScript)
	if err != nil {
		return
	}
	if !bytes.Equal(txinDigest, txInsDigest[:]) {
		t.Fatalf("wrong txInsDigest")
	}

	td, err := tx.transparentSigDigestV5(0, txscript.SigHashAll, []int64{prevValue}, [][]byte{prevScript})
	if err != nil {
		t.Fatalf("transparentSigDigest error: %v", err)
	}

	if !bytes.Equal(td[:], transparentDigest) {
		t.Fatalf("wrong digest")
	}

	sd, err := tx.SignatureDigest(0, txscript.SigHashAll, nil, []int64{prevValue}, [][]byte{prevScript})
	if err != nil {
		t.Fatalf("transparentSigDigest error: %v", err)
	}

	if !bytes.Equal(sd[:], sigDigest) {
		t.Fatalf("wrong signatureDigest")
	}
}

func TestV4SigDigest(t *testing.T) {
	// Test Vector 3 from ZIP-0243, but fixed.
	// Preimage and test vector in ZIP-0243 are WRONG!!!!
	// The test vector's preimage DOES NOT include a varint for script size, but
	// it should, and I modified zclassicd to log the preimage just to make
	// sure. I had run into this problem in the Zcash docs before too. When they
	// say "(serialized as scripts inside CTxOuts)", that's apparently code for
	// adding the varint, but the guy tasked with generating test vectors
	// apparently didn't get it either.
	tx, err := DeserializeTx(v4SighashVectorTx)
	if err != nil {
		t.Fatalf("error decoding tx: %v", err)
	}
	amtLE, _ := hex.DecodeString("80f0fa0200000000")
	val := binary.LittleEndian.Uint64(amtLE)
	vals := []int64{int64(val)}

	script, _ := hex.DecodeString("1976a914507173527b4c3318a2aecd793bf1cfed705950cf88ac")
	pimg, err := tx.sighashPreimageV4(txscript.SigHashAll, 0, vals, script)
	if err != nil {
		t.Fatalf("sighashPreimageV4 error: %v", err)
	}

	expPimg, _ := hex.DecodeString(
		"0400008085202f89fae31b8dec7b0b77e2c8d6b6eb0e7e4e55abc6574c26dd44464d94" +
			"08a8e33f116c80d37f12d89b6f17ff198723e7db1247c4811d1a695d74d930f99e9841" +
			"8790d2b04118469b7810a0d1cc59568320aad25a84f407ecac40b4f605a4e686845400" +
			"0000000000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000029b0040048b004000000" +
			"00000000000001000000a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5b" +
			"b6a1d9952104d9010000001a1976a914507173527b4c3318a2aecd793bf1cfed705950" +
			"cf88ac80f0fa0200000000feffffff",
	)
	if !bytes.Equal(pimg, expPimg) {
		fmt.Println("preimage:", hex.EncodeToString(pimg))
		t.Fatal("wrong preimage")
	}
	// After fixing the vector's preimage, the sighash obviously changed, but
	// I'll leave this here to maintain expected behavior in case of future code
	// updates.
	expSighash, _ := hex.DecodeString("a358eb2ce8b214facba92761be09cc3e889e91a2e301146e8e40b5a6417da3d8")
	h, err := tx.SignatureDigest(0, txscript.SigHashAll, script, vals, nil)
	if err != nil {
		t.Fatalf("SignatureDigest error: %v", err)
	}
	if !bytes.Equal(expSighash, h[:]) {
		fmt.Println("sighash:", hex.EncodeToString(h[:]))
		t.Fatal("wrong sighash")
	}
}
