// Copyright (c) 2013 - 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package komodoutil_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/DeckerSU/rosetta-komodo/komodod/btcec"
	"github.com/DeckerSU/rosetta-komodo/komodod/chaincfg"
	. "github.com/DeckerSU/rosetta-komodo/komodoutil"
)

// Passphrase: 'myverysecretandstrongpassphrase_noneabletobrute'

func TestEncodeDecodeWIF(t *testing.T) {
	validEncodeCases := []struct {
		privateKey []byte           // input
		net        *chaincfg.Params // input
		compress   bool             // input
		wif        string           // output
		publicKey  []byte           // output
		name       string           // name of subtest
	}{
		{
			privateKey: []byte{
				0x90, 0x7e, 0xce, 0x71, 0x7a, 0x8f, 0x94, 0xe0,
				0x7d, 0xe7, 0xbf, 0x6f, 0x8b, 0x3e, 0x9f, 0x91,
				0xab, 0xb8, 0x85, 0x8e, 0xbf, 0x83, 0x10, 0x72,
				0xcd, 0xbb, 0x90, 0x16, 0xef, 0x53, 0xbc, 0x5d},
			net:      &chaincfg.MainNetParams,
			compress: false,
			wif:      "7KYb75jv5BgrDCbmW36yhofiBy2vSLpCCWDfJ9dMdZxPWnKicJh",
			publicKey: []byte{
				0x04, 0xa8, 0x54, 0x25, 0x1a, 0xdf, 0xee, 0x22, 0x2b, 0xed, 0xe8,
				0x39, 0x6f, 0xed, 0x07, 0x56, 0x98, 0x5d, 0x4e, 0xa9, 0x05, 0xf7,
				0x26, 0x11, 0x74, 0x08, 0x67, 0xc7, 0xa4, 0xad, 0x64, 0x88, 0xc1,
				0x76, 0x7a, 0xe7, 0xbe, 0xd1, 0x59, 0xfc, 0xa3, 0x9d, 0xc2, 0x6e,
				0x2f, 0x9d, 0xe3, 0x18, 0x17, 0xbd, 0x32, 0xe0, 0xd6, 0xc5, 0xa8,
				0x70, 0x80, 0x1b, 0xcd, 0x81, 0xfb, 0x7f, 0x1c, 0x20, 0x30},
			name: "encodeValidUncompressedMainNetWif",
		},
		{
			privateKey: []byte{
				0x90, 0x7e, 0xce, 0x71, 0x7a, 0x8f, 0x94, 0xe0,
				0x7d, 0xe7, 0xbf, 0x6f, 0x8b, 0x3e, 0x9f, 0x91,
				0xab, 0xb8, 0x85, 0x8e, 0xbf, 0x83, 0x10, 0x72,
				0xcd, 0xbb, 0x90, 0x16, 0xef, 0x53, 0xbc, 0x5d},
			net:      &chaincfg.RegressionNetParams,
			compress: true,
			wif:      "UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh",
			publicKey: []byte{
				0x02, 0xa8, 0x54, 0x25, 0x1a, 0xdf, 0xee, 0x22,
				0x2b, 0xed, 0xe8, 0x39, 0x6f, 0xed, 0x07, 0x56,
				0x98, 0x5d, 0x4e, 0xa9, 0x05, 0xf7, 0x26, 0x11,
				0x74, 0x08, 0x67, 0xc7, 0xa4, 0xad, 0x64, 0x88,
				0xc1},
			name: "encodeValidCompressedTestNet3Wif",
		},
	}

	for _, validCase := range validEncodeCases {
		t.Run(validCase.name, func(t *testing.T) {
			priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), validCase.privateKey)
			wif, err := NewWIF(priv, validCase.net, validCase.compress)
			if err != nil {
				t.Fatalf("NewWIF failed: expected no error, got '%v'", err)
			}

			if !wif.IsForNet(validCase.net) {
				t.Fatal("IsForNet failed: got 'false', want 'true'")
			}

			if gotPubKey := wif.SerializePubKey(); !bytes.Equal(gotPubKey, validCase.publicKey) {
				t.Fatalf("SerializePubKey failed: got '%s', want '%s'",
					hex.EncodeToString(gotPubKey), hex.EncodeToString(validCase.publicKey))
			}

			// Test that encoding the WIF structure matches the expected string.
			got := wif.String()
			if got != validCase.wif {
				t.Fatalf("NewWIF failed: want '%s', got '%s'",
					validCase.wif, got)
			}

			// Test that decoding the expected string results in the original WIF
			// structure.
			decodedWif, err := DecodeWIF(got)
			if err != nil {
				t.Fatalf("DecodeWIF failed: expected no error, got '%v'", err)
			}
			if decodedWifString := decodedWif.String(); decodedWifString != validCase.wif {
				t.Fatalf("NewWIF failed: want '%v', got '%v'", validCase.wif, decodedWifString)
			}
		})
	}

	invalidDecodeCases := []struct {
		name string
		wif  string
		err  error
	}{
		{
			name: "decodeInvalidLengthWif",
			wif:  "deadbeef",
			err:  ErrMalformedPrivateKey,
		},
		{
			name: "decodeInvalidCompressMagicWif",
			wif:  "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sfZr2ym",
			err:  ErrMalformedPrivateKey,
		},
		{
			name: "decodeInvalidChecksumWif",
			wif:  "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj",
			err:  ErrChecksumMismatch,
		},
	}

	for _, invalidCase := range invalidDecodeCases {
		t.Run(invalidCase.name, func(t *testing.T) {
			decodedWif, err := DecodeWIF(invalidCase.wif)
			if decodedWif != nil {
				t.Fatalf("DecodeWIF: unexpectedly succeeded - got '%v', want '%v'",
					decodedWif, nil)
			}
			if err != invalidCase.err {
				t.Fatalf("DecodeWIF: expected error '%v', got '%v'",
					invalidCase.err, err)
			}
		})
	}

	t.Run("encodeInvalidNetworkWif", func(t *testing.T) {
		privateKey := []byte{
			0x0c, 0x28, 0xfc, 0xa3, 0x86, 0xc7, 0xa2, 0x27,
			0x60, 0x0b, 0x2f, 0xe5, 0x0b, 0x7c, 0xae, 0x11,
			0xec, 0x86, 0xd3, 0xbf, 0x1f, 0xbe, 0x47, 0x1b,
			0xe8, 0x98, 0x27, 0xe1, 0x9d, 0x72, 0xaa, 0x1d}
		priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)

		wif, err := NewWIF(priv, nil, true)

		if wif != nil {
			t.Fatalf("NewWIF: unexpectedly succeeded - got '%v', want '%v'",
				wif, nil)
		}
		if err == nil || err.Error() != "no network" {
			t.Fatalf("NewWIF: expected error 'no network', got '%v'", err)
		}
	})
}
