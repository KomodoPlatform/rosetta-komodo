package chaincfg_test

import (
	"bytes"
	"reflect"
	"testing"

	. "github.com/DeckerSU/rosetta-komodo/komodod/chaincfg"
)

// Define some of the required parameters for a user-registered
// network.  This is necessary to test the registration of and
// lookup of encoding magics from the network.
var mockNetParams = Params{
	Name:             "mocknet",
	Net:              1<<32 - 1,
	PubKeyHashAddrID: 0x9f,
	ScriptHashAddrID: 0xf9,
	HDPrivateKeyID:   [4]byte{0x01, 0x02, 0x03, 0x04},
	HDPublicKeyID:    [4]byte{0x05, 0x06, 0x07, 0x08},
}

func TestRegister(t *testing.T) {
	type registerTest struct {
		name   string
		params *Params
		err    error
	}
	type magicTest struct {
		magic byte
		valid bool
	}
	type prefixTest struct {
		prefix string
		valid  bool
	}
	type hdTest struct {
		priv []byte
		want []byte
		err  error
	}

	tests := []struct {
		name           string
		register       []registerTest
		p2pkhMagics    []magicTest
		p2shMagics     []magicTest
		segwitPrefixes []prefixTest
		hdMagics       []hdTest
	}{
		{
			name: "default networks",
			register: []registerTest{
				{
					name:   "duplicate mainnet",
					params: &MainNetParams,
					err:    ErrDuplicateNet,
				},
				{
					name:   "duplicate regtest",
					params: &RegtestParams,
					err:    ErrDuplicateNet,
				},
				{
					name:   "duplicate testnet3",
					params: &RegressionNetParams,
					err:    ErrDuplicateNet,
				},
			},
			p2pkhMagics: []magicTest{
				{
					magic: MainNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.PubKeyHashAddrID,
					valid: false,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			p2shMagics: []magicTest{
				{
					magic: MainNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.ScriptHashAddrID,
					valid: false,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			hdMagics: []hdTest{
				{
					priv: MainNetParams.HDPrivateKeyID[:],
					want: MainNetParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: RegressionNetParams.HDPrivateKeyID[:],
					want: RegressionNetParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: RegtestParams.HDPrivateKeyID[:],
					want: RegtestParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: mockNetParams.HDPrivateKeyID[:],
					err:  ErrUnknownHDKeyID,
				},
				{
					priv: []byte{0xff, 0xff, 0xff, 0xff},
					err:  ErrUnknownHDKeyID,
				},
				{
					priv: []byte{0xff},
					err:  ErrUnknownHDKeyID,
				},
			},
		},
		{
			name: "register mocknet",
			register: []registerTest{
				{
					name:   "mocknet",
					params: &mockNetParams,
					err:    nil,
				},
			},
			p2pkhMagics: []magicTest{
				{
					magic: MainNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			p2shMagics: []magicTest{
				{
					magic: MainNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			hdMagics: []hdTest{
				{
					priv: mockNetParams.HDPrivateKeyID[:],
					want: mockNetParams.HDPublicKeyID[:],
					err:  nil,
				},
			},
		},
		{
			name: "more duplicates",
			register: []registerTest{
				{
					name:   "duplicate mainnet",
					params: &MainNetParams,
					err:    ErrDuplicateNet,
				},
				{
					name:   "duplicate regtest",
					params: &RegtestParams,
					err:    ErrDuplicateNet,
				},
				{
					name:   "duplicate testnet3",
					params: &RegressionNetParams,
					err:    ErrDuplicateNet,
				},
				{
					name:   "duplicate mocknet",
					params: &mockNetParams,
					err:    ErrDuplicateNet,
				},
			},
			p2pkhMagics: []magicTest{
				{
					magic: MainNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.PubKeyHashAddrID,
					valid: true,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			p2shMagics: []magicTest{
				{
					magic: MainNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegressionNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: RegtestParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: mockNetParams.ScriptHashAddrID,
					valid: true,
				},
				{
					magic: 0xFF,
					valid: false,
				},
			},
			hdMagics: []hdTest{
				{
					priv: MainNetParams.HDPrivateKeyID[:],
					want: MainNetParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: RegressionNetParams.HDPrivateKeyID[:],
					want: RegressionNetParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: RegtestParams.HDPrivateKeyID[:],
					want: RegtestParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: mockNetParams.HDPrivateKeyID[:],
					want: mockNetParams.HDPublicKeyID[:],
					err:  nil,
				},
				{
					priv: []byte{0xff, 0xff, 0xff, 0xff},
					err:  ErrUnknownHDKeyID,
				},
				{
					priv: []byte{0xff},
					err:  ErrUnknownHDKeyID,
				},
			},
		},
	}

	for _, test := range tests {
		for _, regTest := range test.register {
			err := Register(regTest.params)
			if err != regTest.err {
				t.Errorf("%s:%s: Registered network with unexpected error: got %v expected %v",
					test.name, regTest.name, err, regTest.err)
			}
		}
		for i, magTest := range test.p2pkhMagics {
			valid := IsPubKeyHashAddrID(magTest.magic)
			if valid != magTest.valid {
				t.Errorf("%s: P2PKH magic %d valid mismatch: got %v expected %v",
					test.name, i, valid, magTest.valid)
			}
		}
		for i, magTest := range test.p2shMagics {
			valid := IsScriptHashAddrID(magTest.magic)
			if valid != magTest.valid {
				t.Errorf("%s: P2SH magic %d valid mismatch: got %v expected %v",
					test.name, i, valid, magTest.valid)
			}
		}
		for i, prxTest := range test.segwitPrefixes {
			valid := IsBech32SegwitPrefix(prxTest.prefix)
			if valid != prxTest.valid {
				t.Errorf("%s: segwit prefix %s (%d) valid mismatch: got %v expected %v",
					test.name, prxTest.prefix, i, valid, prxTest.valid)
			}
		}
		for i, magTest := range test.hdMagics {
			pubKey, err := HDPrivateKeyToPublicKeyID(magTest.priv[:])
			if !reflect.DeepEqual(err, magTest.err) {
				t.Errorf("%s: HD magic %d mismatched error: got %v expected %v ",
					test.name, i, err, magTest.err)
				continue
			}
			if magTest.err == nil && !bytes.Equal(pubKey, magTest.want[:]) {
				t.Errorf("%s: HD magic %d private and public mismatch: got %v expected %v ",
					test.name, i, pubKey, magTest.want[:])
			}
		}
	}
}
