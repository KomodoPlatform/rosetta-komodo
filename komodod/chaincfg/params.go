// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math/big"
	"strings"

	"github.com/DeckerSU/rosetta-komodo/komodod/chaincfg/chainhash"
	"github.com/DeckerSU/rosetta-komodo/komodod/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)
	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// These fields define the block heights at which the specified softfork
	// BIP became active.
	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change. It should typically
	// be 95% for the main network and 75% for test networks.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32 // [!!! NOT USED]
	MinerConfirmationWindow       uint32 // [!!! NOT USED]

	// Address encoding magics
	PubKeyHashAddrID uint16 // First 2 bytes of a P2PKH address
	ScriptHashAddrID uint16 // First 2 bytes of a P2SH address
	PrivateKeyID     byte   // First byte of a WIF private key

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "7771",
	DNSSeeds: []DNSSeed{
		{"kmd.komodoseeds.org", false},          // decker
		{"seeds1.kmd.sh", false},                // decker
		{"kmdseed.cipig.net", false},            // cipig
		{"kmdseeds.lordofthechains.com", false}, // gcharang
	},

	// Chain parameters
	GenesisBlock:     &genesisBlock,
	GenesisHash:      &genesisHash,
	BIP0034Height:    0,
	BIP0065Height:    0,
	BIP0066Height:    0,
	CoinbaseMaturity: 100,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{0, newHashFromStr("027e3758c3a65b12aa1046462b486d0a63bfa1beae327897f56c5cfb7daaae71")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016, //

	// Address encoding magics
	PubKeyHashAddrID: 0x2089, // starts with 1
	ScriptHashAddrID: 0x2096, // starts with 3
	PrivateKeyID:     0x80,   // starts with 5 (uncompressed) or K (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "test",
	Net:         wire.TestNet,
	DefaultPort: "19033",
	DNSSeeds: []DNSSeed{
		{"dnsseed.testnet.komodo.global", false},
	},
	// Chain parameters
	GenesisBlock:     &testNetGenesisBlock,
	GenesisHash:      &testnetGenesisHash,
	CoinbaseMaturity: 100,
	BIP0034Height:    0,
	BIP0065Height:    0, // Used by regression tests
	BIP0066Height:    0, // Used by regression tests

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{0, newHashFromStr("03e1c4bb705c871bf9bfda3e74b7f8f86bff267993c215a89d5795e3708e5e1f")},
		{50000, newHashFromStr("00076e16d3fa5194da559c17cf9cf285e21d1f13154ae4f7c7b87919549345aa")},
		{100000, newHashFromStr("0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f")},
		{150000, newHashFromStr("0a817f15b9da636f453a7a01835cfc534ed1a55ce7f08c566471d167678bedce")},
		{200000, newHashFromStr("000001763a9337328651ca57ac487cc0507087be5838fb74ca4165ff19f0e84f")},
		{250000, newHashFromStr("0dd54ef5f816c7fde9d2b1c8c1a26412b3c761cc5dd3901fa5c4cd1900892fba")},
		{300000, newHashFromStr("000000fa5efd1998959926047727519ed7de06dcf9f2cd92a4f71e907e1312dc")},
		{350000, newHashFromStr("0000000228ef321323f81dae00c98d7960fc7486fb2d881007fee60d1e34653f")},
		{400000, newHashFromStr("036d294c5be96f4c0efb28e652eb3968231e87204a823991a85c5fdab3c43ae6")},
		{450000, newHashFromStr("0906ef1e8dc194f1f03bd4ce1ac8c6992fd721ef2c5ccbf4871ec8cdbb456c18")},
		{500000, newHashFromStr("0bebdb417f7a51fe0c36fcf94e2ed29895a9a862eaa61601272866a7ecd6391b")},
		{550000, newHashFromStr("06df52fc5f9ba03ccc3a7673b01ab47990bd5c4947f6e1bc0ba14d21cd5bcccd")},
		{600000, newHashFromStr("00000005080d5689c3b4466e551cd1986e5d2024a62a79b1335afe12c42779e4")},
		{650000, newHashFromStr("039a3cb760cc6e564974caf69e8ae621c14567f3a36e4991f77fd869294b1d52")},
		{700000, newHashFromStr("00002285be912b2b887a5bb42d2f1aa011428c565b0ffc908129c47b5ce87585")},
		{750000, newHashFromStr("04cff4c26d185d591bed3613ce15e1d15d9c91dd8b98a6729f89c58ce4bd1fd6")},
		{800000, newHashFromStr("0000000617574d402fca8e6570f0845bd5fe449398b318b4e1f65bc69cdd6606")},
		{850000, newHashFromStr("044199301f37194f20ba7b498fc72ed742f6c0ba6e476f28d6c81d225e58d5ce")},
		{900000, newHashFromStr("08bdbe4de2a65ac89fd2913192d05362c900e3af476a0c99d9f311875067451e")},
		{950000, newHashFromStr("0000000aa9a44b593e6138f247bfae75bd43b9396ef9ff0a6a3ebd852f131806")},
		{1000000, newHashFromStr("0cb1d2457eaa58af5028e86e27ac54578fa09558206e7b868ebd35e7005ed8bb")},
		{1050000, newHashFromStr("044d49bbc3bd9d32b6288b768d4f7e0afe3cbeda606f3ac3579a076e4bddf6ae")},
		{1100000, newHashFromStr("000000050cad04887e170059dd2556d85bbd20390b04afb9b07fb62cafd647b4")},
		{1150000, newHashFromStr("0c85501c759d957dd1ccc5f7fdfcc415c89c7f2a26471fffc75b75f79e63c16a")},
		{1200000, newHashFromStr("0763cbf43ed7227988081c29d9e9fc7ab2450216e6d0354cc4596c86689702d4")},
		{1250000, newHashFromStr("0489640207f8c343a56a10e45d987516059ea82a3c6859a771b3a9cf94f5c3bb")},
		{1300000, newHashFromStr("000000012a01709b254b4f75e2b9ed772d8fe558655c8c859892ca8c9d625e87")},
		{1350000, newHashFromStr("075a1a5c66a68b47d9848ca6986687ed2665b1852457051bf142208e62f98a60")},
		{1400000, newHashFromStr("055f73dd9b20650c3d6e6dbb606af8d9479e4c81d89430867abff5329f167bb2")},
		{1450000, newHashFromStr("014c2926e07e9712211c5e82f05df1b802c59cc8bc24e3cc9b09942017080f2d")},
		{1500000, newHashFromStr("0791f892210ce3c513ab607d689cd1e8907a27f3dfeb58dec21ae299b7981cb7")},
		{1550000, newHashFromStr("08fcbaffb7164b161a25efc6dd5c70b679498ee637d663fe201a55c7decc37a3")},
		{1600000, newHashFromStr("0e577dcd49319a67fe2acbb39ae6d46afccd3009d3ba9d1bcf6c624708e12bac")},
		{1650000, newHashFromStr("091ac57a0f786a9526b2224a10b62f1f464b9ffc0afc2240d86264439e6ad3d0")},
		{1700000, newHashFromStr("0d0be6ab4a5083ce9d2a7ea2549b03cfc9770427b7d51c0bf0c603399a60d037")},
		{1750000, newHashFromStr("0a019d830157db596eeb678787279908093fd273a4e022b5e052f3a9f95714ca")},
		{1800000, newHashFromStr("0390779f6c615620391f9dd7df7f3f4947523bd6350b26625c0315571c616076")},
		{1850000, newHashFromStr("000000007ca2de1bd9cb7b52fe0accca4874143822521d955e58c73e304279e0")},
		{1900000, newHashFromStr("04c6589d5703f8237bf215c4e3e881c1c77063ef079cea5dc132a0e7f7a0cbd9")},
		{1950000, newHashFromStr("00000000386795b9fa21f14782ee1b9176763d6a544d7e0511d1860c62d540aa")},
		{2000000, newHashFromStr("0b0403fbe3c5742bbd0e3fc643049534e50c4a49bbc4a3b284fc0ecedf15c044")},
		{2050000, newHashFromStr("0c7923957469864d49a0be56b5ffbee7f21c1b6d00acc7374f60f1c1c7b87e14")},
		{2100000, newHashFromStr("05725ed166ae796529096ac2a42e85a3bdd0d69dbb2f69e620c08219fda1130a")},
		{2150000, newHashFromStr("0edb94f5a5501fc8dd72a455cdaccf0af0215b914dd3d8d4ae5d644e27ef562c")},
		{2200000, newHashFromStr("08b92203aa4a3b09001a75e8eebe8e64434259ae7ed7a31384203924d1ab03b8")},
		{2250000, newHashFromStr("0127d1ed5cd6f261631423275b6b17728c392583177e1151a6e638a4b0dea985")},
		{2300000, newHashFromStr("07df8af646bc30c71d068b146d9ea2c8b25b27a180e9537d5aef859efcfc41f7")},
		{2350000, newHashFromStr("0b8028dbfcd92fe34496953872cba2d256923e3e52b4abbdcbe9911071e929e5")},
		{2400000, newHashFromStr("0000000030f4e55dab91dc3528257fdddbbaec7e7e6f877d357654f07704d773")},
		{2450000, newHashFromStr("00000000b1cb8e9046e561486a5dbdb7fa06ac35c96f290653d1f0f4578d55c0")},
		{2500000, newHashFromStr("0d79a66e1e611b8b7070f924c6d23f41837caa6e2636d3e0e94fb74f4c0e7eaf")},
		{2550000, newHashFromStr("08ead55adf3253d8e7d4cc5eab3586bbc3bdbba9ae4104d13f0e9731350aa991")},
		{2600000, newHashFromStr("0665b6e23d60a892069fe12ccc3c6ec1f4b38bfd6c62ebbc88039d99492ec67d")},
		{2650000, newHashFromStr("0c0997bd2251d5aaa7d7509f49fd41ff8666f3d137cbe1b7695ec77afa95a977")},
		{2700000, newHashFromStr("02c317060b9ee983f30f33e21ae6973cda8c2746d38dff546a56341440fa0ff2")},
		{2750000, newHashFromStr("00000000d534909e2726aa0eb132cbd27894914de21f7e42942a11ce152bd0e8")},
		{2800000, newHashFromStr("0ce1585dfde5b561e4c436e9bceb3070681f033604df3ae5ee471fa37f93df40")},
		{2850000, newHashFromStr("000000000dd1a4cdc68d869d7bff1459c24950c2c49bfbc99379b1192189d9ff")},
		{2900000, newHashFromStr("0e476e4c8680723d5993c8d3241437eb496785a681bfee2723d48c8aca7e7775")},
		{2950000, newHashFromStr("02c2ad86947eb44eb0c341f62cbb42ee7604120736b59e3bf4ae7c15876116c6")},
		{3000000, newHashFromStr("000000000341c41238da4aa354c0b110c0dcb406c77ae88c6cbe1af9279e5ad5")},
		{3050000, newHashFromStr("06201c395a0e570e7efe63e8c406a57ba01ee1e7994a496aa7314d66c46f4d03")},
		{3100000, newHashFromStr("0cc9d173d3062e7bd02fe3880f6647c12be5e4fbc0d54bbc57fb630a4d27b152")},
		{3150000, newHashFromStr("0bc9aacb5b61ce72269156ef1c3d097b3866c1d41f9204eda0565c71e6f28765")},
		{3200000, newHashFromStr("0000000086d9a4cd07bab1c621f626c8b56fdb4502b47294d84215a263c74e72")},
		{3250000, newHashFromStr("05c1d8fff5449019ebf0dfc442fb6ab08aa8acb46c3fde0e9913a17feac897d9")},
		{3300000, newHashFromStr("0549e87f0f3f028e10e20f6844e5d4605ad2a26e810d671ae516ee33328eda94")},
		{3350000, newHashFromStr("0000000016335c6ac62b78d90dcc14a7e73fb71484bf18974ba13449fc223f4b")},
		{3400000, newHashFromStr("0a7db2957f5122f54351ffa79e0399788b180628daa440be63230454ab6ebdbe")},
		{3450000, newHashFromStr("0ed55d5048453070204e5301a194980aa6632dc53bf1fb3f5a38bcc127229751")},
		{3500000, newHashFromStr("00000000058ded4878267a04562fba5f5455f3f015d0befc30f18a2a5363293c")},
		{3550000, newHashFromStr("008e33e444039a184a27b083526a963f792f5053a1811cd8fde6aac0954a3925")},
		{3600000, newHashFromStr("09a6622ca9c61abcd2e20c5bedfd3c975803ae8c1fb913f61be9ba3e82916791")},
		{3648244, newHashFromStr("002fdc2c0a087b8b4075268c8caf97571ac9b0908aa6dde37077ad179dc614ee")},
	},
	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,

	// Address encoding magics
	PubKeyHashAddrID: 60,
	ScriptHashAddrID: 85,
	PrivateKeyID:     188,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xb2, 0x1e},
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xad, 0xe4},
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var RegtestParams = Params{
	Name:        "regtest",
	Net:         wire.Regtest,
	DefaultPort: "19133",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:     &regTestGenesisBlock,
	GenesisHash:      &regtestGenesisHash,
	BIP0034Height:    0,
	BIP0065Height:    0,
	BIP0066Height:    0,
	CoinbaseMaturity: 100,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{0, newHashFromStr("0da5ee723b7923feb580518541c6f098206330dbc711a6678922c11f2ccf1abb")},
	},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       144,

	// Address encoding magics
	PubKeyHashAddrID: 0x2098, // starts with m or n
	ScriptHashAddrID: 0x2092, // starts with 2
	PrivateKeyID:     0xef,   // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")

	// ErrInvalidHDKeyID describes an error where the provided hierarchical
	// deterministic version bytes, or hd key id, is malformed.
	ErrInvalidHDKeyID = errors.New("invalid hd extended key version bytes")
)

var (
	registeredNets       = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs    = make(map[uint16]struct{})
	scriptHashAddrIDs    = make(map[uint16]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}

	err := RegisterHDKeyID(params.HDPublicKeyID[:], params.HDPrivateKeyID[:])
	if err != nil {
		return err
	}

	// A valid Bech32 encoded segwit address always has as prefix the
	// human-readable part for the given net followed by '1'.
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id uint16) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id uint16) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// RegisterHDKeyID registers a public and private hierarchical deterministic
// extended key ID pair.
//
// Non-standard HD version bytes, such as the ones documented in SLIP-0132,
// should be registered using this method for library packages to lookup key
// IDs (aka HD version bytes). When the provided key IDs are invalid, the
// ErrInvalidHDKeyID error will be returned.
//
// Reference:
//   SLIP-0132 : Registered HD version bytes for BIP-0032
//   https://github.com/satoshilabs/slips/blob/master/slip-0132.md
func RegisterHDKeyID(hdPublicKeyID []byte, hdPrivateKeyID []byte) error {
	if len(hdPublicKeyID) != 4 || len(hdPrivateKeyID) != 4 {
		return ErrInvalidHDKeyID
	}

	var keyID [4]byte
	copy(keyID[:], hdPrivateKeyID)
	hdPrivToPubKeyIDs[keyID] = hdPublicKeyID

	return nil
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&RegtestParams)
	mustRegister(&RegressionNetParams)
}
