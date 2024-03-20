/* 
    Node JS Example how to calculate sapling sighash. 
    Deps: bitgo-utxo-lib

    nvm use  v18.16.1
    npm install debug
    npm install git+https://github.com/DeckerSU/bitgo-utxo-lib.git
*/

process.env['DEBUG'] = '*';
var debug = require('debug')('decker:server');

debug('I ❤️ Komodo :)')

const bitcoinZcashSapling = require('bitgo-utxo-lib'); 
const rawtx = "0400008085202f8901e74e10852371d539e7e4f512a55ac39c94b293972475df0eea814f6e7b4116290000000000ffffffff01611e0000000000001976a914dc5abb3c56eba571a0910fe18fa8f205d29a06e388ac0000000038d23a000000000000000000000000";

const komodo_network = {
    messagePrefix: '\x18ZCash Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 60,
    scriptHash: 85,
    wif: 188,
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: bitcoinZcashSapling.coins.ZEC
  };

const network = komodo_network;

const buildFromHex = true;

if (buildFromHex) {
    // (1)
    tx = new bitcoinZcashSapling.TransactionBuilder.fromTransaction(bitcoinZcashSapling.Transaction.fromHex(rawtx, network), network);
    /*
    // for (1)
    tx.inputs = [ {} ]; // if tx in TransactionBuilder is "copied" from another tx via fromTransaction we should do a small hack to clean inputs array (!),
    // if we have just one input tx.inputs = [ {} ], if two - tx.inputs = [ {}, {} ] and and so on.  if tx is built "from scratch" - no actions required,
    // tx.inputs is already in needed state for sign.
    */

    //debug(tx);
    //debug(tx.tx.ins);
    //debug(tx.tx.ins.script);
} else {
    // (2)
    tx = new bitcoinZcashSapling.TransactionBuilder(network);

    tx.setVersion(4);
    tx.setVersionGroupId(0x892F2085);
    tx.setLockTime(0);
    tx.setExpiryHeight(3854904);

    // .reverse()
    tx.addInput(Buffer.from('2916417b6e4f81ea0edf75249793b2949cc35aa512f5e4e739d5712385104ee7','hex').toString('hex'), 0, 0xFFFFFFFF);
    tx.addOutput(Buffer.from('76a914dc5abb3c56eba571a0910fe18fa8f205d29a06e388ac', 'hex'), 7777);
}

const keyPair = bitcoinZcashSapling.ECPair.fromWIF("UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh", network);
console.log(keyPair.getPrivateKeyBuffer().toString('hex'));
console.log(keyPair.getPublicKeyBuffer().toString('hex'));
console.log(keyPair.getAddress());
console.log(keyPair.toWIF());

const hashType = bitcoinZcashSapling.Transaction.SIGHASH_ALL;

// inIndex, prevOutScript, value, hashType
var sighash = tx.tx.hashForZcashSignature(0, Buffer.from('76a914dc5abb3c56eba571a0910fe18fa8f205d29a06e388ac' , 'hex'), 7777, hashType).toString('hex');
console.log("sighash: " + sighash);

// vin, keyPair, redeemScript, hashType, witnessValue, witnessScript
tx.sign(0, keyPair, '', hashType, 7777); 

//const hex = tx.build().toHex(); 
const hex = tx.buildIncomplete().toHex();
console.log(hex);


