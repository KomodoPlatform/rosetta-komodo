- https://github.com/dajohi/dcrdex/blob/3f200df2a2de03501076f8a7351d513ed196887b/dex/networks/zec/tx.go#L61
- https://github.com/guardawallet/lightwalletd/blob/0d3b4ec36faac0bcb4d9dde96ecdd69502f2636e/parser/transaction.go#L187
- https://github.com/dajohi/dcrdex/commit/f6cccaa6a3d29059613ca02f4bbcefa0fb35d7e1
- https://github.com/renproject/mercury/blob/de07b07e33c539d79e356ebe5792036090486dc1/types/btctypes/zec.go#L30
- https://github.com/zcash/zcash/blob/cc815528eda4dd228951bf84bef649f7a9ef0591/src/primitives/transaction.h#L537
- https://github.com/DeckerSU/KomodoOcean/blob/281f59e32f3ce9914cb21746e1a885549aa8d962/src/primitives/transaction.h#L599

Bitcoin Tests
-------------


Only for tests:
```
bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx
17puWhTHhsSpzEBokTZRE8nweri7BQM1Z9
4ae023c5debe8f33c462ecf83b2b05dbc9616f20 (hash160, reedem script)
021088c1fcb881ed6e97fa092a0bf2c343579bd5767cc181f91488d858e10443ce
KxMJNxZEA4kqqemaVUzq6rXaurxsEvgCMoUi8fPxvqU3gUpeunJ3
```

Request:

http://127.0.0.1:8100/account/balance
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "account_identifier": {
    "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx"
  }
}
```

Response:
```
{
  "block_identifier": {
    "index": 421981,
    "hash": "0000000000000000036e64048915ea5561e8f42474c805ac6ae3a1885705d546"
  },
  "balances": [
    {
      "value": "0",
      "currency": {
        "symbol": "BTC",
        "decimals": 8
      }
    }
  ]
}
```
Request:

http://127.0.0.1:8100/construction/derive
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "public_key": {
    "hex_bytes": "021088c1fcb881ed6e97fa092a0bf2c343579bd5767cc181f91488d858e10443ce",
    "curve_type":"secp256k1"
  }
}
```
Response:
```
{
  "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx",
  "account_identifier": {
    "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx"
  }
}
```
Request:

http://127.0.0.1:8100/construction/preprocess
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "operations": [
    {
      "operation_identifier": {
        "index": 0
      },
      "type": "INPUT",
      "account": {
        "address": "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
      },
      "amount": {
        "value": "-1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      },
      "coin_change": {
        "coin_identifier": {
          "identifier": "7c668549d08fa8fbda748ba33c80827f1b289502b68b780d0ea92a80d66052f2:0"
        },
        "coin_action": "coin_spent"
      }
    },
    {
      "operation_identifier": {
        "index": 1
      },
      "type": "OUTPUT",
      "account": {
        "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx"
      },
      "amount": {
        "value": "1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      }
    }
  ]
}
```
Response:
```
{
  "options": {
    "coins": [
      {
        "coin_identifier": {
          "identifier": "7c668549d08fa8fbda748ba33c80827f1b289502b68b780d0ea92a80d66052f2:0"
        },
        "amount": {
          "value": "-1254993446",
          "currency": {
            "symbol": "BTC",
            "decimals": 8
          }
        }
      }
    ],
    "estimated_size": 111
  }
}
```

Request:

http://127.0.0.1:8100/construction/metadata
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "options": {
    "coins": [
      {
        "coin_identifier": {
          "identifier": "7c668549d08fa8fbda748ba33c80827f1b289502b68b780d0ea92a80d66052f2:0"
        },
        "amount": {
          "value": "-1254993446",
          "currency": {
            "symbol": "BTC",
            "decimals": 8
          }
        }
      }
    ],
    "estimated_size": 111
  }
}
```

Response:
```
{
  "metadata": {
    "script_pub_keys": [
      {
        "asm": "OP_DUP OP_HASH160 35df7e6daa60393b0ed2474a21713a845a2212dd OP_EQUALVERIFY OP_CHECKSIG",
        "hex": "76a91435df7e6daa60393b0ed2474a21713a845a2212dd88ac",
        "reqSigs": 1,
        "type": "pubkeyhash",
        "addresses": [
          "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
        ]
      }
    ]
  },
  "suggested_fee": [
    {
      "value": "111",
      "currency": {
        "symbol": "BTC",
        "decimals": 8
      }
    }
  ]
}
```

Request:
http://127.0.0.1:8100/construction/payloads
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "operations": [
    {
      "operation_identifier": {
        "index": 0
      },
      "type": "INPUT",
      "account": {
        "address": "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
      },
      "amount": {
        "value": "-1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      },
      "coin_change": {
        "coin_identifier": {
          "identifier": "7c668549d08fa8fbda748ba33c80827f1b289502b68b780d0ea92a80d66052f2:0"
        },
        "coin_action": "coin_spent"
      }
    },
    {
      "operation_identifier": {
        "index": 1
      },
      "type": "OUTPUT",
      "account": {
        "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx"
      },
      "amount": {
        "value": "1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      }
    }
  ],
  "metadata": {
    "script_pub_keys": [
      {
        "asm": "OP_DUP OP_HASH160 35df7e6daa60393b0ed2474a21713a845a2212dd OP_EQUALVERIFY OP_CHECKSIG",
        "hex": "76a91435df7e6daa60393b0ed2474a21713a845a2212dd88ac",
        "reqSigs": 1,
        "type": "pubkeyhash",
        "addresses": [
          "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
        ]
      }
    ]
  }
}
```

Response:
```
{
  "unsigned_transaction": "7b227472616e73616374696f6e223a223031303030303030303166323532363064363830326161393065306437383862623630323935323831623766383238303363613338623734646166626138386664303439383536363763303030303030303030306666666666666666303132366165636434613030303030303030313630303134346165303233633564656265386633336334363265636638336232623035646263393631366632303030303030303030222c227363726970745075624b657973223a5b7b2261736d223a224f505f445550204f505f484153483136302033356466376536646161363033393362306564323437346132313731336138343561323231326464204f505f455155414c564552494659204f505f434845434b534947222c22686578223a223736613931343335646637653664616136303339336230656432343734613231373133613834356132323132646438386163222c2272657153696773223a312c2274797065223a227075626b657968617368222c22616464726573736573223a5b2231357572596e79654a6533677762474a37347763583839547a375a74734644566577225d7d5d2c22696e7075745f616d6f756e7473223a5b222d31323534393933343436225d2c22696e7075745f616464726573736573223a5b2231357572596e79654a6533677762474a37347763583839547a375a74734644566577225d7d",
  "payloads": [
    {
      "address": "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew",
      "hex_bytes": "7a2d933980fee42e8c26d85c9939d0454d4401f1bda0cee3ecaa36c3dbf3c52c",
      "account_identifier": {
        "address": "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
      },
      "signature_type": "ecdsa"
    }
  ]
}
```

Request:
http://127.0.0.1:8100/construction/parse
```
{
  "network_identifier": {
    "blockchain": "Bitcoin",
    "network": "Mainnet"
  },
  "transaction": "7b227472616e73616374696f6e223a223031303030303030303166323532363064363830326161393065306437383862623630323935323831623766383238303363613338623734646166626138386664303439383536363763303030303030303030306666666666666666303132366165636434613030303030303030313630303134346165303233633564656265386633336334363265636638336232623035646263393631366632303030303030303030222c227363726970745075624b657973223a5b7b2261736d223a224f505f445550204f505f484153483136302033356466376536646161363033393362306564323437346132313731336138343561323231326464204f505f455155414c564552494659204f505f434845434b534947222c22686578223a223736613931343335646637653664616136303339336230656432343734613231373133613834356132323132646438386163222c2272657153696773223a312c2274797065223a227075626b657968617368222c22616464726573736573223a5b2231357572596e79654a6533677762474a37347763583839547a375a74734644566577225d7d5d2c22696e7075745f616d6f756e7473223a5b222d31323534393933343436225d2c22696e7075745f616464726573736573223a5b2231357572596e79654a6533677762474a37347763583839547a375a74734644566577225d7d"
}
```
Response:
```
{
  "operations": [
    {
      "operation_identifier": {
        "index": 0,
        "network_index": 0
      },
      "type": "INPUT",
      "account": {
        "address": "15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"
      },
      "amount": {
        "value": "-1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      },
      "coin_change": {
        "coin_identifier": {
          "identifier": "7c668549d08fa8fbda748ba33c80827f1b289502b68b780d0ea92a80d66052f2:0"
        },
        "coin_action": "coin_spent"
      }
    },
    {
      "operation_identifier": {
        "index": 1,
        "network_index": 0
      },
      "type": "OUTPUT",
      "account": {
        "address": "bc1qftsz83w7h68n83rzanurk2c9m0ykzmequy3sfx"
      },
      "amount": {
        "value": "1254993446",
        "currency": {
          "symbol": "BTC",
          "decimals": 8
        }
      }
    }
  ]
}
```


```
{"transaction":"0100000001f25260d6802aa90e0d788bb60295281b7f82803ca38b74dafba88fd04985667c0000000000ffffffff0126aecd4a000000001600144ae023c5debe8f33c462ecf83b2b05dbc9616f2000000000","scriptPubKeys":[{"asm":"OP_DUP OP_HASH160 35df7e6daa60393b0ed2474a21713a845a2212dd OP_EQUALVERIFY OP_CHECKSIG","hex":"76a91435df7e6daa60393b0ed2474a21713a845a2212dd88ac","reqSigs":1,"type":"pubkeyhash","addresses":["15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"]}],"input_amounts":["-1254993446"],"input_addresses":["15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew"]}
```



System parameters:
```
/usr/sbin/sysctl net.ipv4.tcp_tw_reuse
/usr/sbin/sysctl net.core.rmem_max
/usr/sbin/sysctl net.core.wmem_max
/usr/sbin/sysctl net.ipv4.tcp_max_syn_backlog
/usr/sbin/sysctl net.core.somaxconn

net.ipv4.tcp_tw_reuse = 2
net.core.rmem_max = 212992
net.core.wmem_max = 212992
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sudo sysctl -w net.core.somaxconn=10000
```
