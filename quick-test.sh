#!/bin/bash

# RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj
# 032ba2d26c2c0ecaf03464f7b3ba2b3893699fdbdc17d5f7eb9812ab58743f1c03
# UrLfd36SDu1iyhCWYKird3SRGRRaPsfPNkjzAtoTf7wreoheQgvT

# createmultisig 1 '["032ba2d26c2c0ecaf03464f7b3ba2b3893699fdbdc17d5f7eb9812ab58743f1c03"]'
# bKtMwYNKZ9DNVjSxvXmEBiQ8hLQBoeRCvj
# 5121032ba2d26c2c0ecaf03464f7b3ba2b3893699fdbdc17d5f7eb9812ab58743f1c0351ae
# a9144e8100ff98ae296d1c9d1a7dfa17c2ac31588a0187
# OP_HASH160 4e8100ff98ae296d1c9d1a7dfa17c2ac31588a01 OP_EQUAL

#  "RXL3YXG2ceaB6C5hfJcN4fvmLH2C34knhA"

API_ENDPOINT=127.0.0.1:8000

if false; then
    addresses=("RMUCCfZf42bEP1HvJsRjbXyYHkKusJsf4s" "RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj")

    for address in "${addresses[@]}"; do
        res1=$(curl -s -L -X POST 'http://'${API_ENDPOINT}'/account/balance' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-raw '{"network_identifier":{"blockchain":"Komodo","network":"main"},"account_identifier":{"address":"'${address}'"}}' | jq -r .balances[0].value)

        res2=$(curl -s -L -X GET 'https://kmdexplorer.io/insight-api-komodo/addr/'${address}'/balance')

        if [ "$res1" -eq "$res2" ]; then
            echo "✅ Balance: $address: $res1"
        else
            echo "❌ Balance in explorer and in API instance is different! ${res1} != ${res2}"
        fi
    done
fi

address=$(curl -s -L -X POST 'http://'${API_ENDPOINT}'/construction/derive' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
--data-raw '{"network_identifier":{"blockchain":"Komodo","network":"main"},"public_key":{"hex_bytes":"032ba2d26c2c0ecaf03464f7b3ba2b3893699fdbdc17d5f7eb9812ab58743f1c03","curve_type":"secp256k1"}}' | jq -r .address)
if [[ $address == "RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj" ]]; then
    echo "✅ The address matches."
else
    echo "❌ The address does not match. (${address})"
fi

curl -s -L -X POST 'http://'${API_ENDPOINT}'/account/balance' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-raw '{"network_identifier":{"blockchain":"Komodo","network":"main"},"account_identifier":{"address":"RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj"}}' | jq .

curl -v -L -X POST 'http://'${API_ENDPOINT}'/construction/payloads' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
--data-raw '{
    "network_identifier": {
        "blockchain": "Komodo",
        "network": "main"
    },
    "public_keys":[{
        "hex_bytes":"032ba2d26c2c0ecaf03464f7b3ba2b3893699fdbdc17d5f7eb9812ab58743f1c03",
        "curve_type":"secp256k1"}
    ],
    "operations": [
        {
            "operation_identifier": {
                "index": 0
            },
            "type": "INPUT",
            "account": {
                "address": "RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj"
            },
            "amount": {
                "value": "-50000000",
                "currency": {
                    "symbol": "KMD",
                    "decimals": 8
                }
            },
            "coin_change": {
                "coin_identifier": {
                    "identifier": "1515a68eb1d64bd92499d639229bebf5075216090eaaff4c5afc270772176b6a:0"
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
                "address": "RB8kzeTovoBpxgzmG3xaFDZWimC2PU8pKj"
            },
            "amount": {    
                "value": "39980000",
                "currency": {
                    "symbol": "KMD",
                    "decimals": 8
                }
            }
        }
    ]
}';
# 0400008085202f89037882b132b244f3910fcb3ffbfe69498e40fa7da823e08b465d8ccfc975dcba45010000006a4730440220480e05f7ed486c83e77db424923e0e8ec30f4fca8fcf95a9b4b83b2254018ce602203643aed2635fea279afa91a87c780132dbb1045c767fbeb8f465c06a7fd8e967012103de25408efa876cde9d42bb6a99b0ac6d2a4de9e5073165f64acf7198627e426dffffffff1ea6b748b82d869d9a7c39665918b0d635e13581bfa8d00a557dec51901d1d22000000006a4730440220544b309f8b3893ff63e422e06b10089d666d487d8b2879d4cec6b2a47c39600502203f92c8ce98994711e54e4161953da96de7d8b3bdf03679b1bd72c5dff3fd60ac012103de25408efa876cde9d42bb6a99b0ac6d2a4de9e5073165f64acf7198627e426dffffffff572953c3b0cff747cc303a2a86d418d23c110a64e0fd7ca1baad9c75539cf4ad000000006a47304402206b872aa9a968ff675839fe3d55eec0ecf01ea9263a6705e7e5d641bcc353f272022014c060a3ab5f5e82a514e2f9eabb334ed35ef4ed23a7dfd72e484abedf2307cc012103de25408efa876cde9d42bb6a99b0ac6d2a4de9e5073165f64acf7198627e426dffffffff0271cba204000000001976a9141457fc1ea749025759c40aad94bb2ef595b13b3088ace879360d000000001976a91485b630193f8d9025495f51b4a3f884d32b92fa1d88acfc44f465000000000000000000000000000000

# curl -s -L -X POST 'http://'${API_ENDPOINT}'/construction/parse' \
# -H 'Content-Type: application/json' \
# -H 'Accept: application/json' \
# --data-raw '{"network_identifier":{"blockchain":"Komodo","network":"main"},"transaction":""}'


# P2PKH
# echo "76a914f1dce4182fce875748c4986b240ff7d7bc3fffb088ac" | sed -E 's/^76a914|88ac$//g; s/../0x&, /g; s/, $//'
# P2SH
# echo "a9144e8100ff98ae296d1c9d1a7dfa17c2ac31588a0187" | sed -E 's/^a914|87$//g; s/../0x&, /g; s/, $//'

#
# echo "04a854251adfee222bede8396fed0756985d4ea905f72611740867c7a4ad6488c1767ae7bed159fca39dc26e2f9de31817bd32e0d6c5a870801bcd81fb7f1c2030" | sed -E 's/../0x&, /g; s/, $//'
# echo "907ece717a8f94e07de7bf6f8b3e9f91abb8858ebf831072cdbb9016ef53bc5d" | sed -E 's/../0x&, /g; s/, $//'
# echo "02a854251adfee222bede8396fed0756985d4ea905f72611740867c7a4ad6488c1" | sed -E 's/../0x&, /g; s/, $//'

