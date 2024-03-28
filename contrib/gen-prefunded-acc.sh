#!/bin/bash
#
# (c) Decker, 2024
#

API_ENDPOINT=127.0.0.1:8000

# Declare an array of required tools
required_tools=("openssl" "base58" "rosetta-cli" "qrencode")

# Loop through the array and check each tool
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "$tool could not be found. Please install it and try again."
        exit 1
    fi
done

# Run the rosetta-cli key generation command and capture the output
output=$(rosetta-cli key:gen --curve-type secp256k1)

# Use grep and awk to extract the private and public keys
privKey=$(echo "$output" | grep 'Private Key' | awk '{ print $NF }')
pubKey=$(echo "$output" | grep 'Public Key' | awk '{ print $NF }')

# Store the keys in variables
PRIVATE_KEY="$privKey"
PUBLIC_KEY="$pubKey"

# Print the keys to verify
echo "Private Key: $PRIVATE_KEY"
echo "Public Key: $PUBLIC_KEY"

address=$(curl -s -L -X POST 'http://'${API_ENDPOINT}'/construction/derive' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
--data-raw '{"network_identifier":{"blockchain":"Komodo","network":"main"},"public_key":{"hex_bytes":"'${PUBLIC_KEY}'","curve_type":"secp256k1"}}' | jq -r .address)

echo "Address: $address"

pubkey_hex=${PUBLIC_KEY}
privkey_hex=${PRIVATE_KEY}

network_byte_hex="3c" #  60 (dec) KMD (Komodo)
secret_key_hex="bc"   # 188 (dec) KMD (Komodo)

hash160_hex=$(echo -n "${pubkey_hex}" | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -provider=legacy -rmd160 -binary | xxd -p -c 20)
if [ "${#hash160_hex}" -ne "40" ]; then
    echo "Error obtaining rmd-160 ..." 1>&2
    exit
fi
echo "rmd-160 (hex): $hash160_hex (${#hash160_hex})"
checksum_hex=$(echo -n "${network_byte_hex}${hash160_hex}" | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -sha256 -binary | xxd -p -c 32)
address=$(echo -n "${network_byte_hex}${hash160_hex}${checksum_hex:0:8}" | xxd -r -p | base58)
echo "      Address: ${address}"

wif_checksum_hex=$(echo -n "${secret_key_hex}${privkey_hex}01" | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -sha256 -binary | xxd -p -c 32)
wif=$(echo -n "${secret_key_hex}${privkey_hex}01${wif_checksum_hex:0:8}" | xxd -r -p | base58)
echo "          WIF: ${wif}"

echo
qrencode -t ANSIUTF8 ${address}
