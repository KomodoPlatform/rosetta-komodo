// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"fmt"

	"github.com/DeckerSU/rosetta-komodo/komodoutil/base58"
)

// This example demonstrates how to decode modified base58 encoded data.
func ExampleDecode() {
	// Decode example modified base58 encoded data.
	encoded := "25JnwSn7XKfNQ"
	decoded := base58.Decode(encoded)

	// Show the decoded data.
	fmt.Println("Decoded Data:", string(decoded))

	// Output:
	// Decoded Data: Test data
}

// This example demonstrates how to encode data using the modified base58
// encoding scheme.
func ExampleEncode() {
	// Encode example data with the modified base58 encoding scheme.
	data := []byte("Test data")
	encoded := base58.Encode(data)

	// Show the encoded data.
	fmt.Println("Encoded Data:", encoded)

	// Output:
	// Encoded Data: 25JnwSn7XKfNQ
}

// This example demonstrates how to decode Base58Check encoded data.
func ExampleCheckDecode() {
	// Decode an example Base58Check encoded data.
	encoded := "RLaSC1WFwLEKSBka2LN7rX3nrCcbX2vbn4"
	decoded, version, err := base58.CheckDecode(encoded)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Show the decoded data.
	fmt.Printf("Decoded data: %x\n", decoded)
	fmt.Println("Version Byte:", version)

	// Output:
	// Decoded data: 7bec3c2b8f04ddbda3c238e3eae6fbcffa757a25
	// Version Byte: 60
}

// This example demonstrates how to encode data using the Base58Check encoding
// scheme.
func ExampleCheckEncode() {
	// Encode example data with the Base58Check encoding scheme.
	data := []byte{
		0x7b, 0xec, 0x3c, 0x2b, 0x8f, 0x04, 0xdd, 0xbd, 0xa3, 0xc2, 0x38, 0xe3, 0xea, 0xe6, 0xfb, 0xcf, 0xfa, 0x75, 0x7a, 0x25,
	}
	encoded := base58.CheckEncode(data, 60)

	// Show the encoded data.
	fmt.Println("Encoded Data:", encoded)

	// Output:
	// Encoded Data: RLaSC1WFwLEKSBka2LN7rX3nrCcbX2vbn4
}
