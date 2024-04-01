package address_converter

// simple address converter to KMD (Komodo) address
// go get github.com/btcsuite/btcutil/base58

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcutil/base58"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run address-converter.go <address>")
	}
	address := os.Args[1]
	decoded := base58.Decode(address)
	if len(decoded) < 6 {
		log.Fatal("Invalid address length")
	}
	network_bytes_len := len(decoded) - 4 - 20
	trimmed := decoded[network_bytes_len : len(decoded)-4]

	fmt.Printf("Trimmed 20-byte slice: %x\n", trimmed)
	prefixed := append([]byte{0x3C}, trimmed...)
	checksum := checksum(prefixed)
	fullAddress := append(prefixed, checksum[:4]...)
	finalAddress := base58.Encode(fullAddress)
	fmt.Println("Converted address:", finalAddress)
}

func checksum(input []byte) []byte {
	firstSHA := sha256.Sum256(input)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:]
}
