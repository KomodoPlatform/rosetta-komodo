package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/dgraph-io/badger/v2"
)

func addressToAccountInternal(address string) (string, error) {

	addressJSON, err := json.Marshal(map[string]string{"address": address})
	if err != nil {
		return "", err
	}

	hexStr := hex.EncodeToString(addressJSON)
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	sha256Hash := sha256.Sum256(hexBytes)
	return hex.EncodeToString(sha256Hash[:]), nil
}

func main() {
	db, err := badger.Open(badger.DefaultOptions("/data/indexer"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Example: how to convert address to hash for coin-account keys search
	address := "RGBEt22GeFXRvZjfZpvzo68aaxEUtAFZg8"
	hashResult, err := addressToAccountInternal(address)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Address: %s, Coin-Account Hash: %s\n", address, hashResult)
	}

	pattern := "685c488a2d97da7cbc111f7dcde880997cbf578636d15653b64377b07dd54a0f"

	err = db.View(func(txn *badger.Txn) error {

		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // Set to false if only keys are needed
		//opts.Prefix = []byte(prefix)

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			//for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			if stringContainsPattern(key, pattern) {
				if strings.HasPrefix(string(key), "bal") || strings.HasPrefix(string(key), "hbal") {

					// just as an example, probably bal/hbal need other endianless
					err := item.Value(func(val []byte) error {
						if len(val) < 4 {
							return fmt.Errorf("value is too short to be an int32")
						}
						intValue := uint32(binary.LittleEndian.Uint32(val))
						fmt.Printf("Key: %s, Value: %d\n", key, intValue)
						return nil
					})
					if err != nil {
						return err
					}
				} else {

					err := item.Value(func(val []byte) error {
						fmt.Printf("Key: %s, Value: %s\n", key, val)
						return nil
					})
					if err != nil {
						return err
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
}

func stringContainsPattern(data []byte, pattern string) bool {
	return bytes.Contains(data, []byte(pattern))
}
