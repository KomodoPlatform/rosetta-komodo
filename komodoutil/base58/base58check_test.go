// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"testing"

	"github.com/DeckerSU/rosetta-komodo/komodoutil/base58"
)

var checkEncodingStringTests = []struct {
	version byte
	in      string
	out     string
}{
	{60, "", "7rLnRLD"},
	{60, " ", "WwehhPts"},
	{60, "-", "Wy3QJvAz"},
	{60, "0", "WyTagpXB"},
	{60, "1", "WyWiavip"},
	{60, "-1", "3HGLY1vtMX"},
	{60, "11", "3HJL1BrnWA"},
	{60, "abc", "B6mQSY3jaz6"},
	{60, "1234598760", "2gfwmkMXD94oQG5xfVoEU"},
	{60, "abcdefghijklmnopqrstuvwxyz", "vQF5toxmgBwCrqy4KXKCqtnVsb2Xw7zTeabKigpzD4"},
	{60, "00000000000000000000000000000000000000000000000000000000000000", "2nUUTtgWGX9jjQ1mQpZH9EVa4gPgXTCTeNwEnWKwTum13bB89q5SRE2zY1eqC6VtxfFVBq2GbM8eJD5qcYcY7z4WzSxX"},
}

func TestBase58Check(t *testing.T) {
	for x, test := range checkEncodingStringTests {
		// test encoding
		if res := base58.CheckEncode([]byte(test.in), test.version); res != test.out {
			t.Errorf("CheckEncode test #%d failed: got %s, want: %s", x, res, test.out)
		}

		// test decoding
		res, version, err := base58.CheckDecode(test.out)
		if err != nil {
			t.Errorf("CheckDecode test #%d failed with err: %v", x, err)
		} else if version != test.version {
			t.Errorf("CheckDecode test #%d failed: got version: %d want: %d", x, version, test.version)
		} else if string(res) != test.in {
			t.Errorf("CheckDecode test #%d failed: got: %s want: %s", x, res, test.in)
		}
	}

	// test the two decoding failure cases
	// case 1: checksum error
	_, _, err := base58.CheckDecode("3MNQE1Y")
	if err != base58.ErrChecksum {
		t.Error("Checkdecode test failed, expected ErrChecksum")
	}
	// case 2: invalid formats (string lengths below 5 mean the version byte and/or the checksum
	// bytes are missing).
	testString := "x"
	for len := 0; len < 3; len++ {
		testString = testString + "x"
		_, _, err = base58.CheckDecode(testString)
		if err != base58.ErrInvalidFormat {
			t.Error("Checkdecode test failed, expected ErrInvalidFormat")
		}
	}

}
