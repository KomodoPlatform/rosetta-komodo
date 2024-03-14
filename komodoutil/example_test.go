package komodoutil_test

import (
	"fmt"
	"math"

	"github.com/DeckerSU/rosetta-komodo/komodoutil"
)

func ExampleAmount() {

	a := komodoutil.Amount(0)
	fmt.Println("Zero Kmdtoshi:", a)

	a = komodoutil.Amount(1e8)
	fmt.Println("100,000,000 Kmdtoshi:", a)

	a = komodoutil.Amount(1e5)
	fmt.Println("100,000 Kmdtoshi:", a)
	// Output:
	// Zero Kmdtoshi: 0 KMD
	// 100,000,000 Kmdtoshi: 1 KMD
	// 100,000 Kmdtoshi: 0.001 KMD
}

func ExampleNewAmount() {
	amountOne, err := komodoutil.NewAmount(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountOne) //Output 1

	amountFraction, err := komodoutil.NewAmount(0.01234567)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountFraction) //Output 2

	amountZero, err := komodoutil.NewAmount(0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountZero) //Output 3

	amountNaN, err := komodoutil.NewAmount(math.NaN())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountNaN) //Output 4

	// Output: 1 KMD
	// 0.01234567 KMD
	// 0 KMD
	// invalid komodo amount
}

func ExampleAmount_unitConversions() {
	amount := komodoutil.Amount(44433322211100)

	fmt.Println("Kmdtoshi to kKMD:", amount.Format(komodoutil.AmountKiloKMD))
	fmt.Println("Kmdtoshi to KMD:", amount)
	fmt.Println("Kmdtoshi to MilliKMD:", amount.Format(komodoutil.AmountMilliKMD))
	fmt.Println("Kmdtoshi to MicroKMD:", amount.Format(komodoutil.AmountMicroKMD))
	fmt.Println("Kmdtoshi to Kmdtoshi:", amount.Format(komodoutil.AmountKMDtoshi))

	// Output:
	// Kmdtoshi to kKMD: 444.333222111 kKMD
	// Kmdtoshi to KMD: 444333.222111 KMD
	// Kmdtoshi to MilliKMD: 444333222.111 mKMD
	// Kmdtoshi to MicroKMD: 444333222111 μKMD
	// Kmdtoshi to Kmdtoshi: 44433322211100 Kmdtoshi
}
