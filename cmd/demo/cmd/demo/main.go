package main

import (
	"fmt"

	"github.com/sergelen02/hppk-ds/internal/hppkds"
)

func main() {
	pp := hppkds.LevelI()
	sk, pk := hppkds.KeyGen(pp, []byte("keygen-seed"))
	msg := []byte("hello-phaseA")
	sig, err := hppkds.Sign(pp, sk, msg, []byte("alpha-seed"))
	if err != nil {
		panic(err)
	}
	ok, err := hppkds.Verify(pp, pk, msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify:", ok)
}
