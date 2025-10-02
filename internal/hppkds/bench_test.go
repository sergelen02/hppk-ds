package hppkds

import (
	"os"
	"strconv"
	"testing"
)

var sinkSig *Signature
var sinkOK  bool

func cpuGHz() float64 {
	if s := os.Getenv("CPU_GHZ"); s!="" {
		if f,err := strconv.ParseFloat(s,64); err==nil { return f }
	}
	return 3.0 // 기본값
}

func Benchmark_Sign(b *testing.B) {
	pp := LevelI()
	sk, _ := KeyGen(pp, []byte("keygen-seed"))
	msg := []byte("HPPK-phaseA")
	b.ReportAllocs()
	for i:=0;i<b.N;i++{
		sinkSig, _ = Sign(pp, sk, msg, []byte("alpha-seed"))
	}
}
func Benchmark_Verify(b *testing.B) {
	pp := LevelI()
	sk, pk := KeyGen(pp, []byte("keygen-seed"))
	msg := []byte("HPPK-phaseA")
	sig, _ := Sign(pp, sk, msg, []byte("alpha-seed"))
	b.ReportAllocs()
	for i:=0;i<b.N;i++{
		sinkOK, _ = Verify(pp, pk, msg, sig)
	}
	_ = sinkOK
}
