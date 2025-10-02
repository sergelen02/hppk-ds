package hppkds

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

func u256(b *big.Int) []byte {
	z := b.Bytes()
	if len(z)<32 {
		pad := make([]byte, 32-len(z))
		return append(pad, z...)
	}
	return z
}

func MarshalPK(pk *PublicKey) []byte {
	buf := new(bytes.Buffer)
	// [P(32)][K(2)][S1b(32)][S2b(32)][P'0..2(3×32)][Q'0..2(3×32)][Mu0..2(3×32)][Nu0..2(3×32)]
	buf.Write(u256(pk.P))
	binary.Write(buf, binary.BigEndian, uint16(pk.K))
	buf.Write(u256(pk.S1beta)); buf.Write(u256(pk.S2beta))
	for i:=0;i<3;i++{ buf.Write(u256(pk.Pprime[i])) }
	for i:=0;i<3;i++{ buf.Write(u256(pk.Qprime[i])) }
	for i:=0;i<3;i++{ buf.Write(u256(pk.Mu[i])) }
	for i:=0;i<3;i++{ buf.Write(u256(pk.Nu[i])) }
	return buf.Bytes()
}
func MarshalSK(sk *PrivateKey) []byte {
	buf := new(bytes.Buffer)
	buf.Write(u256(sk.P))
	for _,x := range []*big.Int{sk.S1,sk.S2,sk.R1,sk.R2,sk.F0,sk.F1,sk.H0,sk.H1,sk.Beta}{
		buf.Write(u256(x))
	}
	for i:=0;i<3;i++{ buf.Write(u256(sk.Pplain[i])) }
	for i:=0;i<3;i++{ buf.Write(u256(sk.Qplain[i])) }
	return buf.Bytes()
}
func MarshalSIG(sig *Signature) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(sig.Segs)))
	for _,s := range sig.Segs {
		buf.Write(u256(s.F)); buf.Write(u256(s.H))
	}
	return buf.Bytes()
}
