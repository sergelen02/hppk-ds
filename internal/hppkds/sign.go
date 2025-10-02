package hppkds

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

type SigSeg struct{ F,H *big.Int }
type Signature struct{ Segs []SigSeg }

func hashChunks(p *big.Int, msg []byte) []*big.Int {
	// Domain separation: "HPPK-DS|v1|" || msg
	d := sha256.Sum256(append([]byte("HPPK-DS|v1|"), msg...))
	out := make([]*big.Int, 0, 4)
	for i:=0;i<32;i+=8{
		u := binary.BigEndian.Uint64(d[i:i+8])
		out = append(out, new(big.Int).Mod(new(big.Int).SetUint64(u), p))
	}
	return out
}

func Sign(pp *Params, sk *PrivateKey, msg []byte, seed []byte) (*Signature, error) {
	if sk==nil { return nil, errors.New("nil sk") }
	drbg := NewDRBG(seed) // 결정적 α 생성
	xs := hashChunks(sk.P, msg)
	segs := make([]SigSeg, len(xs))

	R1inv := invMod(sk.R1, sk.S1)
	R2inv := invMod(sk.R2, sk.S2)
	if R1inv==nil || R2inv==nil { return nil, errors.New("no inverse") }

	for i,x := range xs {
		alpha := drbg.RandMod(sk.P); for alpha.Sign()==0 { alpha = drbg.RandMod(sk.P) }

		fx := addMod(sk.F0, mulMod(sk.F1,x,sk.P), sk.P)
		hx := addMod(sk.H0, mulMod(sk.H1,x,sk.P), sk.P)

		Fpart := mulMod(alpha, fx, sk.P)
		Hpart := mulMod(alpha, hx, sk.P)

		F := mod(new(big.Int).Mul(R2inv, Fpart), sk.S2)
		H := mod(new(big.Int).Mul(R1inv, Hpart), sk.S1)

		segs[i] = SigSeg{F:F, H:H}
	}
	return &Signature{Segs: segs}, nil
}
