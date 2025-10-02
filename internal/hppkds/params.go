package hppkds

import "math/big"

// Security Level I (paper): p=2^64-59, L=144, K=L+64  => R=2^K
type Params struct {
	P *big.Int
	L int // |S1|,|S2| bit-length
	K int // Barrett scale
}

func LevelI() *Params {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(59))
	L := 144
	K := L + 64 // ★ 논문 권장 (이전 코드의 L+32는 오차 위험)
	return &Params{P: p, L: L, K: K}
}

func (pp *Params) R() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(pp.K))
}
