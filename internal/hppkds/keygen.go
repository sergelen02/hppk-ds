package hppkds

import (
	"crypto/sha256"
	"math/big"
)

type PrivateKey struct {
	P *big.Int
	S1,S2 *big.Int
	R1,R2 *big.Int
	F0,F1 *big.Int
	H0,H1 *big.Int
	// plain coefficients p_i, q_i (i=0..2)
	Pplain [3]*big.Int
	Qplain [3]*big.Int
	Beta   *big.Int
}

type PublicKey struct {
	P *big.Int
	S1beta, S2beta *big.Int // s1=β S1 mod p, s2=β S2 mod p
	Pprime [3]*big.Int      // p′_i = β Pij (mod p), j=1
	Qprime [3]*big.Int
	Mu [3]*big.Int          // μ_i = floor(R * Pij / S1)
	Nu [3]*big.Int          // ν_i = floor(R * Qij / S2)
	R  *big.Int
	K  int
}

func randBits(drbg *DRBG, bits int) *big.Int {
	lim := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	for {
		var b [32]byte; drbg.bytes(b[:])
		x := new(big.Int).SetBytes(b[:])
		x.Mod(x, lim)
		if x.Sign() > 0 && x.BitLen() == bits { return x }
	}
}
func randCoprime(drbg *DRBG, S *big.Int) *big.Int {
	for {
		r := drbg.RandMod(S)
		if r.Sign() > 0 && new(big.Int).GCD(nil, nil, r, S).Cmp(big.NewInt(1))==0 {
			return r
		}
	}
}

// 해시 기반 시드(테스트 재현용)
func seedFromLabel(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

func KeyGen(pp *Params, seed []byte) (*PrivateKey, *PublicKey) {
	drbg := NewDRBG(seed)
	P := new(big.Int).Set(pp.P)

	// 1) f,h (f1,h1 ≠ 0)
	f0 := drbg.RandMod(P)
	f1 := drbg.RandMod(P); for f1.Sign()==0 { f1 = drbg.RandMod(P) }
	h0 := drbg.RandMod(P)
	h1 := drbg.RandMod(P); for h1.Sign()==0 { h1 = drbg.RandMod(P) }

	// 2) S1,S2 (L bits), R1,R2 with gcd=1
	S1 := randBits(drbg, pp.L)
	S2 := randBits(drbg, pp.L)
	R1 := randCoprime(drbg, S1)
	R2 := randCoprime(drbg, S2)

	// 3) base polynomial B: b0,b1,b2 in F_p
	b0 := drbg.RandMod(P)
	b1 := drbg.RandMod(P)
	b2 := drbg.RandMod(P)

	mul := func(a,b *big.Int)*big.Int{ return mulMod(a,b,P) }
	add := func(a,b *big.Int)*big.Int{ return addMod(a,b,P) }
	// p_i = Σ f_s * b_t, q_i = Σ h_s * b_t  (λ=1 → s∈{0,1}, t∈{0,1,2}, s+t=i)
	p0 := mul(f0,b0)
	p1 := add(mul(f0,b1), mul(f1,b0))
	p2 := add(mul(f0,b2), mul(f1,b1))
	q0 := mul(h0,b0)
	q1 := add(mul(h0,b1), mul(h1,b0))
	q2 := add(mul(h0,b2), mul(h1,b1))

	// 4) ring-encrypt: Pij=R1*p_i mod S1; Qij=R2*q_i mod S2 (j=1)
	Pij := [3]*big.Int{
		mod(new(big.Int).Mul(R1,p0), S1),
		mod(new(big.Int).Mul(R1,p1), S1),
		mod(new(big.Int).Mul(R1,p2), S1),
	}
	Qij := [3]*big.Int{
		mod(new(big.Int).Mul(R2,q0), S2),
		mod(new(big.Int).Mul(R2,q1), S2),
		mod(new(big.Int).Mul(R2,q2), S2),
	}

	// 5) β-fold + Barrett μ,ν
	beta := drbg.RandMod(P); for beta.Sign()==0 { beta = drbg.RandMod(P) }
	S1b := mulMod(beta,S1,P); S2b := mulMod(beta,S2,P)
	R := pp.R()
	var Pp, Qp [3]*big.Int
	var Mu, Nu [3]*big.Int
	for i:=0;i<3;i++{
		Pp[i] = mulMod(beta, Pij[i], P)
		Qp[i] = mulMod(beta, Qij[i], P)
		Mu[i] = new(big.Int).Div(new(big.Int).Mul(R, Pij[i]), S1) // floor
		Nu[i] = new(big.Int).Div(new(big.Int).Mul(R, Qij[i]), S2)
	}

	sk := &PrivateKey{
		P:P, S1:S1, S2:S2, R1:R1, R2:R2,
		F0:f0, F1:f1, H0:h0, H1:h1,
		Pplain:[3]*big.Int{p0,p1,p2},
		Qplain:[3]*big.Int{q0,q1,q2},
		Beta:beta,
	}
	pk := &PublicKey{
		P:P, S1beta:S1b, S2beta:S2b,
		Pprime:Pp, Qprime:Qp, Mu:Mu, Nu:Nu,
		R:new(big.Int).Set(R), K:pp.K,
	}
	return sk, pk
}
