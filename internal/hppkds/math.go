package hppkds

import "math/big"

func mod(a, m *big.Int) *big.Int {
	x := new(big.Int).Mod(a, m)
	if x.Sign() < 0 { x.Add(x, m) }
	return x
}
func addMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Add(a, b), m) }
func subMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b), m) }
func mulMod(a, b, m *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b), m) }
func invMod(a, m *big.Int) *big.Int    { return new(big.Int).ModInverse(a, m) } // nil if no inverse

// floor(z * c / 2^K) with R=2^K
func barrettFloor(z, c, R *big.Int, K int) *big.Int {
	t := new(big.Int).Mul(z, c)
	t.Rsh(t, uint(K))
	return t
}

// Horner sum: (((a_n)*x + a_{n-1})*x + ... + a_0) mod p
func horner(coeff []*big.Int, x, p *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := len(coeff)-1; i >= 0; i-- {
		acc = mulMod(acc, x, p)
		acc = addMod(acc, coeff[i], p)
	}
	return acc
}
