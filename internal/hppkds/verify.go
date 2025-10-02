package hppkds

import "errors"

func Verify(pp *Params, pk *PublicKey, msg []byte, sig *Signature) (bool, error) {
	if pk==nil || sig==nil { return false, errors.New("nil arg") }
	xs := hashChunks(pk.P, msg)
	if len(xs)!=len(sig.Segs) { return false, errors.New("length mismatch") }

	R := pk.R; K := pk.K; p := pk.P
	for k,x := range xs {
		F := sig.Segs[k].F
		H := sig.Segs[k].H

		Ui := make([]*big.Int, 3)
		Vi := make([]*big.Int, 3)
		for i:=0;i<3;i++{
			// U_i(H) = H*p′_i - s1*floor(H*μ_i / 2^K)
			hp := mulMod(H, pk.Pprime[i], p)
			floorU := barrettFloor(H, pk.Mu[i], R, K)
			s1floor := mulMod(pk.S1beta, floorU, p)
			Ui[i] = subMod(hp, s1floor, p)

			// V_i(F) = F*q′_i - s2*floor(F*ν_i / 2^K)
			fq := mulMod(F, pk.Qprime[i], p)
			floorV := barrettFloor(F, pk.Nu[i], R, K)
			s2floor := mulMod(pk.S2beta, floorV, p)
			Vi[i] = subMod(fq, s2floor, p)
		}
		sumU := horner(Ui, x, p)
		sumV := horner(Vi, x, p)
		if sumU.Cmp(sumV)!=0 { return false, nil }
	}
	return true, nil
}
