package hppkds

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type DRBG struct{ K, V [32]byte }

func NewDRBG(seed []byte) *DRBG {
	var d DRBG
	for i := range d.V { d.V[i] = 0x01 }
	// instantiate/update (NIST SP 800-90A 방식 요약)
	d.update(seed)
	return &d
}
func (d *DRBG) update(provided []byte) {
	mac := hmac.New(sha256.New, d.K[:]); mac.Write(d.V[:]); mac.Write([]byte{0x00}); mac.Write(provided)
	sum := mac.Sum(nil); copy(d.K[:], sum); mac = hmac.New(sha256.New, d.K[:]); mac.Write(d.V[:]); copy(d.V[:], mac.Sum(nil))
	if len(provided) > 0 {
		mac = hmac.New(sha256.New, d.K[:]); mac.Write(d.V[:]); mac.Write([]byte{0x01}); mac.Write(provided)
		sum = mac.Sum(nil); copy(d.K[:], sum); mac = hmac.New(sha256.New, d.K[:]); mac.Write(d.V[:]); copy(d.V[:], mac.Sum(nil))
	}
}
func (d *DRBG) bytes(out []byte) {
	off := 0
	for off < len(out) {
		m := hmac.New(sha256.New, d.K[:]); m.Write(d.V[:]); copy(d.V[:], m.Sum(nil))
		n := copy(out[off:], d.V[:]); off += n
	}
}
func (d *DRBG) Uint64() uint64 {
	var b [8]byte; d.bytes(b[:]); return binary.BigEndian.Uint64(b[:])
}
func (d *DRBG) RandMod(m *big.Int) *big.Int {
	// rejection sampling using 256-bit blocks
	for {
		var b [32]byte; d.bytes(b[:])
		x := new(big.Int).SetBytes(b[:])
		if x.Cmp(m) < 0 { return x }
	}
}
