package hppkds

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func Test_Golden_SmallP(t *testing.T) {
	// 1) 논문 부록의 작은 p 예제가 있다면 여기 채우세요.
	//    (예: p=13, L 작은 값, 시드 고정)
	//    아래는 자리표시자입니다.
	pp := &Params{P: bigPrime13(), L: 16, K: 16+64}
	seed := []byte("golden-smallp-v1")
	sk, pk := KeyGen(pp, seed)

	msg := []byte("abc")
	sig, err := Sign(pp, sk, msg, []byte("sig-seed"))
	if err != nil { t.Fatal(err) }
	ok, err := Verify(pp, pk, msg, sig)
	if err != nil || !ok { t.Fatalf("verify fail: %v", err) }

	// 2) 바이트 일치 (논문 제공값과 비교)
	gotPK := hex.EncodeToString(MarshalPK(pk))
	gotSK := hex.EncodeToString(MarshalSK(sk))
	gotSG := hex.EncodeToString(MarshalSIG(sig))
	// wantPK := "..." // 논문 값
	_ = gotPK; _ = gotSK; _ = gotSG
	// if gotPK!=wantPK || gotSK!=wantSK || gotSG!=wantSG { t.Fatal("mismatch") }
}

func Test_LevelI_Deterministic(t *testing.T) {
	pp := LevelI()
	sk, pk := KeyGen(pp, []byte("keygen-seed"))
	msg := []byte("hello-phaseA")
	sig, err := Sign(pp, sk, msg, []byte("alpha-seed"))
	if err != nil { t.Fatal(err) }
	ok, err := Verify(pp, pk, msg, sig)
	if err != nil || !ok { t.Fatalf("verify fail: %v", err) }

	// 재현성 체크 (동일 시드 → 완전 동일 바이트)
	pk2 := MarshalPK(pk)
	sk2 := MarshalSK(sk)
	sig2 := MarshalSIG(sig)

	sk_, pk_ := KeyGen(pp, []byte("keygen-seed"))
	sig_, _ := Sign(pp, sk_, msg, []byte("alpha-seed"))
	if !bytes.Equal(pk2, MarshalPK(pk_)) || !bytes.Equal(sk2, MarshalSK(sk_)) || !bytes.Equal(sig2, MarshalSIG(sig_)) {
		t.Fatal("determinism mismatch")
	}
}
