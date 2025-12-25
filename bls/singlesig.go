package bls

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)

func Sign(msg Message, sk SecretKey) Signature {
	h := hashToG1(msg)

	signature := new(e.G1)
	signature.ScalarMult(sk, h)

	return signature
}

func Verify(msg Message, sig Signature, pk PublicKey) bool {
	h := hashToG1(msg)

	gt1 := e.Pair(h, pk)

	gt2 := e.Pair(sig, e.G2Generator())

	return gt1.IsEqual(gt2)
}
