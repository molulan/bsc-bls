package main

import (
	"crypto/rand"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

type SecretKey *e.Scalar
type PublicKey *e.G2

type KeyPair struct {
	SecretKey SecretKey
	PublicKey PublicKey
}

type Signature *e.G1

func KeyGen() KeyPair {
	sk := new(e.Scalar)
	sk.Random(rand.Reader)

	pk := new(e.G2)
	pk.ScalarMult(sk, e.G2Generator())

	return KeyPair{sk, pk}
}

func Sign(sk *e.Scalar, msg []byte) Signature {
	h := hashToG1(msg)

	signature := new(e.G1)
	signature.ScalarMult(sk, h)

	return signature
}

func Verify(pk PublicKey, msg []byte, s Signature) bool {
	h := hashToG1(msg)

	gt1 := e.Pair(h, pk)

	gt2 := e.Pair(s, e.G2Generator())

	return gt1.IsEqual(gt2)
}

func hashToG1(msg []byte) *e.G1 {
	h := new(e.G1)
	dst := []byte(SignatureDst)

	h.Hash(msg, dst)

	return h
}
