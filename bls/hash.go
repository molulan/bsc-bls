package bls

import (
	"crypto/sha256"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

const SignatureDst = "sign"

func hashToG1(msg Message) *e.G1 {
	h := new(e.G1)
	dst := []byte(SignatureDst)

	h.Hash(msg, dst)

	return h
}

func hashToScalar(x []byte) *e.Scalar {
	hash := sha256.Sum256(x)

	scalar := new(e.Scalar)
	scalar.SetBytes(hash[:])

	return scalar
}
