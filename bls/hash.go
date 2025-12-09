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


func hashToScalar(pk PublicKey, pks []PublicKey) *e.Scalar {
	pkSerialized := (*pk).Bytes()

	pksSerialized := make([]byte, 0)
	for _, pk := range pks {
		pksSerialized = append(pksSerialized, (*pk).Bytes()...)
	}

	combined := append(pksSerialized, pkSerialized...)
	hash := sha256.Sum256(combined)

	scalar := new(e.Scalar)
	scalar.SetBytes(hash[:])

	return scalar
}