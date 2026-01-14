package bls

import (
	"crypto/rand"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Generate a random KeyPair
func KeyGen() KeyPair {
	sk := new(e.Scalar)
	sk.Random(rand.Reader)

	pk := new(e.G2)
	pk.ScalarMult(sk, e.G2Generator())

	return KeyPair{sk, pk}
}
