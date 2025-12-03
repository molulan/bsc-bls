package crypto

import (
	"crypto/rand"
	e "github.com/cloudflare/circl/ecc/bls12381"
)


func KeyGen() KeyPair {
	sk := new(e.Scalar)
	sk.Random(rand.Reader)

	pk := new(e.G2)
	pk.ScalarMult(sk, e.G2Generator())

	return KeyPair{sk, pk}
}
