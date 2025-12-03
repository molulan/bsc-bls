package crypto

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)

type Message []byte

type SecretKey *e.Scalar
type PublicKey *e.G2

type KeyPair struct {
	SecretKey SecretKey
	PublicKey PublicKey
}

type Signature *e.G1

type MultisigContext struct {
	Participants	[]PublicKey
	AggregatePk		PublicKey
}


