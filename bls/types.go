package bls

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Message is the object that is signed
type Message []byte

type SecretKey *e.Scalar

// PublicKey is a point in the twist of the BLS12 curve over Fp2
type PublicKey *e.G2

type KeyPair struct {
	SecretKey SecretKey
	PublicKey PublicKey
}

// Signature is a point in the BLS12 curve over Fp
type Signature *e.G1

// MultisigContext is a struct keeps track of all public keys
// and the corresponding aggregate public of a group of signers
type MultisigContext struct {
	Participants []PublicKey
	AggregatePk  PublicKey
}
