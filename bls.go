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

func KeyAggregation(pks []PublicKey) PublicKey {
	apk := new(e.G2)
	apk.SetIdentity()

	for _, pk := range pks {
		a := hashToScalar(pk, pks)

		temp := new(e.G2)
		temp.ScalarMult(a, pk)

		apk.Add(apk, temp)
	}

	return apk
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

func MuSign(msg Message, kp KeyPair, pks []PublicKey, apk PublicKey) Signature {
	msg = append(msg, (*apk).Bytes()...)

	a := hashToScalar(kp.PublicKey, pks)

	temp := new(e.Scalar)
	temp.Mul(a, kp.SecretKey)

	partialSigature := new(e.G1)
	partialSigature.ScalarMult(temp, hashToG1(msg))

	return partialSigature
}

func SignatureAggregation(sigs []Signature) Signature {
	aggregateSignature := new(e.G1)
	aggregateSignature.SetIdentity()

	for _, sig := range sigs {
		aggregateSignature.Add(aggregateSignature, sig)
	}

	return aggregateSignature
}

func VerifyMultisig(msg Message, sig Signature, apk PublicKey) bool {
	msg = append(msg, (*apk).Bytes()...)
	h := hashToG1(msg)

	gt1 := e.Pair(h, apk)

	gt2 := e.Pair(sig, e.G2Generator())

	return gt1.IsEqual(gt2)
}

func VerifyAggregateMultisig(msgs []Message, sig Signature, apks []PublicKey) bool {
	left := e.Pair(sig, e.G2Generator())

	right := new(e.Gt)
	right.SetIdentity()

	for i, msg := range msgs {
		msg = append(msg, (*apks[i]).Bytes()...)
		next := e.Pair(hashToG1(msg), apks[i])
		right.Mul(right, next)
	}

	return left.IsEqual(right)
}
