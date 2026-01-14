package bls

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Create new multisignature context
func NewMultisigContext(participants []PublicKey) (*MultisigContext, error) {
	aggregatePk, err := KeyAggregation(participants)
	if err != nil {
		return nil, err
	}

	return &MultisigContext{
		Participants: participants,
		AggregatePk:  aggregatePk,
	}, nil
}

// Create a partial signature on a message within a multi-signature context
func (ctx *MultisigContext) Sign(msg Message, kp KeyPair) Signature {
	msg = append(msg, (*ctx.AggregatePk).Bytes()...)

	combinedPublicKeys := combinePublicKeyAndPublicKeySet(kp.PublicKey, ctx.Participants)

	a := hashToScalar(combinedPublicKeys)

	temp := new(e.Scalar)
	temp.Mul(a, kp.SecretKey)

	partialMultisig := new(e.G1)
	partialMultisig.ScalarMult(temp, hashToG1(msg))

	return partialMultisig
}

// Verify a multi-signature on a message
func VerifyMultisig(msg Message, sig Signature, apk PublicKey) bool {
	msg = append(msg, (*apk).Bytes()...)
	h := hashToG1(msg)

	gt1 := e.Pair(h, apk)

	gt2 := e.Pair(sig, e.G2Generator())

	return gt1.IsEqual(gt2)
}

// Create an aggregate public key
func KeyAggregation(pks []PublicKey) (PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	apk := new(e.G2)
	apk.SetIdentity()

	for _, pk := range pks {
		combinedPublicKeys := combinePublicKeyAndPublicKeySet(pk, pks)

		a := hashToScalar(combinedPublicKeys)
		temp := new(e.G2)
		temp.ScalarMult(a, pk)

		apk.Add(apk, temp)
	}

	return apk, nil
}

// Combine a public key with a set of public keys 
func combinePublicKeyAndPublicKeySet(pk PublicKey, pks []PublicKey) []byte {
	pkSerialized := (*pk).Bytes()
	pksSerialized := serializePublicKeys(pks)
	combined := append(pksSerialized, pkSerialized...)

	return combined
}

// Serialize a set of public keys
func serializePublicKeys(pks []PublicKey) []byte {
	pksSerialized := make([]byte, 0)
	for _, pk := range pks {
		pksSerialized = append(pksSerialized, (*pk).Bytes()...)
	}

	return pksSerialized
}

// Combine partial multi-signatures or 
// Create an aggregate signature
func SignatureAggregation(sigs []Signature) (Signature, error) {
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	aggregateSignature := new(e.G1)
	aggregateSignature.SetIdentity()

	for _, sig := range sigs {
		aggregateSignature.Add(aggregateSignature, sig)
	}

	return aggregateSignature, nil
}

// Verify an aggregate multi-signature
func VerifyAggregateMultisig(msgs []Message, sig Signature, apks []PublicKey) (bool, error) {
	if len(msgs) == 0 {
		return false, ErrNoMessages
	}

	if len(msgs) != len(apks) {
		return false, ErrMismatchedLengths
	}

	gt1 := e.Pair(sig, e.G2Generator())

	gt2 := new(e.Gt)
	gt2.SetIdentity()

	for i, msg := range msgs {
		msg = append(msg, (*apks[i]).Bytes()...)
		temp := e.Pair(hashToG1(msg), apks[i])
		gt2.Mul(gt2, temp)
	}

	return gt1.IsEqual(gt2), nil
}
