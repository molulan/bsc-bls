package bls

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)


func NewMultiSigContext(participants []PublicKey) (*MultisigContext, error) {
	aggregatePk, err := KeyAggregation(participants)
	if err != nil {
		return nil, err
	}

	return &MultisigContext{
		Participants: participants,
		AggregatePk: aggregatePk,
	}, nil
}


func (ctx *MultisigContext) Sign(msg Message, kp KeyPair) Signature {
	
	msg = append(msg, (*ctx.AggregatePk).Bytes()...)

	a := hashToScalar(kp.PublicKey, ctx.Participants)

	temp := new(e.Scalar)
	temp.Mul(a, kp.SecretKey)

	partialMultisig := new(e.G1)
	partialMultisig.ScalarMult(temp, hashToG1(msg))

	return partialMultisig
}


func (ctx *MultisigContext) Verify(msg Message, sig Signature) bool {
	msg = append(msg, (*ctx.AggregatePk).Bytes()...)
	h := hashToG1(msg)

	gt1 := e.Pair(h, ctx.AggregatePk)

	gt2 := e.Pair(sig, e.G2Generator())

	return gt1.IsEqual(gt2)
}


func KeyAggregation(pks []PublicKey) (PublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrNoPublicKeys
	}

	apk := new(e.G2)
	apk.SetIdentity()

	for _, pk := range pks {
		a := hashToScalar(pk, pks)

		temp := new(e.G2)
		temp.ScalarMult(a, pk)

		apk.Add(apk, temp)
	}

	return apk, nil
}


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


func VerifyAggregateMultisig(msgs []Message, sig Signature, apks []PublicKey) (bool, error) {
	if len(msgs) == 0 {
		return false, ErrNoMessages
	}

	if len(msgs) != len(apks) {
		return  false, ErrMismatchedLengths
	}

	gt1 := e.Pair(sig, e.G2Generator())

	gt2 := new(e.Gt)
	gt2.SetIdentity()

	for i, msg := range msgs {
		msg = append(msg, (*apks[i]).Bytes()...)
		next := e.Pair(hashToG1(msg), apks[i])
		gt2.Mul(gt2, next)
	}

	return gt1.IsEqual(gt2), nil
}