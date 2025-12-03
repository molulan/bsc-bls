package crypto

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)


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