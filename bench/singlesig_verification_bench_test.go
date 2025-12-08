package bench

import (
	"fmt"
	"testing"
	"github.com/molulan/bsc-bls/crypto"
)

var testCases = []int{1, 5, 10, 25, 50, 75, 100}

func BenchmarkSinglesigVerification(b *testing.B) {
	for _, numSigs := range testCases {
		b.Run(fmt.Sprintf("singlesig_verification_of_%d_signatures", numSigs), func(b *testing.B) {
			benchmarkSinglesigVerification(numSigs, b)
		})
        b.Run(fmt.Sprintf("multisig_verification_of_%d_signatures", numSigs), func(b *testing.B) {
            benchmarkMultisigVerification1Signer(numSigs, b)
		})
        b.Run(fmt.Sprintf("aggregate_verification_of_%d_signatures", numSigs), func(b *testing.B) {
            benchmarkAggregateMultisigVerification1Signer(numSigs, b)
		})
	}
}

func benchmarkSinglesigVerification(numSigs int, b *testing.B) {
	kps := make([]crypto.KeyPair, numSigs)
	sigs := make([]crypto.Signature, numSigs)

	msg := []byte("msg")

	for i := range numSigs {
		kp := crypto.KeyGen()
		kps[i] = kp
		sigs[i] = crypto.Sign(msg, kp.SecretKey)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for i, sig := range sigs {
			crypto.Verify(msg, sig, kps[i].PublicKey)
		}
	}

}

func benchmarkMultisigVerification1Signer(numSigs int, b *testing.B) {
	groups := make([]struct {
		sig crypto.Signature
		ctx *crypto.MultisigContext
	}, numSigs)

    msg := []byte("msg")

	for i := range groups {
		kps, ctx := setupMultisigContext(b, 1)
		
		signature := ctx.Sign(msg, kps[0])

		groups[i] = struct {
			sig crypto.Signature
			ctx *crypto.MultisigContext
		}{sig: signature, ctx: ctx}
	}

    b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for _, group := range groups {
			group.ctx.Verify(msg, group.sig)
		}
	}
}


func benchmarkAggregateMultisigVerification1Signer(numSigs int, b *testing.B) {
    apks := make([]crypto.PublicKey, numSigs)
    msgs := make([]crypto.Message, numSigs)
    sigs := make([]crypto.Signature, numSigs)

	for i := range numSigs {
		kps, ctx := setupMultisigContext(b, 1)

        apks[i] = ctx.AggregatePk

        msg := []byte("msg")
        msgs[i] = msg
		
		signature := ctx.Sign(msg, kps[0])
        sigs[i] = signature
	}

    aggregateSignature, _ := crypto.SignatureAggregation(sigs)

    b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		crypto.VerifyAggregateMultisigOptimized(msgs, aggregateSignature, apks)
	}
}
