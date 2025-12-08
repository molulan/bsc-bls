package bench

import (
	"fmt"
	"testing"

	"github.com/molulan/bsc-bls/crypto"
)

var multisigVerificationTests = []struct {
    numSigs  int
    signersPerGroup int
}{
    {1, 5},
    {5, 5},
    {10, 5},
    {25, 5},
    {50, 5},
    {75, 5},
    {100, 5},
}

func BenchmarkMultisigVerification(b *testing.B) {
    for _, test := range multisigVerificationTests {
        b.Run(fmt.Sprintf("individual_verification_of_%d_signatures", test.numSigs), func(b *testing.B) {
            benchmarkIndividualMultisigVerification(test.numSigs, test.signersPerGroup, b)
        })
        b.Run(fmt.Sprintf("aggregate_verification_of_%d_signatures", test.numSigs), func(b *testing.B) {
            benchmarkAggregateMultisigVerification(test.numSigs, test.signersPerGroup, b)
        })
    }
}

func benchmarkIndividualMultisigVerification(numGroups, signersPerGroup int, b *testing.B) {
    groups := make([]struct {
        msg crypto.Message
        sig crypto.Signature
        ctx *crypto.MultisigContext
    }, numGroups)

    msg := []byte("msg")
    
    for i := range groups {
        kps, ctx := setupMultisigContext(b, signersPerGroup)
        
        partialSigs := make([]crypto.Signature, signersPerGroup)
        for j, kp := range kps {
            partialSigs[j] = ctx.Sign(msg, kp)
        }
        multisig, _ := crypto.SignatureAggregation(partialSigs)
        
        groups[i] = struct {
            msg crypto.Message
            sig crypto.Signature
            ctx *crypto.MultisigContext
        }{msg: msg, sig: multisig, ctx: ctx}
    }
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for b.Loop() {
        for _, group := range groups {
            group.ctx.Verify(msg, group.sig)
        }
    }
}

func benchmarkAggregateMultisigVerification(numGroups, signersPerGroup int, b *testing.B) {
    msgs := make([]crypto.Message, numGroups)
    sigs := make([]crypto.Signature, numGroups)
    apks := make([]crypto.PublicKey, numGroups)
    
    for i := range msgs {
        kps, ctx := setupMultisigContext(b, signersPerGroup)
        msg := []byte("msg")
        
        partialSigs := make([]crypto.Signature, signersPerGroup)
        for j, kp := range kps {
            partialSigs[j] = ctx.Sign(msg, kp)
        }
        multisig, _ := crypto.SignatureAggregation(partialSigs)
        
        msgs[i] = msg
        sigs[i] = multisig
        apks[i] = ctx.AggregatePk
    }
    
    aggregateMultisig, _ := crypto.SignatureAggregation(sigs)
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for b.Loop() {
        crypto.VerifyAggregateMultisig(msgs, aggregateMultisig, apks)
    }
}


func setupMultisigContext(b *testing.B, n int) ([]crypto.KeyPair, *crypto.MultisigContext) {
	pks := make([]crypto.PublicKey, n)
	kps := make([]crypto.KeyPair, n)

	for i := range n {
		kp := crypto.KeyGen()
		kps[i] = kp
		pks[i] = kp.PublicKey
	}

	ctx, err := crypto.NewMultiSigContext(pks)
	if err != nil {
		b.Fatalf("Failed to create multisig context: %v", err)
	}

	return kps, ctx
}