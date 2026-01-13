package bls

import (
	"fmt"
	"testing"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

var testcases = []struct {
	numSigs         int
	signersPerGroup int
}{
	{1, 5},
	{10, 5},
	{20, 5},
	{30, 5},
	{40, 5},
	{50, 5},
	{60, 5},
	{70, 5},
	{80, 5},
	{90, 5},
	{100, 5},
}

func BenchmarkAggregateMultisigVerification(b *testing.B) {
	for _, test := range testcases {
		testname := fmt.Sprintf("%d_signatures", test.numSigs)
		b.Run(testname, func(b *testing.B) {
			setupAggregateMultisigVerification(test.numSigs, test.signersPerGroup, b)
		})
	}
}

func BenchmarkIndividualMultisigVerification(b *testing.B) {
	for _, test := range testcases {
		testname := fmt.Sprintf("%d_signatures", test.numSigs)
		b.Run(testname, func(b *testing.B) {
			setupIndividualMultisigVerification(test.numSigs, test.signersPerGroup, b)
		})
	}
}

func BenchmarkSinglesigVerification(b *testing.B) {
	for _, test := range testcases {
		testname := fmt.Sprintf("%d_signatures", test.numSigs)
		b.Run(testname, func(b *testing.B) {
			setupSinglesigVerification(test.numSigs, b)
		})
	}
}

func BenchmarkSingleSignerMultisigVerification(b *testing.B) {
	for _, test := range testcases {
		testname := fmt.Sprintf("%d_signatures", test.numSigs)
		b.Run(testname, func(b *testing.B) {
			setupSingleSignerMultisigVerification(test.numSigs, b)
		})
	}
}

func BenchmarkPairingComputations(b *testing.B) {
	g1 := new(e.G1)
	g2 := new(e.G2)
	
	for b.Loop() {
		e.Pair(g1,g2)
	}
}

func BenchmarkHashToG1(b *testing.B) {
	msg := []byte("msg")
	
	for b.Loop() {
		hashToG1(msg)
	}
}

func setupSinglesigVerification(numSigs int, b *testing.B) {
	kps := make([]KeyPair, numSigs)
	sigs := make([]Signature, numSigs)

	msg := []byte("msg")

	for i := range numSigs {
		kp := KeyGen()
		kps[i] = kp
		sigs[i] = Sign(msg, kp.SecretKey)
	}

	for b.Loop() {
		for i, sig := range sigs {
			Verify(msg, sig, kps[i].PublicKey)
		}
	}
}

func setupSingleSignerMultisigVerification(numSigs int, b *testing.B) {
	groups := make([]struct {
		sig Signature
		ctx *MultisigContext
	}, numSigs)

	msg := []byte("msg")

	for i := range groups {
		kps, ctx := setupMultisigContext(1)

		signature := ctx.Sign(msg, kps[0])

		groups[i] = struct {
			sig Signature
			ctx *MultisigContext
		}{sig: signature, ctx: ctx}
	}

	for b.Loop() {
		for _, group := range groups {
			group.ctx.Verify(msg, group.sig)
		}
	}
}

func setupIndividualMultisigVerification(numGroups, signersPerGroup int, b *testing.B) {
	groups := make([]struct {
		msg Message
		sig Signature
		ctx *MultisigContext
	}, numGroups)

	msg := []byte("msg")

	for i := range groups {
		kps, ctx := setupMultisigContext(signersPerGroup)

		partialSigs := make([]Signature, signersPerGroup)
		for j, kp := range kps {
			partialSigs[j] = ctx.Sign(msg, kp)
		}
		multisig, _ := SignatureAggregation(partialSigs)

		groups[i] = struct {
			msg Message
			sig Signature
			ctx *MultisigContext
		}{msg: msg, sig: multisig, ctx: ctx}
	}

	for b.Loop() {
		for _, group := range groups {
			group.ctx.Verify(group.msg, group.sig)
		}
	}
}

func setupAggregateMultisigVerification(numGroups, signersPerGroup int, b *testing.B) {
	msgs := make([]Message, numGroups)
	sigs := make([]Signature, numGroups)
	apks := make([]PublicKey, numGroups)

	for i := range msgs {
		kps, ctx := setupMultisigContext(signersPerGroup)
		msg := []byte("msg")

		partialSigs := make([]Signature, signersPerGroup)
		for j, kp := range kps {
			partialSigs[j] = ctx.Sign(msg, kp)
		}
		multisig, _ := SignatureAggregation(partialSigs)

		msgs[i] = msg
		sigs[i] = multisig
		apks[i] = ctx.AggregatePk
	}

	aggregateMultisig, _ := SignatureAggregation(sigs)

	for b.Loop() {
		VerifyAggregateMultisig(msgs, aggregateMultisig, apks)
	}
}
