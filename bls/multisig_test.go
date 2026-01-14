package bls

import (
	"testing"
)

var multisigSignAndVerifyTestCases = []struct {
	name            string
	requiredSigners int
	numSigners      int
	matchingMsgs    bool
	expectedResult  bool
}{
	{
		name:            "valid signature with 1 signer",
		requiredSigners: 1,
		numSigners:      1,
		matchingMsgs:    true,
		expectedResult:  true,
	},
	{
		name:            "valid signature with multiple signers",
		requiredSigners: 100,
		numSigners:      100,
		matchingMsgs:    true,
		expectedResult:  true,
	},
	{
		name:            "invalid signature - wrong message",
		requiredSigners: 3,
		numSigners:      3,
		matchingMsgs:    false,
		expectedResult:  false,
	},
	{
		name:            "invalid signature - not enough signers",
		requiredSigners: 3,
		numSigners:      2,
		matchingMsgs:    true,
		expectedResult:  false,
	},
}

func TestMultisigSignAndVerify(t *testing.T) {
	for _, test := range multisigSignAndVerifyTestCases {
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			msg := []byte("original message")

			kps, ctx := setupMultisigContext(test.requiredSigners)

			partialSigs := make([]Signature, test.numSigners)
			for i := range test.numSigners {
				partialSigs[i] = ctx.Sign(msg, kps[i])
			}

			signature, err := SignatureAggregation(partialSigs)
			if err != nil {
				t.Fatalf("Failed to aggregate signatures: %v", err)
			}

			if !test.matchingMsgs {
				msg = []byte("wrong message")
			}

			// Act
			result := VerifyMultisig(msg, signature, ctx.AggregatePk)

			// Assert
			if result != test.expectedResult {
				t.Errorf("Verify() = %v, want %v", result, test.expectedResult)
			}
		})
	}
}

func TestMultisigSignWithNonParticipant(t *testing.T) {
	// Arrange
	_, ctx := setupMultisigContext(1)
	outsiderKp := KeyGen()

	msg := []byte("msg")
	signature := ctx.Sign(msg, outsiderKp)
	expectedResult := false

	// Act
	result := VerifyMultisig(msg, signature, ctx.AggregatePk)

	// Assert
	if result != expectedResult {
		t.Errorf("Verify() = %v, want %v", result, expectedResult)
	}
}

func TestVerifyAggregatedMultiSig(t *testing.T) {
	// Arrange
	//multisig group 1
	kps1, ctx1 := setupMultisigContext(5)
	msg1 := []byte("msg1")
	partial_sigs1 := make([]Signature, 5)
	for i, kp := range kps1 {
		partial_sigs1[i] = ctx1.Sign(msg1, kp)
	}
	multiSig1, _ := SignatureAggregation(partial_sigs1)

	// multisig group 2
	kps2, ctx2 := setupMultisigContext(3)
	msg2 := []byte("msg2")
	partial_sigs2 := make([]Signature, 3)
	for i, kp := range kps2 {
		partial_sigs2[i] = ctx2.Sign(msg2, kp)
	}
	multiSig2, _ := SignatureAggregation(partial_sigs2)

	// multisig group 3
	kps3, ctx3 := setupMultisigContext(4)
	msg3 := []byte("msg3")
	partial_sigs3 := make([]Signature, 4)
	for i, kp := range kps3 {
		partial_sigs3[i] = ctx3.Sign(msg3, kp)
	}
	multiSig3, _ := SignatureAggregation(partial_sigs3)

	// Aggregate signatures
	signatures := []Signature{multiSig1, multiSig2, multiSig3}
	aggregateMultiSig, _ := SignatureAggregation(signatures)

	msgs := []Message{msg1, msg2, msg3}
	apks := []PublicKey{ctx1.AggregatePk, ctx2.AggregatePk, ctx3.AggregatePk}
	expectedResult := true

	// Act
	result, _ := VerifyAggregateMultisig(msgs, aggregateMultiSig, apks)

	// Assert
	if result != expectedResult {
		t.Error("Signature should be valid")
	}
}

func TestVerifyAggregatedMultiSig_WithWrongMessage(t *testing.T) {
	// Arrange
	// multisig group 1
	msg1 := []byte("message 1")
	kps1, ctx1 := setupMultisigContext(3)
	partialSigs1 := make([]Signature, len(kps1))
	for i, kp := range kps1 {
		partialSigs1[i] = ctx1.Sign(msg1, kp)
	}
	multiSig1, _ := SignatureAggregation(partialSigs1)

	// multisig group 2
	msg2 := []byte("message 2")
	kps2, ctx2 := setupMultisigContext(2)
	partialSigs2 := make([]Signature, len(kps2))
	for i, kp := range kps2 {
		partialSigs2[i] = ctx2.Sign(msg2, kp)
	}
	multiSig2, _ := SignatureAggregation(partialSigs2)

	// Aggregate signatures
	signatures := []Signature{multiSig1, multiSig2}
	aggregatedMultiSig, _ := SignatureAggregation(signatures)

	wrongMsg1 := []byte("wrong message")
	msgs := []Message{wrongMsg1, msg2}
	apks := []PublicKey{ctx1.AggregatePk, ctx2.AggregatePk}

	expectedResult := false

	// Act
	result, _ := VerifyAggregateMultisig(msgs, aggregatedMultiSig, apks)

	//Assert
	if result != expectedResult {
		t.Error("Aggregated multisig should not verify with wrong message")
	}
}

func TestSignatureAggregationWithNoSignaturesShouldReportError(t *testing.T) {
	_, err := SignatureAggregation([]Signature{})
	if err != ErrNoSignatures {
		t.Errorf("Expected ErrNoSignatures, got %v", err)
	}
}

func TestKeyAggregationWithNoPublicKeysShouldReportError(t *testing.T) {
	_, err := KeyAggregation([]PublicKey{})
	if err != ErrNoPublicKeys {
		t.Errorf("Expected ErrNoPublicKeys, got %v", err)
	}
}

func TestVerifyAggregateMultisigWithNoMessagesShouldReportError(t *testing.T) {
	_, err := VerifyAggregateMultisig([]Message{}, nil, []PublicKey{})
	if err != ErrNoMessages {
		t.Errorf("Expected ErrNoMessages, got %v", err)
	}
}

func TestNewMultisigContextWithZeroParticipantsShouldReportError(t *testing.T) {
	_, err := NewMultisigContext([]PublicKey{})

	if err != ErrNoPublicKeys {
		t.Errorf("Expected ErrNoMessages, got %v", err)
	}
}

func setupMultisigContext(n int) ([]KeyPair, *MultisigContext) {
	pks := make([]PublicKey, n)
	kps := make([]KeyPair, n)

	for i := range n {
		kp := KeyGen()
		kps[i] = kp
		pks[i] = kp.PublicKey
	}

	ctx, _ := NewMultisigContext(pks)

	return kps, ctx
}
