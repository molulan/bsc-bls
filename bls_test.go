package main

import (
	"testing"
)

func TestSignAndVerifySucces(t *testing.T) {
	msg := []byte("msg")

	keyPair := KeyGen()

	signature := Sign(keyPair.SecretKey, msg)

	ok :=  Verify(keyPair.PublicKey, msg, signature)

	if !ok {
		t.Errorf("Signature should be valid")
	}
}

func TestSignAndVerifyDifferentMessages(t *testing.T) {
	msg1 := []byte("msg1")
	msg2 := []byte("msg2")

	keyPair := KeyGen()

	signature := Sign(keyPair.SecretKey, msg1)

	ok := Verify(keyPair.PublicKey, msg2, signature)

	if ok {
		t.Errorf("Signature should not be valid")
	}
}

func TestSignAndVerifyWithWrongKeys(t *testing.T) {
	msg := []byte("msg")

	keyPair1 := KeyGen()
	keyPair2 := KeyGen()

	signature := Sign(keyPair1.SecretKey, msg)

	ok := Verify(keyPair2.PublicKey, msg, signature)

	if ok {
		t.Errorf("Signature should not be valid")
	}
}

func TestKeyGenReturnsUniqueKeyPairs(t *testing.T) {
	secretKeySet := make(map[SecretKey]bool)
	publicKeySet := make(map[PublicKey]bool)

	for range 1000 {
		kp := KeyGen()
		if secretKeySet[kp.SecretKey] || publicKeySet[kp.PublicKey] {
			t.Errorf("duplicate key found")
		}
		
		secretKeySet[kp.SecretKey] = true
		publicKeySet[kp.PublicKey] = true
	}
}

func TestMuSignAndMuVerifyWith1Signer(t *testing.T) {
	msg := []byte("msg")

	keyPair := KeyGen()

	pks := []PublicKey{keyPair.PublicKey}

	apk := KeyAggregation(pks)

	signature := MuSign(msg, keyPair, pks, apk)

	ok := VerifyMultisig(msg, signature, apk)

	if !ok {
		t.Errorf("Signature should be valid")
	}
}

func TestMuSignAndMuVerifyWithMultipleSigners(t *testing.T) {
	n := 100

	msg := []byte("msg")

	pks := make([]PublicKey, n)
	kps := make([]KeyPair, n)

	for i := range n {
		kp := KeyGen()
		kps[i] = kp
		pks[i] = kp.PublicKey
	}

	apk := KeyAggregation(pks)

	partial_sigs := make([]Signature, n)

	for i, kp := range kps {
		partial_sigs[i] = MuSign(msg, kp, pks, apk)
	}

	multiSig := SignatureAggregation(partial_sigs)

	ok := VerifyMultisig(msg, multiSig, apk)

	if !ok {
		t.Errorf("Signature should be valid")
	}
}

func TestMuSignAndMuVerifyWithAggregatedMultiSig(t *testing.T) {

	msg1 := []byte("msg1")
	msg2 := []byte("msg2")
	msg3 := []byte("msg3")

	kps1, pks1, apk1 := setupKeys(5)
	kps2, pks2, apk2 := setupKeys(3)
	kps3, pks3, apk3 := setupKeys(4)

	partial_sigs1 := make([]Signature, 5)
	partial_sigs2 := make([]Signature, 3)
	partial_sigs3 := make([]Signature, 4)

	for i, kp := range kps1 {
		partial_sigs1[i] = MuSign(msg1, kp, pks1, apk1)
	}
	for i, kp := range kps2 {
		partial_sigs2[i] = MuSign(msg2, kp, pks2, apk2)
	}
	for i, kp := range kps3 {
		partial_sigs3[i] = MuSign(msg3, kp, pks3, apk3)
	}

	multiSig1 := SignatureAggregation(partial_sigs1)
	multiSig2 := SignatureAggregation(partial_sigs2)
	multiSig3 := SignatureAggregation(partial_sigs3)

	multisigs := []Signature{multiSig1, multiSig2, multiSig3}

	aggregateMultiSig := SignatureAggregation(multisigs)

	msgs :=[]Message{msg1, msg2, msg3}

	apks := []PublicKey{apk1, apk2, apk3}

	ok := VerifyAggregateMultisig(msgs, aggregateMultiSig, apks)

	if !ok {
		t.Errorf("Signature should be valid")
	}
}

func setupKeys(n int) ([]KeyPair, []PublicKey, PublicKey) {
	pks := make([]PublicKey, n)
	kps := make([]KeyPair, n)

	for i := range n {
		kp := KeyGen()
		kps[i] = kp
		pks[i] = kp.PublicKey
	}

	apk := KeyAggregation(pks)

	return kps, pks, apk
}
