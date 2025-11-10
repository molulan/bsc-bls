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
