package bls

import (
	"testing"
)

func TestKeyGenReturnsUniqueKeyPairs(t *testing.T) {
	secretKeySet := make(map[SecretKey]bool)
	publicKeySet := make(map[PublicKey]bool)

	for range 1000 {
		kp := KeyGen()
		if secretKeySet[kp.SecretKey] || publicKeySet[kp.PublicKey] {
			t.Error("duplicate key found")
		}

		secretKeySet[kp.SecretKey] = true
		publicKeySet[kp.PublicKey] = true
	}
}