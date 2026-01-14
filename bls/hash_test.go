package bls

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
	"strconv"
	"testing"
)

func TestHashToG1ProducesConsistentHashesOnSameInput(t *testing.T) {
	msg := []byte("msg")

	hash := hashToG1(msg)

	for range 1000 {
		if !hash.IsEqual(hashToG1(msg)) {
			t.Error("Hashing is not consistent")
		}
	}
}

func TestHashToG1ProducesDifferentHashesOnDifferentInputs(t *testing.T) {
	hashSet := make(map[*e.G1]bool)

	for i := range 1000 {
		str := strconv.Itoa(i)
		msg := []byte(str)
		hash := hashToG1(msg)

		if hashSet[hash] {
			t.Error("Hash collision found")
		}

		hashSet[hash] = true
	}
}

func TestHashToScalarProducesConsistentHashesOnSameInput(t *testing.T) {
	kp := KeyGen()

	pks := make([]PublicKey, 0)

	hash := hashToScalar(kp.PublicKey, pks)

	for range 1000 {
		if hash.IsEqual(hashToScalar(kp.PublicKey, pks)) != 1 {
			t.Error("Hashing is not consistent")
		}
	}
}

func TestHashToScalarProducesDifferentHashesOnDifferentInputs(t *testing.T) {
	hashSet := make(map[*e.Scalar]bool)

	pks := make([]PublicKey, 0)

	kp := KeyGen()
	pk := kp.PublicKey

	for range 1000 {
		pks = append(pks, pk)

		hash := hashToScalar(pk, pks)

		if hashSet[hash] {
			t.Error("Hash collision found")
		}

		hashSet[hash] = true
	}
}
