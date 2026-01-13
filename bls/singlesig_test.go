package bls

import (
	"testing"
)

var singlesigSignAndVerifyTestCases = []struct {
	name           string
	matchingKeys   bool
	matchingMsgs   bool
	expectedResult bool
}{
	{
		name:           "same_keys_same_message",
		matchingKeys:   true,
		matchingMsgs:   true,
		expectedResult: true,
	},
	{
		name:           "same_keys_different_message",
		matchingKeys:   true,
		matchingMsgs:   false,
		expectedResult: false,
	},
	{
		name:           "different_keys_same_message",
		matchingKeys:   false,
		matchingMsgs:   true,
		expectedResult: false,
	},
	{
		name:           "different_keys_different_message",
		matchingKeys:   false,
		matchingMsgs:   false,
		expectedResult: false,
	},
}

func TestSinglesigSignAndVerify(t *testing.T) {
	for _, test := range singlesigSignAndVerifyTestCases {
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			keyPair1 := KeyGen()
			var keyPair2 KeyPair
			if test.matchingKeys {
				keyPair2 = keyPair1
			} else {
				keyPair2 = KeyGen()
			}

			msg1 := []byte("test message")
			var msg2 Message
			if test.matchingMsgs {
				msg2 = []byte("test message")
			} else {
				msg2 = []byte("different message")
			}

			// Act
			signature := Sign(msg1, keyPair1.SecretKey)
			result := Verify(msg2, signature, keyPair2.PublicKey)

			// Assert
			if result != test.expectedResult {
				t.Errorf("Verify() = %v, want %v", result, test.expectedResult)
			}
		})
	}
}