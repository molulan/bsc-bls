package bls

import (
	"errors"
)

var (
    ErrNoPublicKeys 			= errors.New("at least one public key is required")
	ErrNoSignatures				= errors.New("at least one signature is required")
	ErrNoMessages				= errors.New("at least one message is required")
	ErrMismatchedLengths		= errors.New("mismatched slice lengths")
)