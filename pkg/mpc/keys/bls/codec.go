package bls

import (
	"github.com/sonrhq/sonr/crypto/accumulator"
	"github.com/sonrhq/sonr/crypto/core/curves"
)

// SecretKey is the secret key for the BLS scheme
type SecretKey struct {
	*accumulator.SecretKey
}

// Accumulator is the accumulator for the BLS scheme
type Accumulator = accumulator.Accumulator

// PublicKey is the public key for the BLS scheme
type PublicKey = accumulator.PublicKey

// Element is the element for the BLS scheme
type Element = accumulator.Element

// NewSecretKey creates a new secret key
func NewSecretKey() (*SecretKey, error) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	if err != nil {
		return nil, err
	}
	return &SecretKey{key}, nil
}


