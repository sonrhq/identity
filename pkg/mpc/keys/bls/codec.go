package bls

import (
	"github.com/sonrhq/sonr/crypto/accumulator"
	"github.com/sonrhq/sonr/crypto/core/curves"
)

// SecretKey is the secret key for the BLS scheme
type SecretKey struct {
	*accumulator.SecretKey
	crv *curves.PairingCurve
}

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
	return &SecretKey{SecretKey: key, crv: curve}, nil
}

// CreateAccumulator creates a new accumulator
func (s *SecretKey) CreateAccumulator() (*Accumulator, error) {
	acc, err := new(accumulator.Accumulator).New(s.crv)
	if err != nil {
		return nil, err
	}
	return &Accumulator{Accumulator: acc, crv: s.crv}, nil
}


// Accumulator is the secret key for the BLS scheme
type Accumulator struct {
	*accumulator.Accumulator
	crv *curves.PairingCurve
}
