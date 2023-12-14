package bls

import (
	"github.com/sonrhq/sonr/crypto/accumulator"
	"github.com/sonrhq/sonr/crypto/core/curves"
)

type SecretKey = accumulator.SecretKey

func NewBLSSecretKey() (*accumulator.SecretKey, error) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	if err != nil {
		return nil, err
	}
	return key, nil
}
