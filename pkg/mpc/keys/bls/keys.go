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

// OpenAccumulator opens an accumulator
func (s *SecretKey) OpenAccumulator(acc []byte) (*Accumulator, error) {
	e := new(accumulator.Accumulator)
	err := e.UnmarshalBinary(acc)
	if err != nil {
		return nil, err
	}
	return &Accumulator{Accumulator: e, crv: s.crv}, nil
}

// PublicKey returns the public key for the secret key
func (s *SecretKey) PublicKey() (*PublicKey, error) {
	pk, err := s.SecretKey.GetPublicKey(s.crv)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// Accumulator is the secret key for the BLS scheme
type Accumulator struct {
	*accumulator.Accumulator
	crv *curves.PairingCurve
}

// AddValue adds a value to the accumulator
func (a *Accumulator) AddValue(k *SecretKey, value string) error {
	element := a.crv.Scalar.Hash([]byte(value))
	elements := []accumulator.Element{element}
	acc, _, err := a.Accumulator.Update(k.SecretKey, elements, nil)
	if err != nil {
		return err
	}
	a.Accumulator = acc
	return nil
}

// RemoveValue removes a value from the accumulator
func (a *Accumulator) RemoveValue(k *SecretKey, value string) error {
	element := a.crv.Scalar.Hash([]byte(value))
	elements := []accumulator.Element{element}
	acc, _, err := a.Accumulator.Update(k.SecretKey, nil, elements)
	if err != nil {
		return err
	}
	a.Accumulator = acc
	return nil
}

// Marshal marshals the accumulator
func (a *Accumulator) Marshal() ([]byte, error) {
	return a.Accumulator.MarshalBinary()
}

// CreateWitness creates a witness for the accumulator
func (a *Accumulator) CreateWitness(k *SecretKey, value string) ([]byte, error) {
	element := a.crv.Scalar.Hash([]byte(value))
	mw, err := new(accumulator.MembershipWitness).New(element, a.Accumulator, k.SecretKey)
	if err != nil {
		return nil, err
	}
	return mw.MarshalBinary()
}
