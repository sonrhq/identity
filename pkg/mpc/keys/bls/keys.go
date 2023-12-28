package bls

import (
	"encoding/hex"

	"github.com/mr-tron/base58"
	"github.com/sonrhq/sonr/crypto/accumulator"

	"github.com/sonrhq/identity/pkg/mpc"
)

// SecretKey is the secret key for the BLS scheme
type SecretKey struct {
	*accumulator.SecretKey
}

// PublicKey is the public key for the BLS scheme
type PublicKey = accumulator.PublicKey

// Element is the element for the BLS scheme
type Element = accumulator.Element

// NewSecretKey creates a new secret key
func NewSecretKey() (*SecretKey, error) {
	var seed [32]byte
	key, err := new(accumulator.SecretKey).New(mpc.K_DEFAULT_ZK_CURVE, seed[:])
	if err != nil {
		return nil, err
	}
	return &SecretKey{SecretKey: key}, nil
}

// OpenSecretKey opens a secret key
func OpenSecretKey(key []byte) (*SecretKey, error) {
	e := new(accumulator.SecretKey)
	err := e.UnmarshalBinary(key)
	if err != nil {
		return nil, err
	}
	return &SecretKey{SecretKey: e}, nil
}

// CreateAccumulator creates a new accumulator
func (s *SecretKey) CreateAccumulator() (*Accumulator, error) {
	acc, err := new(accumulator.Accumulator).New(mpc.K_DEFAULT_ZK_CURVE)
	if err != nil {
		return nil, err
	}
	return &Accumulator{Accumulator: acc}, nil
}

// OpenAccumulator opens an accumulator
func (s *SecretKey) OpenAccumulator(hexAcc string) (*Accumulator, error) {
	acc, err := hex.DecodeString(hexAcc)
	if err != nil {
		return nil, err
	}
	e := new(accumulator.Accumulator)
	err = e.UnmarshalBinary(acc)
	if err != nil {
		return nil, err
	}
	return &Accumulator{Accumulator: e}, nil
}

// PublicKey returns the public key for the secret key
func (s *SecretKey) PublicKey() (*PublicKey, error) {
	pk, err := s.SecretKey.GetPublicKey(mpc.K_DEFAULT_ZK_CURVE)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// Serialize marshals the secret key
func (s *SecretKey) Serialize() ([]byte, error) {
	return s.SecretKey.MarshalBinary()
}

// Accumulator is the secret key for the BLS scheme
type Accumulator struct {
	*accumulator.Accumulator
}

// AddValue adds a value to the accumulator
func (a *Accumulator) AddValues(k *SecretKey, values ...string) error {
	elements := []accumulator.Element{}
	for _, value := range values {
		element := mpc.K_DEFAULT_ZK_CURVE.Scalar.Hash([]byte(value))
		elements = append(elements, element)
	}

	acc, _, err := a.Accumulator.Update(k.SecretKey, elements, nil)
	if err != nil {
		return err
	}
	a.Accumulator = acc
	return nil
}

// RemoveValue removes a value from the accumulator
func (a *Accumulator) RemoveValues(k *SecretKey, values ...string) error {
	elements := []accumulator.Element{}
	for _, value := range values {
		element := mpc.K_DEFAULT_ZK_CURVE.Scalar.Hash([]byte(value))
		elements = append(elements, element)
	}

	acc, _, err := a.Accumulator.Update(k.SecretKey, nil, elements)
	if err != nil {
		return err
	}
	a.Accumulator = acc
	return nil
}

// CreateWitness creates a witness for the accumulator for a given value
func (a *Accumulator) CreateWitness(k *SecretKey, value string) (string, error) {
	element := mpc.K_DEFAULT_ZK_CURVE.Scalar.Hash([]byte(value))
	mw, err := new(accumulator.MembershipWitness).New(element, a.Accumulator, k.SecretKey)
	if err != nil {
		return "", err
	}
	mwbz, err := mw.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base58.Encode(mwbz), nil
}

// VerifyElement verifies an element against the accumulator and public key
func (a *Accumulator) VerifyElement(pk *PublicKey, witness string) (bool, error) {
	mbbz, err := base58.Decode(witness)
	if err != nil {
		return false, err
	}
	mw := new(accumulator.MembershipWitness)
	err = mw.UnmarshalBinary(mbbz)
	if err != nil {
		return false, err
	}
	err = mw.Verify(pk, a.Accumulator)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Serialize marshals the accumulator to a hex string
func (a *Accumulator) Serialize() (string, error) {
	bz, err := a.Accumulator.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bz), nil
}
