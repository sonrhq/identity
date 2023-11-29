package kss

import (
	"fmt"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	dklsv1 "github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

// KeyshareSet is a type alias for the KeyshareSet struct in the v1types package.
type KeyshareSet [2]*Keyshare

// The function returns an empty KeyshareSet.
func EmptyKeyshareSet() KeyshareSet {
	return KeyshareSet{nil, nil}
}

// NewKeyshareSet function creates a new KeyshareSet object using the provided Alice and Bob keyshares.
func NewKeyshareSet(a *Keyshare, b *Keyshare) KeyshareSet {
	return KeyshareSet{
		a,
		b,
	}
}

// NewKeyshareSetFromMessages function creates a new KeyshareSet object using the provided Alice and Bob DKG result messages.
func NewKeyshareSetFromMessages(aliceDkgResultMsg *protocol.Message, bobDkgResultMsg *protocol.Message) KeyshareSet {
	return KeyshareSet{
		NewAliceKeyshare(aliceDkgResultMsg),
		NewBobKeyshare(bobDkgResultMsg),
	}
}

// The `Alice()` function is a method of the `KeyshareSet` type. It returns the `Keyshare` object corresponding to Alice's keyshare in the keyshare set.
func (kss KeyshareSet) Alice() *Keyshare {
	a := kss[0]
	if a == nil {
		panic("alice keyshare is nil")
	}
	return a
}

// The `Bob()` function is a method of the `KeyshareSet` type. It returns the `Keyshare` object corresponding to Bob's keyshare in the keyshare set.
func (kss KeyshareSet) Bob() *Keyshare {
	b := kss[1]
	if b == nil {
		panic("bob keyshare is nil")
	}
	return b
}

// The `DKGAtIndex` function is a method of the `KeyshareSet` type. It takes an integer `i` as input and returns the DKG (Distributed Key Generation) result message at the specified index.
func (kss KeyshareSet) DKGAtIndex(i int) *protocol.Message {
	if i == 0 {
		return kss.Alice().Output
	} else if i == 1 {
		return kss.Bob().Output
	} else {
		fmt.Println("DKGAtIndex(): invalid index")
		return nil
	}
}

// FormatAddress returns the address of the account based on the coin type
func (kss KeyshareSet) FormatAddress(ct crypto.CoinType) string {
	ad, err := kss.Alice().FormatAddress(ct)
	if err != nil {
		panic(err)
	}
	return ad
}

// FormatDID returns the DID of the account based on the coin type
func (kss KeyshareSet) FormatDID(ct crypto.CoinType) string {
	did, err := kss.Alice().FormatDID(ct)
	if err != nil {
		panic(err)
	}
	return did
}

// GetAccountData returns the proto representation of the account
func (wa KeyshareSet) GetAccountData(ct crypto.CoinType) *crypto.AccountData {
	dat, err := crypto.NewDefaultAccountData(ct, wa.PublicKey())
	if err != nil {
		panic(err)
	}
	return dat
}

// IsValid returns an error if the keyshare set is invalid.
func (kss KeyshareSet) IsValid() error {
	if len(kss) != 2 {
		return fmt.Errorf("keyshare set must have exactly 2 keyshares")
	}
	alice := kss[0]
	if alice == nil {
		return fmt.Errorf("alice keyshare is nil")
	}
	bob := kss[1]
	if bob == nil {
		return fmt.Errorf("bob keyshare is nil")
	}
	return nil
}

// PublicKey returns the public key corresponding to Alice's keyshare in the keyshare set.
func (kss KeyshareSet) PublicKey() crypto.PublicKey {
	pub, err := kss.Alice().PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}

// Sign takes a byte slice `msg` as input and returns a byte slice and an error.
func (kss KeyshareSet) Sign(msg []byte) ([]byte, error) {
	if err := kss.IsValid(); err != nil {
		return nil, fmt.Errorf("error validating keyshare set: %v", err)
	}
	aliceSign, err := dklsv1.NewAliceSign(kDefaultCurve, sha3.New256(), msg, kss.Alice().Output, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error creating Alice sign: %v", err)
	}
	bobSign, err := dklsv1.NewBobSign(kDefaultCurve, sha3.New256(), msg, kss.Bob().Output, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error creating Bob sign: %v", err)
	}

	aErr, bErr := RunIteratedProtocol(aliceSign, bobSign)
	if aErr != protocol.ErrProtocolFinished || bErr != protocol.ErrProtocolFinished {
		return nil, fmt.Errorf("error running protocol: aErr=%v, bErr=%v", aErr, bErr)
	}

	resultMessage, err := bobSign.Result(protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error getting result: %v", err)
	}

	result, err := dklsv1.DecodeSignature(resultMessage)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}
	sigBytes, err := ecdsa.SerializeSecp256k1Signature(result)
	if err != nil {
		return nil, fmt.Errorf("error serializing signature: %v", err)
	}
	return sigBytes, nil
}

// Verify takes a byte slice `msg` and a byte slice `sigBz` as input and returns a boolean and an error.
func (kss KeyshareSet) Verify(msg []byte, sigBz []byte) (bool, error) {
	if err := kss.IsValid(); err != nil {
		return false, fmt.Errorf("error validating keyshare set: %v", err)
	}
	return kss[0].Verify(msg, sigBz)
}

// EncryptUserKeyshare encrypts the user keyshare using the provided encryption key.
func (kss KeyshareSet) EncryptUserKeyshare(c crypto.EncryptionKey) (*EncKeyshareSet, error) {
	if err := kss.IsValid(); err != nil {
		return nil, fmt.Errorf("error validating keyshare set: %v", err)
	}
	bz, err := kss.Bob().MarshalPrivate()
	if err != nil {
		return nil, fmt.Errorf("error marshaling bob keyshare: %v", err)
	}
	enc, err := c.Encrypt(bz)
	if err != nil {
		return nil, fmt.Errorf("error encrypting keyshare: %v", err)
	}
	return &EncKeyshareSet{
		Public:    kss.Alice(),
		Encrypted: enc,
	}, nil
}
