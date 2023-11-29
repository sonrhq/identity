package kss

import (
	"encoding/json"
	"fmt"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/sonrhq/sonr/crypto/core/protocol"
)

// EncKeyshareSet is a type alias for the EncKeyshareSet struct in the v1types package.
type EncKeyshareSet struct {
	Public    *Keyshare `json:"public"`
	Encrypted []byte    `json:"user"`
}

// FormatDID returns the DID of the account based on the coin type
func (kss *EncKeyshareSet) FormatDID(ct crypto.CoinType) string {
	did, err := kss.Public.FormatDID(ct)
	if err != nil {
		panic(err)
	}
	return did
}

// The `PublicKey()` function is a method of the `KeyshareSet` type. It returns the public key corresponding to Alice's keyshare in the keyshare set. It does this by calling the `PubKey()` method of the `Keyshare` object corresponding to Alice's keyshare. If the keyshare set is not
// valid or if there is an error in retrieving the public key, it returns an error.
func (kss *EncKeyshareSet) PublicKey() crypto.PublicKey {
	pub, err := kss.Public.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}

// GetAccountData returns the proto representation of the account
func (kss *EncKeyshareSet) GetAccountData(ct crypto.CoinType) *crypto.AccountData {
	dat, err := crypto.NewDefaultAccountData(ct, kss.PublicKey())
	if err != nil {
		panic(err)
	}
	return dat
}

// Marshal returns the JSON encoding of the EncKeyshareSet.
func (kss *EncKeyshareSet) Marshal() ([]byte, error) {
	return json.Marshal(kss)
}

// Unmarshal parses the JSON-encoded data and stores the result in the EncKeyshareSet.
func (kss *EncKeyshareSet) Unmarshal(bz []byte) error {
	return json.Unmarshal(bz, kss)
}

// DecryptUserKeyshare decrypts the user keyshare using the provided encryption key.
func (kss *EncKeyshareSet) DecryptUserKeyshare(key crypto.EncryptionKey) (KeyshareSet, error) {
	alice := kss.Public
	if alice == nil {
		return EmptyKeyshareSet(), fmt.Errorf("alice keyshare is nil")
	}
	bz, err := key.Decrypt(kss.Encrypted)
	if err != nil {
		return EmptyKeyshareSet(), fmt.Errorf("error decrypting keyshare: %v", err)
	}
	// Deserialize keyshare
	msg := &protocol.Message{}
	if err := json.Unmarshal(bz, msg); err != nil {
		return EmptyKeyshareSet(), fmt.Errorf("error unmarshalling keyshare: %v", err)
	}
	bob := NewBobKeyshare(msg)
	return KeyshareSet{
		alice,
		bob,
	}, nil
}
