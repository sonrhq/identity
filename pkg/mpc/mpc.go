package mpc

import (
	"github.com/sonrhq/sonr/common/crypto"

	"github.com/sonrhq/identity/pkg/mpc/bip44"
	"github.com/sonrhq/identity/pkg/mpc/dkls"
	"github.com/sonrhq/identity/pkg/mpc/kss"
)

// AccountV1 is a type alias for the AccountV1 struct in the base package.
type AccountV1 = bip44.AccountV1

// KeyshareV1 is a type alias for the Keyshare struct in the v1types package.
type KeyshareV1 = kss.Keyshare

// KeyshareSet is a type alias for the KeyshareSet struct in the v1types package.
type KeyshareSet = kss.KeyshareSet

// EncKeyshareSet is a type alias for the EncKeyshareSet struct in the v1types package.
type EncKeyshareSet = kss.EncKeyshareSet

// GenerateV2 generates a new account with a given ID.
func GenerateV2(name string, ct crypto.CoinType) (*bip44.AccountV1, KeyshareSet, error) {
	return bip44.NewAccountV1(name, ct)
}

// KeygenV1 generates a keyshare set.
func KeygenV1() (KeyshareSet, error) {
	ksset, err := dkls.DKLSKeygen()
	if err != nil {
		return kss.EmptyKeyshareSet(), err
	}
	return ksset, nil
}

// NewKSS creates a new keyshare set from a list of keyshares.
func NewKSS(pub *KeyshareV1, priv *KeyshareV1) KeyshareSet {
	return kss.NewKeyshareSet(pub, priv)
}

