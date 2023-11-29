package bip44

import (
	"encoding/json"
	"fmt"

	"github.com/sonrhq/sonr/common/crypto"

	"github.com/sonrhq/identity/pkg/mpc/network"
)

type AccountV1 struct {
	// Address is the address of the account.
	Address string `json:"address"`

	// CoinType is the coin type of the account.
	CoinType crypto.CoinType `json:"coin_type"`

	// Name is the name of the account.
	Name string `json:"name"`

	// Data is the marshalled keyshare
	Data []byte `json:"data"`
}

// NewAccountV1 creates a new account with the given name and coin type.
func NewAccountV1(name string, coin crypto.CoinType) (*AccountV1, error) {
	mpcNet := network.NewNetwork()
	err := mpcNet.Generate()
	if err != nil {
		return nil, fmt.Errorf("error generating keyshare set: %v", err)
	}
	acc := &AccountV1{
		CoinType:       coin,
		Name:           name,
	}
	return acc, nil
}


// DIDAlias returns the DID alias or name of the account.
func (a *AccountV1) DIDAlias() string {
	return a.Name
}



// Marshal returns the JSON encoding of the account.
func (a *AccountV1) Marshal() ([]byte, error) {
	return json.Marshal(a)
}

// Unmarshal parses the JSON-encoded data and stores the result in the account.
func (a *AccountV1) Unmarshal(data []byte) error {
	err := json.Unmarshal(data, a)
	if err != nil {
		return err
	}
	return nil
}
