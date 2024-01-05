package didmethod

import (
	"github.com/okx/go-wallet-sdk/coins/cosmos"

	modulev1 "github.com/sonrhq/identity/api/module/v1"
)

// NewCosmosAddress returns a cosmos address from a coin type and hex public key.
func NewCosmosAddress(coinType modulev1.CoinType, pubKeyHex string) (string, error) {
    hrp := GetHRPByCoinType(coinType)
    addr, err := cosmos.GetAddressByPublicKey(pubKeyHex, hrp)
    if err!= nil {
        return "", err
    }
    return addr, nil
}
