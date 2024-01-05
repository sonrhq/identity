package didmethod

import (
	modulev1 "github.com/sonrhq/identity/api/module/v1"
)

// GetHRPByCoinType returns the HRP for the given coin type.
func GetHRPByCoinType(coinType modulev1.CoinType) string {
	switch coinType {
	case modulev1.CoinType_COIN_TYPE_ATOM:
		return "cosmos"
	case modulev1.CoinType_COIN_TYPE_AXELAR:
		return "axelar"
	case modulev1.CoinType_COIN_TYPE_BITCOIN:
		return "bc"
	case modulev1.CoinType_COIN_TYPE_ETHEREUM:
		return "0x"
	case modulev1.CoinType_COIN_TYPE_EVMOS:
		return "evmos"
	case modulev1.CoinType_COIN_TYPE_JUNO:
		return "juno"
	case modulev1.CoinType_COIN_TYPE_OSMO:
		return "osmo"
	case modulev1.CoinType_COIN_TYPE_SOLANA:
		return "sol"
	case modulev1.CoinType_COIN_TYPE_SONR:
		return "idx"
	case modulev1.CoinType_COIN_TYPE_STARGAZE:
		return "stars"
	}
	return ""
}

// GetDIDMethodByCoinType returns the DID method for the given coin type.
func GetDIDMethodByCoinType(coinType modulev1.CoinType) string {
    	switch coinType {
	case modulev1.CoinType_COIN_TYPE_ATOM:
		return "did:cosmosr:"
	case modulev1.CoinType_COIN_TYPE_AXELAR:
		return "did:cosmosr:"
	case modulev1.CoinType_COIN_TYPE_BITCOIN:
		return "did:btcr:"
	case modulev1.CoinType_COIN_TYPE_ETHEREUM:
		return "did:ethr:"
	case modulev1.CoinType_COIN_TYPE_EVMOS:
		return "did:cosmosr:"
	case modulev1.CoinType_COIN_TYPE_JUNO:
		return "did:cosmosr:"
	case modulev1.CoinType_COIN_TYPE_OSMO:
		return "did:cosmosr:"
	case modulev1.CoinType_COIN_TYPE_SOLANA:
		return "did:solr:"
	case modulev1.CoinType_COIN_TYPE_SONR:
		return "did:sonr:"
	case modulev1.CoinType_COIN_TYPE_STARGAZE:
		return "did:cosmosr:"
	}
	return ""
}
