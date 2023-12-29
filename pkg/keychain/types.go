package keychain

import (
	"github.com/sonrhq/sonr/crypto/core/curves"

	modulev1 "github.com/sonrhq/identity/api/module/v1"
)

type GenerateRequest struct {
	CoinType modulev1.CoinType
	Curve           *curves.Curve
}

type SignRequest struct {
	Message         []byte
	ResponseChannel chan *SignResponse
}

type SignResponse struct {
	Signature []byte
	Message   []byte
	Error    error
}

type VerifyRequest struct {
	Message         []byte
	Signature       []byte
	ResponseChannel chan *VerifyResponse
}

type VerifyResponse struct {
	Verified bool
	Error    error
}
