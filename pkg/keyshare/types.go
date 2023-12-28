package keyshare

import "github.com/sonrhq/identity/pkg/mpc/share"

type GetSignFuncRequest struct {
	Message         []byte
	ResponseChannel chan *GetSignFuncResponse
}

type GetSignFuncResponse struct {
	Message   []byte
	Signature []byte
	Role      share.ShareRole
	Error     error
}

type VerifyRequest struct {
	Message         []byte
	Signature       []byte
	ResponseChannel chan *VerifyResponse
}

type VerifyResponse struct {
	Verified bool
	Role      share.ShareRole
	Error    error
}
