package keychain

type GenerateRequest struct {
	ResponseChannel chan *GenerateResponse
}

type GenerateResponse struct {
	PublicKey []byte
	Error    error
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
