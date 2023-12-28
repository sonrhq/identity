package controller

type InitRequest struct {
	ResponseChannel chan *InitResponse
}

type InitResponse struct {
	Address string
	PublicKey []byte
	Error error
}

type SignRequest struct {
	Message []byte
    ResponseChannel chan *SignResponse
}

type SignResponse struct {
	Message   []byte
	Signature []byte
	Error     error
}

type VerifyRequest struct {
	Message   []byte
	Signature []byte
    ResponseChannel chan *VerifyResponse
}

type VerifyResponse struct {
	Verified bool
	Error    error
}
