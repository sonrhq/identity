package keychain

import (
	"fmt"

	"github.com/sonrhq/sonr/crypto/core/curves"
	pv1 "github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	"github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

func (s *keychain) GenerateSequence(req *GenerateRequest) {
	aErr, bErr := runIteratedProtocol(s.rootPub.Iterator(), s.rootPriv.Iterator())
	if aErr != pv1.ErrProtocolFinished || bErr != pv1.ErrProtocolFinished {
		req.ResponseChannel <- &GenerateResponse{
			Error: fmt.Errorf("error running protocol: aErr=%v, bErr=%v", aErr, bErr),
		}
		return
	}
	_, err := s.rootPriv.Finish()
	if err != nil {
		req.ResponseChannel <- &GenerateResponse{
			Error: fmt.Errorf("error getting Alice DKG result: %v", err),
		}
		return
	}

	_, err = s.rootPub.Finish()
	if err != nil {
		req.ResponseChannel <- &GenerateResponse{
			Error: fmt.Errorf("error getting Bob DKG result: %v", err),
		}
		return
	}

	req.ResponseChannel <- &GenerateResponse{
		Error: nil,
	}
}

func (s *keychain) SignSequence(req *SignRequest) {
	if !s.IsReady {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("keyset not ready"),
		}
		return
	}
	privSign, err := s.rootPriv.GetSignFunc(req.Message)
	if err != nil {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("failed to get sign func from Priv Share: %w", err),
		}
		return
	}

	pubSign, err := s.rootPub.GetSignFunc(req.Message)
	if err != nil {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("failed to get sign func from Pub Share: %w", err),
		}
		return
	}
	aErr, bErr := runIteratedProtocol(privSign, pubSign)
	if aErr != pv1.ErrProtocolFinished || bErr != pv1.ErrProtocolFinished {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("error running protocol: aErr=%v, bErr=%v", aErr, bErr),
		}
		return
	}
	resultMessage, err := pubSign.Result(pv1.Version1)
	if err != nil {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("error getting result: %v", err),
		}
		return
	}

	result, err := dklsv1.DecodeSignature(resultMessage)
	if err != nil {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("error decoding result: %v", err),
		}
		return
	}
	sigBytes, err := ecdsa.SerializeSecp256k1Signature(result)
	if err != nil {
		req.ResponseChannel <- &SignResponse{
			Signature: nil,
			Message:   req.Message,
			Error:     fmt.Errorf("error serializing result: %v", err),
		}
		return
	}
	s.IsReady = true
	req.ResponseChannel <- &SignResponse{
		Signature: sigBytes,
		Message:   req.Message,
		Error:     nil,
	}
}

func (s *keychain) VerifySequence(req *VerifyRequest) {
	sig, err := ecdsa.DeserializeSecp256k1Signature(req.Signature)
	if err != nil {
		req.ResponseChannel <- &VerifyResponse{
			Verified: false,
			Error:    fmt.Errorf("failed to verify: %w", err),
		}
		return
	}
	hash := sha3.New256()
	_, err = hash.Write(req.Message)
	if err != nil {
		req.ResponseChannel <- &VerifyResponse{
			Verified: false,
			Error:    fmt.Errorf("failed to verify: %w", err),
		}
		return
	}
	digest := hash.Sum(nil)
	publicKey, err := s.rootPub.PublicPoint()
	if err != nil {
		req.ResponseChannel <- &VerifyResponse{
			Verified: false,
			Error:    fmt.Errorf("failed to verify: %w", err),
		}
		return
	}
	ok := curves.VerifyEcdsa(publicKey, digest[:], sig)
	req.ResponseChannel <- &VerifyResponse{
		Verified: ok,
		Error:    nil,
	}
}

// ! ||--------------------------------------------------------------------------------||
// ! ||                                Network Utilities                               ||
// ! ||--------------------------------------------------------------------------------||

// For DKG bob starts first. For refresh and sign, Alice starts first.
func runIteratedProtocol(firstParty pv1.Iterator, secondParty pv1.Iterator) (error, error) {
	var (
		message *pv1.Message
		aErr    error
		bErr    error
	)
	for aErr != pv1.ErrProtocolFinished || bErr != pv1.ErrProtocolFinished {
		// Crank each protocol forward one iteration
		message, bErr = firstParty.Next(message)
		if bErr != nil && bErr != pv1.ErrProtocolFinished {
			return nil, bErr
		}

		message, aErr = secondParty.Next(message)
		if aErr != nil && aErr != pv1.ErrProtocolFinished {
			return aErr, nil
		}
	}
	return aErr, bErr
}
