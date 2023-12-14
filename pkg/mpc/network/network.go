package network

import (
	"fmt"

	"github.com/sonrhq/sonr/crypto/core/curves"
	pv1 "github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	"github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"

	"github.com/sonrhq/identity/pkg/mpc/share"
)

// Network is a network interface for MPC protocols
type Network struct {
	curve *curves.Curve
	valParty share.Share
	userParty share.Share
}

// NewNetwork creates a new network
func NewNetwork() Network {
	c := curves.K256()
	vp := share.NewPrivateShare(c)
	up := share.NewPublicShare(c)
	return Network{
		curve: c,
		valParty: vp,
		userParty: up,
	}
}

// Generate runs the network to generate a keyshare set
func (n Network) Generate() (error) {
	aErr, bErr := runIteratedProtocol(n.userParty.Iterator(), n.valParty.Iterator())
	if aErr != pv1.ErrProtocolFinished || bErr != pv1.ErrProtocolFinished {
		return fmt.Errorf("error running protocol: aErr=%v, bErr=%v", aErr, bErr)
	}
	_, err := n.valParty.Finish()
	if err != nil {
		return fmt.Errorf("error getting Alice DKG result: %v", err)
	}
	_, err = n.userParty.Finish()
	if err != nil {
		return fmt.Errorf("error getting Bob DKG result: %v", err)
	}
	return nil
}

// Sign runs the network to sign a message
func (n Network) Sign(msg []byte) ([]byte, error) {
	aliceSign, err := n.valParty.GetSignFunc(msg)
	if err != nil {
		return nil, fmt.Errorf("error creating Alice sign: %v", err)
	}
	bobSign, err := n.userParty.GetSignFunc(msg)
	if err != nil {
		return nil, fmt.Errorf("error creating Bob sign: %v", err)
	}
	aErr, bErr := runIteratedProtocol(aliceSign, bobSign)
	if aErr != pv1.ErrProtocolFinished || bErr != pv1.ErrProtocolFinished {
		return nil, fmt.Errorf("error running protocol: aErr=%v, bErr=%v", aErr, bErr)
	}
	// Decode the result message
	resultMessage, err := bobSign.Result(pv1.Version1)
	if err != nil {
		return nil, fmt.Errorf("error getting result: %v", err)
	}

	result, err := dklsv1.DecodeSignature(resultMessage)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}
	sigBytes, err := ecdsa.SerializeSecp256k1Signature(result)
	if err != nil {
		return nil, fmt.Errorf("error serializing signature: %v", err)
	}
	return sigBytes, nil
}

// Verify verifies a message with the signature
func (n Network) Verify(msg []byte, sigBz []byte) (bool, error) {
	privVer, err := n.valParty.Verify(msg, sigBz)
	if err != nil {
		return false, fmt.Errorf("error creating Alice verify: %v", err)
	}
	pubVer, err := n.userParty.Verify(msg, sigBz)
	if err != nil {
		return false, fmt.Errorf("error creating Bob verify: %v", err)
	}
	return privVer && pubVer, nil
}

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
