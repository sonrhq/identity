package kss

import (
	pv1 "github.com/sonrhq/sonr/crypto/core/protocol"
)

type KeyshareRole string

const (
	// KeyshareRolePublic is the default role for the alice dkg
	KeyshareRolePublic KeyshareRole = "alice"

	// KeyshareRoleUser is the role for an encrypted keyshare for a user
	KeyshareRoleUser KeyshareRole = "bob"
)

// isAlice returns true if the keyshare role is alice
func (ksr KeyshareRole) isAlice() bool {
	return ksr == KeyshareRolePublic
}

// isBob returns true if the keyshare role is bob
func (ksr KeyshareRole) isBob() bool {
	return ksr == KeyshareRoleUser
}


// For DKG bob starts first. For refresh and sign, Alice starts first.
func RunIteratedProtocol(firstParty pv1.Iterator, secondParty pv1.Iterator) (error, error) {
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
