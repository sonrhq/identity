package party

import (
	"fmt"
	"math/big"

	"github.com/sonrhq/sonr/crypto/core/curves"
	"github.com/sonrhq/sonr/crypto/core/protocol"
)

// Party is an interface for a party in the DKG protocol
type Party interface {
	// GetKeyshare returns the keyshare for the party
	Finish() (*protocol.Message, error)

	// GetSignFunc returns the sign function for the party
	GetSignFunc(msg []byte) (protocol.Iterator, error)

	// Iterator returns the iterator for the party
	Iterator() protocol.Iterator

	// PublicPoint returns the public point of the party
	PublicPoint() (*curves.EcPoint, error)

	// Role returns the role of the party
	Role() PartyRole

	// Verify verifies a message with the signature
	Verify(msg []byte, sigBz []byte) (bool, error)
}

// SortParties sorts the parties by their role. The first party in the returned slice is bob, the second is alice.
func SortParties(parties []Party) ([]Party, error) {
	var (
		alice Party
		bob   Party
	)
	for _, p := range parties {
		if p.Role().IsAlice() {
			if alice != nil {
				return nil, fmt.Errorf("too many alice parties")
			}
			alice = p
		} else if p.Role().IsBob() {
			if bob != nil {
				return nil, fmt.Errorf("too many bob parties")
			}
			bob = p
		}
	}
	return []Party{bob, alice}, nil
}


func buildEcPoint(crv *curves.Curve, bz []byte) (*curves.EcPoint, error) {
	x := new(big.Int).SetBytes(bz[1:33])
	y := new(big.Int).SetBytes(bz[33:])
	ecCurve, err := crv.ToEllipticCurve()
	if err != nil {
		return nil, fmt.Errorf("error converting curve: %v", err)
	}
	return &curves.EcPoint{X: x, Y: y, Curve: ecCurve}, nil
}
