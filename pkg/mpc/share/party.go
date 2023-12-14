package share

import (
	"fmt"
	"math/big"

	"github.com/sonrhq/sonr/crypto/core/curves"
	"github.com/sonrhq/sonr/crypto/core/protocol"
)

// Share is an interface for a party in the DKG protocol
type Share interface {
	// GetKeyshare returns the keyshare for the party
	Finish() (*protocol.Message, error)

	// GetSignFunc returns the sign function for the party
	GetSignFunc(msg []byte) (protocol.Iterator, error)

	// Iterator returns the iterator for the party
	Iterator() protocol.Iterator

	// Marshal returns the encoded keyshare data for the party
	Marshal() ([]byte, error)

	// PublicPoint returns the Ec public point of the party
	PublicPoint() (*curves.EcPoint, error)

	// Role returns the role of the Share
	Role() ShareRole

	// Unmarshal unmarshals the encoded keyshare data for the party
	Unmarshal(bz []byte) error

	// Verify verifies a message with the signature
	Verify(msg []byte, sigBz []byte) (bool, error)
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
