package party

import (
	"fmt"

	"github.com/sonrhq/sonr/crypto/core/curves"
	"github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	"github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

// Party is a party in the DKG protocol
type PrivateParty struct {
	role      PartyRole
	curve     *curves.Curve
	dkgOutput *dklsv1.AliceDkg
	result    *protocol.Message
}

// NewParty creates a new party
func NewPrivateParty(curve *curves.Curve) Party {
	p := &PrivateParty{
		role:      PartyRolePrivate,
		curve:     curve,
		dkgOutput: dklsv1.NewAliceDkg(curve, protocol.Version1),
	}
	return p
}

// GetResult returns the result of the protocol for the party after execution
func (p *PrivateParty) Finish() (*protocol.Message, error) {
	res, err := p.dkgOutput.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	p.result = res
	return res, nil
}

// GetSignFunc returns the sign function for the party
func (p *PrivateParty) GetSignFunc(msg []byte) (protocol.Iterator, error) {
	aliceSign, err := dklsv1.NewAliceSign(p.curve, sha3.New256(), msg, p.result, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error creating Alice sign: %v", err)
	}
	return aliceSign, nil
}

// Iterator returns the iterator for the party
func (p *PrivateParty) Iterator() protocol.Iterator {
	return p.dkgOutput
}

// PublicPoint returns the public point of the party
func (p *PrivateParty) PublicPoint() (*curves.EcPoint, error) {
	// Decode the result message
	aliceRes, err := dklsv1.DecodeAliceDkgResult(p.result)
	if err != nil {
		return nil, err
	}
	return buildEcPoint(p.curve, aliceRes.PublicKey.ToAffineCompressed())
}

// Role returns the role of the party
func (p *PrivateParty) Role() PartyRole {
	return p.role
}

// Verify verifies the signature of the message
func (p *PrivateParty) Verify(msg []byte, sigBz []byte) (bool, error) {
	sig, err := ecdsa.DeserializeSecp256k1Signature(sigBz)
	if err != nil {
		return false, fmt.Errorf("error deserializing signature: %v", err)
	}
	hash := sha3.New256()
	_, err = hash.Write(msg)
	if err != nil {
		return false, fmt.Errorf("error hashing message: %v", err)
	}
	digest := hash.Sum(nil)
	publicKey, err := p.PublicPoint()
	if err != nil {
		return false, fmt.Errorf("error getting public key: %v", err)
	}
	return curves.VerifyEcdsa(publicKey, digest[:], sig), nil
}
