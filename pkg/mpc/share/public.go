package share

import (
	"encoding/json"
	"fmt"

	"github.com/sonrhq/sonr/crypto/core/curves"
	"github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	"github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

const version = protocol.Version1

// Share is a party in the DKG protocol
type PublicShare struct {
	role      ShareRole
	curve     *curves.Curve
	dkgOutput *dklsv1.BobDkg
	result    *protocol.Message
}

// NewShare creates a new party
func NewPublicShare(curve *curves.Curve) Share {
	p := &PublicShare{
		role:      ShareRolePublic,
		curve:     curve,
		dkgOutput: dklsv1.NewBobDkg(curve, protocol.Version1),
	}
	return p
}

// GetResult returns the result of the protocol for the party after execution
func (p *PublicShare) Finish() (*protocol.Message, error) {
	res, err := p.dkgOutput.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	p.result = res
	return res, nil
}

// GetSignFunc returns the sign function for the party
func (p *PublicShare) GetSignFunc(msg []byte) (protocol.Iterator, error) {
	bobSign, err := dklsv1.NewBobSign(p.curve, sha3.New256(), msg, p.result, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error creating Alice sign: %v", err)
	}
	return bobSign, nil
}

// Iterator returns the iterator for the party
func (p *PublicShare) Iterator() protocol.Iterator {
	return p.dkgOutput
}

// PublicPoint returns the public point of the party
func (p *PublicShare) PublicPoint() (*curves.EcPoint, error) {
	// Decode the result message
	bobRes, err := dklsv1.DecodeBobDkgResult(p.result)
	if err != nil {
		return nil, err
	}
	return buildEcPoint(p.curve, bobRes.PublicKey.ToAffineCompressed())
}

// Role returns the role of the party
func (p *PublicShare) Role() ShareRole {
	return p.role
}

// Verify verifies the signature of the message
func (p *PublicShare) Verify(msg []byte, sigBz []byte) (bool, error) {
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

func (p *PublicShare) Marshal() ([]byte, error) {
	if p.result == nil {
		return nil, fmt.Errorf("no result to marshal")
	}

	bobRes, err := dklsv1.DecodeBobDkgResult(p.result)
	if err != nil {
		return nil, err
	}
	enc, err := dklsv1.EncodeBobDkgOutput(bobRes, version)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enc)
}

func (ks *PublicShare) Unmarshal(bz []byte) error {
	msg := &protocol.Message{}
	err := json.Unmarshal(bz, msg)
	if err != nil {
		return fmt.Errorf("error unmarshalling keyshare: %v", err)
	}
	_, err = dklsv1.DecodeBobDkgResult(msg)
	if err != nil {
		return err
	}
	ks.result = msg
	return nil
}
