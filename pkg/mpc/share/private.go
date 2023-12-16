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

// Share is a Share in the DKG protocol
type PrivateShare struct {
	role      ShareRole
	curve     *curves.Curve
	dkgOutput *dklsv1.AliceDkg
	result    *protocol.Message
}

// NewShare creates a new Share
func NewPrivateShare(curve *curves.Curve) Share {
	p := &PrivateShare{
		role:      ShareRolePrivate,
		curve:     curve,
		dkgOutput: dklsv1.NewAliceDkg(curve, protocol.Version1),
	}
	return p
}

// GetResult returns the result of the protocol for the Share after execution
func (p *PrivateShare) Finish() (error) {
	res, err := p.dkgOutput.Result(protocol.Version1)
	if err != nil {
		return  err
	}
	p.result = res
	return nil
}

// GetSignFunc returns the sign function for the Share
func (p *PrivateShare) GetSignFunc(msg []byte) (protocol.Iterator, error) {
	aliceSign, err := dklsv1.NewAliceSign(p.curve, sha3.New256(), msg, p.result, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error creating Alice sign: %v", err)
	}
	return aliceSign, nil
}

// Iterator returns the iterator for the Share
func (p *PrivateShare) Iterator() protocol.Iterator {
	return p.dkgOutput
}

// PublicPoint returns the public point of the Share
func (p *PrivateShare) PublicPoint() (*curves.EcPoint, error) {
	// Decode the result message
	aliceRes, err := dklsv1.DecodeAliceDkgResult(p.result)
	if err != nil {
		return nil, err
	}
	return buildEcPoint(p.curve, aliceRes.PublicKey.ToAffineCompressed())
}

// Role returns the role of the Share
func (p *PrivateShare) Role() ShareRole {
	return p.role
}

// Verify verifies the signature of the message
func (p *PrivateShare) Verify(msg []byte, sigBz []byte) (bool, error) {
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


func (p *PrivateShare) Marshal() ([]byte, error) {
	if p.result == nil {
		return nil, fmt.Errorf("no result to marshal")
	}

	bobRes, err := dklsv1.DecodeAliceDkgResult(p.result)
	if err != nil {
		return nil, err
	}
	enc, err := dklsv1.EncodeAliceDkgOutput(bobRes, version)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enc)
}

func (ks *PrivateShare) Unmarshal(bz []byte) error {
	msg := &protocol.Message{}
	err := json.Unmarshal(bz, msg)
	if err != nil {
		return fmt.Errorf("error unmarshalling keyshare: %v", err)
	}
	_, err = dklsv1.DecodeAliceDkgResult(msg)
	if err != nil {
		return err
	}
	ks.result = msg
	return nil
}
