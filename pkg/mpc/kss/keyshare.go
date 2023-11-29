package kss

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/sonrhq/sonr/crypto/core/curves"
	"github.com/sonrhq/sonr/crypto/core/protocol"
	"github.com/sonrhq/sonr/crypto/signatures/ecdsa"
	dklsv1 "github.com/sonrhq/sonr/crypto/tecdsa/dklsv1"
	"github.com/sonrhq/sonr/crypto/tecdsa/dklsv1/dkg"
	"golang.org/x/crypto/sha3"
)

var kDefaultCurve = curves.K256()

// Keyshare is a struct that contains the DKG result message and the role of the keyshare.
type Keyshare struct {
	// The `dkgResultMessage` field is a pointer to a `protocol.Message` object that contains the DKG result message.
	Output *protocol.Message `json:"output"`

	// The `role` field is a `KeyshareRole` object that indicates the role of the keyshare.
	Role KeyshareRole `json:"role"`
}

// NewAliceKeyshare function creates a new `Keyshare` object using the provided Alice DKG result message.
func NewAliceKeyshare(dkgResultMsg *protocol.Message) *Keyshare {
	return &Keyshare{
		Output: dkgResultMsg,
		Role:   KeyshareRolePublic,
	}
}

// NewBobKeyshare function creates a new `Keyshare` object using the provided Bob DKG result message.
func NewBobKeyshare(dkgResultMsg *protocol.Message) *Keyshare {
	return &Keyshare{
		Output: dkgResultMsg,
		Role:   KeyshareRoleUser,
	}
}

// FormatAddress returns the address of the keyshare in the specified coin type.
func (ks *Keyshare) FormatAddress(ct crypto.CoinType) (string, error) {
	spk, err := ks.PublicKey()
	if err != nil {
		return "", fmt.Errorf("error getting alice public key: %v", err)
	}
	return ct.FormatAddress(spk), nil
}

// FormatDID returns the DID of the keyshare in the specified coin type.
func (ks *Keyshare) FormatDID(ct crypto.CoinType) (string, error) {
	spk, err := ks.PublicKey()
	if err != nil {
		return "", fmt.Errorf("error getting alice public key: %v", err)
	}
	did, _ := ct.FormatDID(spk)
	return did, nil
}

// GetAliceDKGResult function returns the Alice DKG result message.
func (ks *Keyshare) GetAliceDKGResult() (*dkg.AliceOutput, error) {
	return dklsv1.DecodeAliceDkgResult(ks.Output)
}

// GetBobDKGResult function returns the Bob DKG result message.
func (ks *Keyshare) GetBobDKGResult() (*dkg.BobOutput, error) {
	return dklsv1.DecodeBobDkgResult(ks.Output)
}

// MarshalPublic returns the marshalled public keyshare.
func (ks *Keyshare) MarshalPublic() ([]byte, error) {
	dkgResult, err := ks.GetAliceDKGResult()
	if err != nil {
		return nil, fmt.Errorf("error getting alice dkg result: %v", err)
	}
	msg, err := dklsv1.EncodeAliceDkgOutput(dkgResult, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error encoding alice dkg result: %v", err)
	}
	return json.Marshal(msg)
}

// MarshalPrivate returns the marshalled private keyshare.
func (ks *Keyshare) MarshalPrivate() ([]byte, error) {
	dkgResult, err := ks.GetBobDKGResult()
	if err != nil {
		return nil, fmt.Errorf("error getting bob dkg result: %v", err)
	}
	msg, err := dklsv1.EncodeBobDkgOutput(dkgResult, protocol.Version1)
	if err != nil {
		return nil, fmt.Errorf("error encoding bob dkg result: %v", err)
	}
	return json.Marshal(msg)
}

// UnmarshalPrivate unmarshals the private keyshare.
func (ks *Keyshare) UnmarshalPrivate(bz []byte) error {
	var msg protocol.Message
	if err := json.Unmarshal(bz, &msg); err != nil {
		return fmt.Errorf("error unmarshalling keyshare: %v", err)
	}
	if _, err := ks.GetBobDKGResult(); err != nil {
		return fmt.Errorf("error getting bob dkg result: %v", err)
	}
	ks.Output = &msg
	return nil
}

// UnmarshalPublic unmarshals the public keyshare.
func (ks *Keyshare) UnmarshalPublic(bz []byte) error {
	var msg protocol.Message
	if err := json.Unmarshal(bz, &msg); err != nil {
		return fmt.Errorf("error unmarshalling keyshare: %v", err)
	}
	ks.Output = &msg
	if _, err := ks.GetAliceDKGResult(); err != nil {
		return fmt.Errorf("error getting alice dkg result: %v", err)
	}
	return nil
}

// PublicKey returns the public key of the keyshare as a secp256k1.PubKey
func (ks *Keyshare) PublicKey() (crypto.PublicKey, error) {
	buildSecp256k1 := func(bz []byte) crypto.PublicKey {
		return crypto.NewSecp256k1PubKey(bz)
	}
	if ks.Role.isAlice() {
		dkgResult, err := ks.GetAliceDKGResult()
		if err != nil {
			return nil, fmt.Errorf("error getting alice dkg result: %v", err)
		}
		return buildSecp256k1(dkgResult.PublicKey.ToAffineCompressed()), nil
	}
	if ks.Role.isBob() {
		dkgResult, err := ks.GetBobDKGResult()
		if err != nil {
			return nil, fmt.Errorf("error getting bob dkg result: %v", err)
		}
		return buildSecp256k1(dkgResult.PublicKey.ToAffineCompressed()), nil
	}
	return nil, fmt.Errorf("invalid keyshare role: %v", ks.Role)
}

// PublicPoint returns the public key of the keyshare as a *curves.EcPoint
func (ks *Keyshare) PublicPoint() (*curves.EcPoint, error) {
	buildEcPoint := func(bz []byte) (*curves.EcPoint, error) {
		x := new(big.Int).SetBytes(bz[1:33])
		y := new(big.Int).SetBytes(bz[33:])
		ecCurve, err := kDefaultCurve.ToEllipticCurve()
		if err != nil {
			return nil, fmt.Errorf("error converting curve: %v", err)
		}
		return &curves.EcPoint{X: x, Y: y, Curve: ecCurve}, nil
	}

	if ks.Role.isAlice() {
		dkgResult, err := ks.GetAliceDKGResult()
		if err != nil {
			return nil, fmt.Errorf("error getting alice dkg result: %v", err)
		}
		return buildEcPoint(dkgResult.PublicKey.ToAffineUncompressed())
	}
	if ks.Role.isBob() {
		dkgResult, err := ks.GetBobDKGResult()
		if err != nil {
			return nil, fmt.Errorf("error getting bob dkg result: %v", err)
		}
		return buildEcPoint(dkgResult.PublicKey.ToAffineUncompressed())
	}
	return nil, fmt.Errorf("invalid keyshare role: %v", ks.Role)
}

// Verify returns true if the signature is valid for the keyshare
func (ks *Keyshare) Verify(msg []byte, sigBz []byte) (bool, error) {
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
	publicKey, err := ks.PublicPoint()
	if err != nil {
		return false, fmt.Errorf("error getting public key: %v", err)
	}
	return curves.VerifyEcdsa(publicKey, digest[:], sig), nil
}
