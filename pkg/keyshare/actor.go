package keyshare

import (
	"fmt"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/crypto/core/curves"

	"github.com/sonrhq/identity/pkg/mpc/share"
)

type Keyshare interface {
	actor.Actor
}

// keyshare is an actor that is responsible for one of the two parts of a dkls protocol.
type keyshare struct {
	DID  string
	Name string
	Role share.ShareRole

    data []byte
}

// NewKeyshare creates a new keyshare actor.
func NewPrivate(crv *curves.Curve) (Keyshare, error) {
    privKs := share.NewPrivateShare(crv)
    privBz, err := privKs.Marshal()
    if err!= nil {
        return nil, err
    }
	return &keyshare{
		Role: share.ShareRolePrivate,
        data: privBz,
	}, nil
}

// NewPublic creates a new keyshare actor.
func NewPublic(crv *curves.Curve) (Keyshare, error) {
	pubKs := share.NewPublicShare(crv)
    pubBz, err := pubKs.Marshal()
    if err!= nil {
        return nil, err
    }
    return &keyshare{
        Role: share.ShareRolePublic,
        data: pubBz,
    }, nil
}

// Receive handles the message from the keyshare.
func (s *keyshare) Receive(context actor.Context) {
	switch msg := context.Message().(type) {
	case *actor.Started:
		msg.SystemMessage()
		fmt.Println("Starting, initialize actor here")
	case *actor.Stopping:
		fmt.Println("Stopping, actor is about shut down")
	case *actor.Stopped:
		fmt.Println("Stopped, actor and its children are stopped")
	case GetSignFuncRequest:
		s.GetSignFuncSequence(&msg)
	case VerifyRequest:
		s.VerifySequence(&msg)
	}
}
