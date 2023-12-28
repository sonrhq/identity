package keychain

import (
	"fmt"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/crypto/core/curves"

	"github.com/sonrhq/identity/pkg/mpc/share"
)

type KeyChain interface {
	actor.Actor
}

// keychain is an actor that is responsible for one of the two parts of a dkls protocol.
type keychain struct {
	DID  string
	Name string
	IsReady bool

	curve    *curves.Curve
	rootPriv share.Share
	rootPub  share.Share
}

// NewPrivate creates a new keyshare actor.
func New(crv *curves.Curve) KeyChain {
	privKs := share.NewPrivateShare(crv)
	pubKs := share.NewPublicShare(crv)
	return &keychain{
		IsReady: false,
		curve:    crv,
		rootPriv: privKs,
		rootPub:  pubKs,
	}
}

// Receive handles the message from the keyshare.
func (s *keychain) Receive(context actor.Context) {
	switch msg := context.Message().(type) {
	case *actor.Started:
		msg.SystemMessage()
		fmt.Println("Starting, initialize actor here")
	case *actor.Stopping:
		fmt.Println("Stopping, actor is about shut down")
	case *actor.Stopped:
		fmt.Println("Stopped, actor and its children are stopped")
	case GenerateRequest:
		s.GenerateSequence(&msg)
	case SignRequest:
		s.SignSequence(&msg)
	case VerifyRequest:
		s.VerifySequence(&msg)
	}
}
