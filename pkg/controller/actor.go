package controller

import (
	"context"
	"fmt"
	"log"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/crypto/core/curves"

	"github.com/sonrhq/identity/pkg/keychain"
)

type Controller interface {
	actor.Actor
}

// controller is the api interface for the users to interact with the sonr network.
type controller struct {
	Address string
	jwt     string
	curve   *curves.Curve

	ctx      context.Context
	actorCtx *actor.RootContext
	pid      *actor.PID

	keychains map[string]keychain.KeyChain
}

// New creates a new controller actor.
func New(ctx context.Context, options ...Option) (Controller, error) {
	opts := DefaultSpawnOptions()
	c, err := opts.Apply(ctx, options...)
	if err != nil {
		log.Printf("failed to build controller. %v", err)
		return nil, err
	}
	return c, nil
}

// Receive handles the message from the keyshare.
func (s *controller) Receive(context actor.Context) {
	switch msg := context.Message().(type) {
    case SignRequest:
        s.SignSequence(context, msg)
    case VerifyRequest:
        s.VerifySequence(context, msg)
	case keychain.GenerateRequest:
		s.GenerateSequence(context, msg)
	}
}

// Handle resolves failures with child processes.
func (s *controller) Handle(reason interface{}) actor.Directive {
	fmt.Printf("handling failure for child. reason:%v", reason)
	return actor.StopDirective
}

// Send sends a message to the controller.
func (s *controller) Send(msg interface{}) error {
	if s.pid == nil || s.actorCtx == nil {
		return fmt.Errorf("keychain actor not initialized")
	}
	s.actorCtx.Send(s.pid, msg)
	return nil
}
