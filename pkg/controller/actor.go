package controller

import (
	"context"
	"fmt"
	"log"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/crypto/core/curves"
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
}

// New creates a new controller actor.
func New(ctx context.Context, options ...Option) (Controller, error) {
	opts := DefaultOptions()
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
	case *actor.Started:
		msg.SystemMessage()
		fmt.Println("Starting, initialize actor here")
	case *actor.Stopping:
		fmt.Println("Stopping, actor is about shut down")
	case *actor.Stopped:
		fmt.Println("Stopped, actor and its children are stopped")
    case InitRequest:
        s.InitSequence(&msg)
    case SignRequest:
        s.SignSequence(&msg)
    case VerifyRequest:
        s.VerifySequence(&msg)
	}
}

// Handle resolves failures with child processes.
func (s *controller) Handle(reason interface{}) actor.Directive {
	log.Printf("handling failure for child. reason:%v", reason)
	return actor.RestartDirective
}
