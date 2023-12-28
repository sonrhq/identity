package session

import (
	"fmt"

	"github.com/asynkron/protoactor-go/actor"
)

type Session interface {
    actor.Actor
}

// session is a proto actor which manages an user session with a Sonr enabled service.
type session struct {
    // Origin is the origin url referenced on chain for this session.
    Origin string

    // Address is the address of the user.
    Address string

    // Handle is the handle of the user on the service.
    Handle string

    // Expiry is the expiry of the session.
    Expiry int64
}

// NewSession creates a new session actor.
func NewSession(origin string, address string, handle string, expiry int64) Session {
    return &session{
        Origin: origin,
        Address: address,
        Handle: handle,
        Expiry: expiry,
    }
}

// Receive handles the message from the session.
func (s *session) Receive(context actor.Context) {
    switch msg := context.Message().(type) {
    case *actor.Started:
        msg.SystemMessage()
        fmt.Println("Starting, initialize actor here")
    case *actor.Stopping:
        fmt.Println("Stopping, actor is about shut down")
    case *actor.Stopped:
        fmt.Println("Stopped, actor and its children are stopped")
    }
}
