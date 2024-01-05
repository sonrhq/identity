package controller

import (
	"fmt"

	"github.com/asynkron/protoactor-go/actor"

	"github.com/sonrhq/identity/pkg/keychain"
)

func (c *controller) GenerateSequence(context actor.Context, req keychain.GenerateRequest) {
	fmt.Println("Spawned Actor: ", c.pid.Id)
    kc := keychain.New()
    props := actor.PropsFromProducer(kc.Actor)
    child := context.Spawn(props)
    context.Send(child, req)
}

func (c *controller) SignSequence(context actor.Context, req SignRequest) {
	fmt.Println("Spawned Actor: ", c.pid.Id)
    kc := keychain.New()
    props := actor.PropsFromProducer(kc.Actor)
    child := context.Spawn(props)
    context.Send(child, req)
}

func (c *controller) VerifySequence(context actor.Context, req VerifyRequest) {
	fmt.Println("Spawned Actor: ", c.pid.Id)
    kc := keychain.New()
    props := actor.PropsFromProducer(kc.Actor)
    child := context.Spawn(props)
    context.Send(child, req)
}
