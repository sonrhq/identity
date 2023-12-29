package keychain

import (
	"fmt"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/pkg/did/coins"

	modulev1 "github.com/sonrhq/identity/api/module/v1"
	"github.com/sonrhq/identity/pkg/mpc"
	"github.com/sonrhq/identity/pkg/mpc/share"
)

type KeyChain interface {
	actor.Actor
	Actor() actor.Actor
	Address() (string, error)
	Fingerprint(actorCtx *actor.RootContext) ([]byte, error)
}

// keychain is an actor that is responsible for one of the two parts of a dkls protocol.
type keychain struct {
	DID      string
	Name     string
	CoinType modulev1.CoinType

	pid      *actor.PID

	rootPriv share.Share
	rootPub  share.Share
}

// New returns the keychain.
func New() KeyChain {
	kc := &keychain{
		rootPriv: share.NewPrivateShare(mpc.K_DEFAULT_MPC_CURVE),
		rootPub: share.NewPublicShare(mpc.K_DEFAULT_MPC_CURVE),
	}
	return kc
}

// Actor returns the actor.
func (s *keychain) Actor() actor.Actor {
	return s
}

// Receive handles the message from the keyshare.
func (s *keychain) Receive(context actor.Context) {
	switch msg := context.Message().(type) {
	case *actor.Started:
		s.pid = context.Self()
		fmt.Println("Spawned Keychain: ", s.pid.Id)
	case *actor.Stopping:
		fmt.Println("Stopping, actor is about shut down")
	case *actor.Stopped:
		fmt.Println("Stopped, actor and its children are stopped")
	case GenerateRequest:
		s.GenerateSequence(msg)
	case SignRequest:
		s.SignSequence(msg)
	case VerifyRequest:
		s.VerifySequence(msg)
	}
}

// Send sends a message to the controller.
func (s *keychain) Send(ctx *actor.RootContext, msg interface{}) error {
	if s.pid == nil {
		return fmt.Errorf("keychain actor not initialized")
	}
	ctx.Send(s.pid, msg)
	return nil
}

func (s *keychain) Address() (string, error) {
	pubHex, err := s.rootPriv.PubKeyHex()
	if err != nil {
		return "", err
	}
	return coins.NewSonrAddress(pubHex)
}

func (s *keychain) Fingerprint(ctx *actor.RootContext) ([]byte, error) {
	pubHex, err := s.rootPriv.PubKeyHex()
	if err != nil {
		return nil, err
	}
	addr, err := coins.NewSonrAddress(pubHex)
	if err != nil {
		return nil, err
	}
	respCh := make(chan *SignResponse)
	signMsgReq := SignRequest{
		Message:         []byte(addr),
		ResponseChannel: respCh,
	}
	s.Send(ctx, signMsgReq)
	resp := <-respCh
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Signature, nil
}
