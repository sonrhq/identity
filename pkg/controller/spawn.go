package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/asynkron/protoactor-go/actor"
	"github.com/sonrhq/sonr/crypto/core/curves"

	"github.com/sonrhq/identity/pkg/mpc"
)

// ! ||--------------------------------------------------------------------------------||
// ! ||                              Configuration SpawnOptions                             ||
// ! ||--------------------------------------------------------------------------------||
// SpawnOptions is the options for the controller.
type SpawnOptions struct {
	isExisting bool
	jwt        string
	origin     string
	curve      *curves.Curve

	MaxRetries     int
	WithinDuration time.Duration
	SpawnPrefix    string
	EnableSpawn    bool
}

// DefaultSpawnOptions returns the default options for the controller.
func DefaultSpawnOptions() *SpawnOptions {
	return &SpawnOptions{
		isExisting:     false,
		jwt:            "",
		origin:         "localhost",
		curve:          mpc.K_DEFAULT_MPC_CURVE,
		MaxRetries:     10,
		WithinDuration: 5 * time.Second,
		SpawnPrefix:    "identity-controller",
		EnableSpawn:    true,
	}
}

// Option is a function that applies an option to the controller.
type Option func(*SpawnOptions) *SpawnOptions

// WithJWT sets the jwt for the controller.
func (o *SpawnOptions) WithJWT(jwt string) *SpawnOptions {
	if jwt != "" {
		o.jwt = jwt
		o.isExisting = true
	} else {
		fmt.Println("jwt is empty")
	}
	return o
}

// WithCurve sets the curve for the controller.
func (o *SpawnOptions) WithCurve(curve *curves.Curve) *SpawnOptions {
	o.curve = curve
	return o
}

// WithOrigin sets the origin for the controller.
func (o *SpawnOptions) WithOrigin(origin string) *SpawnOptions {
	o.origin = origin
	return o
}

// WithTimeout sets the timeout for the controller.
func (o *SpawnOptions) WithTimeout(timeout time.Duration) *SpawnOptions {
	o.WithinDuration = timeout
	return o
}

// WithMaxRetries sets the max retries for the controller.
func (o *SpawnOptions) WithMaxRetries(maxRetries int) *SpawnOptions {
	o.MaxRetries = maxRetries
	return o
}

// WithSpawnPrefix sets the spawn prefix for the controller.
func (o *SpawnOptions) WithSpawnPrefix(prefix string) *SpawnOptions {
	o.SpawnPrefix = prefix
	return o
}

// WithDisabledSpawn disables the spawning of the controller.
func (o *SpawnOptions) WithDisabledSpawn() *SpawnOptions {
	o.EnableSpawn = false
	return o
}

// ! ||--------------------------------------------------------------------------------||
// ! ||                               Generation Methods                               ||
// ! ||--------------------------------------------------------------------------------||


// Apply applies the options and returns a Controller
func (o *SpawnOptions) Apply(ctx context.Context, opts ...Option) (*controller, error) {
	for _, opt := range opts {
		o = opt(o)
	}
	c := &controller{
		curve: o.curve,
		jwt:   o.jwt,
		ctx:   ctx,
	}
	err := o.Spawn(c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Spawn spawns the controller.
func (o *SpawnOptions) Spawn(c *controller) error {
	if c == nil {
		return fmt.Errorf("controller is nil")
	}

	// Spawn the controller.
	if o.EnableSpawn {
		// Configure parent supervisor.
		supervisor := actor.NewOneForOneStrategy(o.MaxRetries, o.WithinDuration, c.Handle)
		ctx := actor.NewActorSystem().Root

		// Create the actor.
		spawnFunc := func() actor.Actor { return c }
		props := actor.PropsFromProducer(spawnFunc).Configure(actor.WithSupervisor(supervisor))
		c.pid = ctx.SpawnPrefix(props, o.SpawnPrefix)

		// Set Properties
		c.actorCtx = ctx
		fmt.Println("Spawned Actor: ", c.pid.Id)
	}
	return nil
}
