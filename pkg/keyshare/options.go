package keyshare

import (
	"fmt"

	"github.com/sonrhq/sonr/crypto/core/curves"

	"github.com/sonrhq/identity/pkg/mpc"
)

// ! ||--------------------------------------------------------------------------------||
// ! ||                              Configuration Options                             ||
// ! ||--------------------------------------------------------------------------------||

// Option is a function that applies an option to the controller.
type Option func(*Options) *Options

// WithJWT sets the jwt for the controller.
func (o *Options) WithJWT(jwt string) *Options {
	if jwt != "" {
		o.jwt = jwt
		o.isExisting = true
	} else {
		fmt.Println("jwt is empty")
	}
	return o
}

// WithCurve sets the curve for the controller.
func (o *Options) WithCurve(curve *curves.Curve) *Options {
	o.curve = curve
	return o
}

// ! ||--------------------------------------------------------------------------------||
// ! ||                               Generation Methods                               ||
// ! ||--------------------------------------------------------------------------------||

// Options is the options for the controller.
type Options struct {
	isExisting bool
	jwt        string
	curve      *curves.Curve
	coinType   string
}

// DefaultOptions returns the default options for the controller.
func DefaultOptions() *Options {
	return &Options{
		isExisting: false,
		jwt:        "",
		curve:      mpc.K_DEFAULT_MPC_CURVE,
		coinType:   "BTC",
	}
}
