package mpc

import "github.com/sonrhq/sonr/crypto/core/curves"

// K_DEFAULT_MPC_CURVE is the default curve for the controller.
var K_DEFAULT_MPC_CURVE = curves.K256()

// K_DEFAULT_ZK_CURVE is the default curve for the zk.
var K_DEFAULT_ZK_CURVE = curves.BLS12381(&curves.PointBls12381G1{})
