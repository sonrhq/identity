package bls_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sonrhq/identity/pkg/mpc/keys/bls"
)

func TestBLS(t *testing.T) {
	sk, err := bls.NewSecretKey()
    require.NoError(t, err)
    acc, err := sk.CreateAccumulator()
    require.NoError(t, err)
    err = acc.AddValues(sk, "1", "2", "3", "4", "5", "6", "7", "8", "9")
    require.NoError(t, err)
    mw, err := acc.CreateWitness(sk, "3")
    require.NoError(t, err)
    ok, err := acc.VerifyElement(sk, mw)
    require.NoError(t, err)
    require.True(t, ok)
}
