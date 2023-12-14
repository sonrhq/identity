package bls_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sonrhq/identity/pkg/mpc/keys/bls"
)

func TestBLS(t *testing.T) {
	sk, err := bls.NewSecretKey()
    require.NoError(t, err)
    pk, err := sk.PublicKey()
    require.NoError(t, err)
    acc, err := sk.CreateAccumulator()
    require.NoError(t, err)
    err = acc.AddValues(sk, "1", "2", "3", "4", "5", "6", "7", "8", "9")
    require.NoError(t, err)
    mw, err := acc.CreateWitness(sk, "3")
    require.NoError(t, err)
    ok, err := acc.VerifyElement(pk, mw)
    require.NoError(t, err)
    require.True(t, ok)
    bz, err := acc.Serialize()
    require.NoError(t, err)
    acc2, err := sk.OpenAccumulator(bz)
    require.NoError(t, err)
    mw2, err := acc2.CreateWitness(sk, "3")
    require.NoError(t, err)
    ok, err = acc2.VerifyElement(pk, mw2)
    require.NoError(t, err)
    require.True(t, ok)
}
