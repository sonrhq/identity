package bls_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/sonrhq/identity/pkg/mpc/keys/bls"
)

func TestNewKeys(t *testing.T) {
	sk, err := bls.NewSecretKey()
	require.NoError(t, err)
	pk, err := sk.PublicKey()
	require.NoError(t, err)
	skbz, err := sk.Serialize()
	require.NoError(t, err)
	sk2, err := bls.OpenSecretKey(skbz)
	require.NoError(t, err)
	pk2, err := sk2.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, pk2)
	pk1bz, err := pk.MarshalBinary()
    require.NoError(t, err)
    pk2bz, err := pk2.MarshalBinary()
    require.NoError(t, err)
    require.Equal(t, pk1bz, pk2bz)
    require.NoError(t, err)
}

func TestWitnessElements(t *testing.T) {
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
    fmt.Printf("(acc-hex-bz): %s | length=%v\n", hex.EncodeToString(bz), len(bz))
	acc2, err := sk.OpenAccumulator(bz)
	require.NoError(t, err)
	mw2, err := acc2.CreateWitness(sk, "3")
    fmt.Printf("(mw2-b58): %v\n | length=%v\n", base58.Encode(mw2), len(base58.Encode(mw2)))
	require.NoError(t, err)
	ok, err = acc2.VerifyElement(pk, mw2)
	require.NoError(t, err)
	require.True(t, ok)
}
