package bls_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sonrhq/identity/pkg/bls"
)

func TestNewKeys(t *testing.T) {
	seed := bls.RandomSeed()
	sk, err := bls.NewSecretKey(seed)
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
	seed := bls.RandomSeed()
	sk, err := bls.NewSecretKey(seed)
	require.NoError(t, err)
	pk, err := sk.PublicKey()
	require.NoError(t, err)
	acc, err := sk.CreateAccumulator()
	require.NoError(t, err)
	err = acc.AddValues(sk, "1", "2", "3", "4", "5", "6", "7", "8", "9")
	require.NoError(t, err)
	mw, err := acc.CreateWitness(sk, "3")
	require.NoError(t, err)
	ok := acc.VerifyElement(pk, mw)
	require.True(t, ok)
	bz, err := acc.Serialize()
	require.NoError(t, err)
    fmt.Printf("(acc): %s\n", bz)
	acc2, err := sk.OpenAccumulator(bz)
	require.NoError(t, err)
	mw2, err := acc2.CreateWitness(sk, "3")
    fmt.Printf("(mw2): %v\n", mw2)
	require.NoError(t, err)
	ok2 := acc2.VerifyElement(pk, mw)
	require.True(t, ok2)
}

func TestCorrectDeterministicWitness(t *testing.T) {
	seed := []byte("seed")
	sk, err := bls.NewSecretKey(seed)
	require.NoError(t, err)
	acc, err := sk.CreateAccumulator()
	require.NoError(t, err)
	err = acc.AddValues(sk, "1", "2", "3", "4", "5", "6", "7")
	require.NoError(t, err)
	mw, err := acc.CreateWitness(sk, "3")
	require.NoError(t, err)
	accbz, err := acc.Serialize()
	require.NoError(t, err)
	sk2, err := bls.NewSecretKey(seed)
	require.NoError(t, err)
	pk, err := sk2.PublicKey()
	require.NoError(t, err)
	acc2, err := sk2.OpenAccumulator(accbz)
	require.NoError(t, err)
	ok := acc2.VerifyElement(pk, mw)
	require.True(t, ok)
}


func TestIncorrectDeterministicWitness(t *testing.T) {
	seed := []byte("seed")
	sk, err := bls.NewSecretKey(seed)
	require.NoError(t, err)
	acc, err := sk.CreateAccumulator()
	require.NoError(t, err)
	err = acc.AddValues(sk, "1", "2", "3", "4", "5", "6", "7")
	require.NoError(t, err)
	mw, err := acc.CreateWitness(sk, "3")
	require.NoError(t, err)
	accbz, err := acc.Serialize()
	require.NoError(t, err)
	sk2, err := bls.NewSecretKey([]byte("wrong seed"))
	require.NoError(t, err)
	pk, err := sk2.PublicKey()
	require.NoError(t, err)
	acc2, err := sk2.OpenAccumulator(accbz)
	require.NoError(t, err)
	ok := acc2.VerifyElement(pk, mw)
	require.False(t, ok)
}
