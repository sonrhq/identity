package dkls_test

import (
	"testing"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/sonrhq/identity/pkg/mpc/dkls"
)

func TestMPCKeygenFullSuite(t *testing.T) {
	msg := []byte("hello world")
	kss, err := dkls.DKLSKeygen()
	if err != nil {
		t.Fatalf("error generating keyshares: %v", err)
	}
	sig, err := kss.Sign(msg)
	if err != nil {
		t.Fatalf("error signing: %v", err)
	}
	ok, err := kss.Verify(msg, sig)
	if err != nil {
		t.Fatalf("error verifying: %v", err)
	}
	assert.True(t, ok)
	newKss, err := dkls.DKLSRefresh(kss)
	if err != nil {
		t.Fatalf("error refreshing keyshares: %v", err)
	}
	newSig, err := newKss.Sign(msg)
	if err != nil {
		t.Fatalf("error signing: %v", err)
	}
	ok, err = newKss.Verify(msg, newSig)
	if err != nil {
		t.Fatalf("error verifying: %v", err)
	}
	assert.True(t, ok)
}

func TestControllerKeyshareFullSuite(t *testing.T) {
	msg := []byte("hello world")
	for i, coinType := range crypto.AllCoinTypes() {
		t.Logf("%d) %s", i, coinType.Name())
		kss, err := dkls.DKLSKeygen()
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("\t [ %s ]", kss.FormatDID(coinType))
		t.Logf("\t --> msg: %s", msg)

		sig, err := kss.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("\t --> signature: %s", crypto.Base64Encode(sig))
		t.Logf("\n")
	}
}
