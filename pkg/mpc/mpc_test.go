package mpc_test

import (
	"strings"
	"testing"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/sonrhq/identity/pkg/mpc/bip44"
)

func TestNewAccountV1(t *testing.T) {
	account, token, err := bip44.NewAccountV1("primary", crypto.SONRCoinType)
	if err != nil {
		t.Fatal(err)
	}

	createdAccounts := []string{
		"did:invalid:0x1234567890123456789012345678901234567890",
	}

	msg := "Hello World 2"
	for _, did := range createdAccounts {
		if strings.Contains(did, "invalid") {
			continue
		}
		msgSig, err := account.Sign(token.Bob(), []byte(msg))
		assert.NoError(t, err)
		ok, err := account.Verify([]byte(msg), msgSig)
		assert.NoError(t, err)
		assert.True(t, ok)
		t.Logf("(SIGN-VERIFY) - %s = Msg: %s, Verified: %v", did, msg, ok)
	}
}
