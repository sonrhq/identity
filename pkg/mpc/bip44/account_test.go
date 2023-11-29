package bip44_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/sonrhq/sonr/common/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/sonrhq/identity/pkg/mpc/bip44"
)

func TestNewAccountV1(t *testing.T) {
    // Initialize
	var (
		coins      = crypto.AllCoinTypes()
		namePrefix = "test"
	)

	// Call the function
	for i, coin := range coins {
		name := fmt.Sprintf("%s-%s-%d", namePrefix, coin, i)
		log.Printf("Creating: %v", name)
		account, err := bip44.NewAccountV1(name, coin)
		assert.NoError(t, err, "Error should be nil")
		assert.NotNil(t, account, "Account should not be nil")
	}
	// Add assertions to check the returned account and ksset
}
