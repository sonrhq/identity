package network_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sonrhq/identity/pkg/mpc/network"
)

func TestNewNetwork(t *testing.T) {
    mpcNet := network.NewNetwork()
    assert.NotNil(t, mpcNet)
    err := mpcNet.Generate()
    assert.Nil(t, err)
    msg := []byte("hello world")
    sig, err := mpcNet.Sign(msg)
    assert.Nil(t, err)
    fmt.Println(sig)
}
// idx1n5rrywm7zyg8v4tcq5hpxxtu25pdfp658wgdx4
// idx1hp725m360fesh9gaepghmmm2q8vygzce7qkkrz
