package controller_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sonrhq/identity/pkg/controller"
)

func TestNew(t *testing.T) {
  c, err := controller.New(context.Background())
  assert.Nil(t, err)
  assert.NotNil(t, c)
}
