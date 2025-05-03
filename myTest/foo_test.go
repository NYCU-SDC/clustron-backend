package myTest

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFoo(t *testing.T) {
	assert.Equal(t, 3, 1+1, "1+1 should be 3")
}
