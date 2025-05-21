package testutil

import (
	"fmt"
	"github.com/google/uuid"
)

func RandomEmail() string {
	return fmt.Sprintf("test-%s@example.com", uuid.NewString()[:8])
}
