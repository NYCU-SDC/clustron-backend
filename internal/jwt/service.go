package jwt

import (
	"errors"
)

type ContextKey string

const UserContextKey ContextKey = "user"

var (
	ErrInternalServer = errors.New("internal server error")
)
