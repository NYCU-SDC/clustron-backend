package jwt

import (
	"context"
	"errors"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"user"`
	Role     string `json:"role"`
}

type ContextKey string

const UserContextKey ContextKey = "user"

var (
	ErrInternalServer = errors.New("internal server error")
)

func GetUserFromContext(ctx context.Context) (User, error) {
	user, ok := ctx.Value(UserContextKey).(User)
	if !ok {
		return User{}, ErrInternalServer
	}
	return user, nil
}
