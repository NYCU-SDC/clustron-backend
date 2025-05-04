package jwt

import (
	"context"
	"github.com/NYCU-SDC/clustron-backend/internal"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type User struct {
	ID         uuid.UUID
	Username   string
	Email      string
	Role       pgtype.Text
	Department pgtype.Text
	StudentID  pgtype.Text
	CreatedAt  pgtype.Timestamptz
	UpdatedAt  pgtype.Timestamptz
}

func GetUserFromContext(ctx context.Context) (User, error) {
	user, ok := ctx.Value(internal.UserContextKey).(User)
	if !ok {
		return User{}, handlerutil.ErrInternalServer
	}
	return user, nil
}
