package dbtestdata

import (
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"clustron-backend/test/testutil"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
	"testing"
)

type UserFactoryParams struct {
	ID         uuid.UUID
	FullName   string
	Email      string
	Role       role.GlobalRole
	Department string
	StudentID  string
}

type UserOption func(*UserFactoryParams)

func UserWithID(id uuid.UUID) UserOption {
	return func(p *UserFactoryParams) {
		p.ID = id
	}
}

func UserWithEmail(email string) UserOption {
	return func(p *UserFactoryParams) {
		p.Email = email
	}
}

func UserWithStudentID(sid string) UserOption {
	return func(p *UserFactoryParams) {
		p.StudentID = sid
	}
}

func UserWithFullName(fullName string) UserOption {
	return func(p *UserFactoryParams) {
		p.FullName = fullName
	}
}

func UserWithRole(role role.GlobalRole) UserOption {
	return func(p *UserFactoryParams) {
		p.Role = role
	}
}

func (b Builder) User() *UserBuilder {
	return &UserBuilder{t: b.t, db: b.pool}
}

type UserBuilder struct {
	t  *testing.T
	db DBTX
}

func NewUserBuilder(t *testing.T, db DBTX) *UserBuilder {
	return &UserBuilder{t: t, db: db}
}

func (b UserBuilder) Queries() *user.Queries {
	return user.New(b.db)
}

func (b UserBuilder) Create(opts ...UserOption) user.User {
	queries := user.New(b.db)
	settingQueries := setting.New(b.db)

	p := &UserFactoryParams{
		ID:        uuid.New(),
		FullName:  testutil.RandomName(),
		Email:     testutil.RandomEmail(),
		Role:      role.User,
		StudentID: fmt.Sprintf("sid-%s", uuid.New().String()[:8]),
	}
	for _, opt := range opts {
		opt(p)
	}

	userRow, err := queries.CreateWithID(context.Background(), user.CreateWithIDParams{
		ID:        p.ID,
		Email:     p.Email,
		StudentID: pgtype.Text{String: p.StudentID, Valid: true},
		Role:      p.Role.String(),
	})
	require.NoError(b.t, err)

	_, err = settingQueries.CreateSetting(context.Background(), setting.CreateSettingParams{
		UserID:   userRow.ID,
		FullName: pgtype.Text{String: p.FullName, Valid: true},
	})
	require.NoError(b.t, err)

	return userRow
}
