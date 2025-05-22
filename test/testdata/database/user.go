package dbtestdata

import (
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/test/testutil"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
	"testing"
)

type UserFactoryParams struct {
	FullName   string
	Email      string
	Role       string
	Department string
	StudentID  string
}

type UserOption func(*UserFactoryParams)

func WithEmail(email string) UserOption {
	return func(p *UserFactoryParams) {
		p.Email = email
	}
}

func WithRole(role string) UserOption {
	return func(p *UserFactoryParams) {
		p.Role = role
	}
}

func WithDepartment(dept string) UserOption {
	return func(p *UserFactoryParams) {
		p.Department = dept
	}
}

func WithStudentID(sid string) UserOption {
	return func(p *UserFactoryParams) {
		p.StudentID = sid
	}
}

func WithFullName(fullName string) UserOption {
	return func(p *UserFactoryParams) {
		p.FullName = fullName
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

func (b UserBuilder) GetUserQueries() *user.Queries {
	return user.New(b.db)
}

func (b UserBuilder) CreateUser(opts ...UserOption) user.User {
	queries := user.New(b.db)
	settingQueries := setting.New(b.db)

	p := &UserFactoryParams{}
	for _, opt := range opts {
		opt(p)
	}

	if p.Email == "" {
		p.Email = testutil.RandomEmail()
	}

	if p.StudentID == "" {
		p.StudentID = fmt.Sprintf("sid-%s", uuid.New().String()[:8])
	}

	if p.Role == "" {
		p.Role = "user"
	}

	userRow, err := queries.Create(context.Background(), user.CreateParams{
		Email:     p.Email,
		StudentID: pgtype.Text{String: p.StudentID, Valid: true},
	})
	require.NoError(b.t, err)

	userRow, err = queries.UpdateRoleAndDepartment(context.Background(), user.UpdateRoleAndDepartmentParams{
		ID:         userRow.ID,
		Role:       pgtype.Text{String: p.Role, Valid: true},
		Department: pgtype.Text{String: p.Department, Valid: true},
	})
	require.NoError(b.t, err)

	if p.FullName != "" {
		_, err = settingQueries.CreateSetting(context.Background(), setting.CreateSettingParams{
			UserID:   userRow.ID,
			Username: pgtype.Text{String: p.FullName, Valid: true},
		})
		require.NoError(b.t, err)
	}

	return userRow
}
