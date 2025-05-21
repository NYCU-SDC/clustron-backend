package testdata

import (
	"clustron-backend/internal/user"
	"clustron-backend/test/testutil"
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

type UserFactoryParams struct {
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

func (db DBTestData) GetUserQueries() *user.Queries {
	return user.New(db.pool)
}

func (db *DBTestData) CreateUser(name string, opts ...UserOption) user.User {
	queries := user.New(db.pool)

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
	require.NoError(db.t, err)

	userRow, err = queries.UpdateRoleAndDepartment(context.Background(), user.UpdateRoleAndDepartmentParams{
		ID:         userRow.ID,
		Role:       pgtype.Text{String: p.Role, Valid: true},
		Department: pgtype.Text{String: p.Department, Valid: true},
	})

	return userRow
}
