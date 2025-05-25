package dbtestdata

import (
	"clustron-backend/internal/group"
	"clustron-backend/test/testutil"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
	"testing"
)

// GroupFactoryParams defines the parameters for creating a group.
type GroupFactoryParams struct {
	Title       string
	Description string
}

// GroupOption defines a function type for modifying GroupFactoryParams.
type GroupOption func(*GroupFactoryParams)

// WithTitle sets the title for the group.
func WithTitle(title string) GroupOption {
	return func(p *GroupFactoryParams) {
		p.Title = title
	}
}

// WithDescription sets the description for the group.
func WithDescription(description string) GroupOption {
	return func(p *GroupFactoryParams) {
		p.Description = description
	}
}

func (b Builder) Group() *GroupBuilder {
	return &GroupBuilder{t: b.t, db: b.pool}
}

type GroupBuilder struct {
	t  *testing.T
	db DBTX
}

func NewGroupBuilder(t *testing.T, db DBTX) *GroupBuilder {
	return &GroupBuilder{t: t, db: db}
}

func (b GroupBuilder) GetGroupQueries() *group.Queries {
	return group.New(b.db)
}

// Create creates a new group with the specified options.
func (b GroupBuilder) Create(opts ...GroupOption) *group.Group {
	params := GroupFactoryParams{
		Title:       testutil.RandomName(),
		Description: testutil.RandomDescription(),
	}

	for _, opt := range opts {
		opt(&params)
	}

	q := b.GetGroupQueries()
	result, err := q.Create(b.t.Context(), group.CreateParams{
		Title:       params.Title,
		Description: pgtype.Text{String: params.Description, Valid: true},
	})
	require.NoError(b.t, err, "failed to create group with params: %+v", params)

	return &result
}
