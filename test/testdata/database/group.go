package dbtestdata

import (
	"clustron-backend/internal/group"
	"clustron-backend/test/testutil"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
	"testing"
)

// GroupFactoryParams defines the parameters for creating a group.
type GroupFactoryParams struct {
	ID          uuid.UUID
	Title       string
	Description string
}

// GroupOption defines a function type for modifying GroupFactoryParams.
type GroupOption func(*GroupFactoryParams)

// GroupWithID sets the ID for the group.
func GroupWithID(id uuid.UUID) GroupOption {
	return func(p *GroupFactoryParams) {
		p.ID = id
	}
}

// GroupWithTitle sets the title for the group.
func GroupWithTitle(title string) GroupOption {
	return func(p *GroupFactoryParams) {
		p.Title = title
	}
}

// GroupWithDescription sets the description for the group.
func GroupWithDescription(description string) GroupOption {
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

func (b GroupBuilder) Create(opts ...GroupOption) *group.Group {
	params := GroupFactoryParams{
		ID:          uuid.New(),
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
