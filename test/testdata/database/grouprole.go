package dbtestdata

import (
	"clustron-backend/internal/grouprole"
	"testing"
)

func (b Builder) GroupRole() *GroupRoleBuilder {
	return &GroupRoleBuilder{t: b.t, db: b.pool}
}

type GroupRoleBuilder struct {
	t  *testing.T
	db DBTX
}

func NewGroupRoleBuilder(t *testing.T, db DBTX) *GroupRoleBuilder {
	return &GroupRoleBuilder{t: t, db: db}
}

func (b GroupRoleBuilder) Queries() *grouprole.Queries {
	return grouprole.New(b.db)
}

func (b GroupRoleBuilder) Create(roleName, accessLevel string) (grouprole.GroupRole, error) {
	params := grouprole.CreateParams{
		RoleName:    roleName,
		AccessLevel: accessLevel,
	}

	result, err := b.Queries().Create(b.t.Context(), params)
	if err != nil {
		b.t.Fatalf("failed to create group role: %v", err)
	}

	return result, nil
}
