package dbtestdata

import (
	"clustron-backend/internal/membership"
	"github.com/google/uuid"
	"testing"
)

func (b Builder) Membership() *MembershipBuilder {
	return &MembershipBuilder{t: b.t, db: b.pool}
}

type MembershipBuilder struct {
	t  *testing.T
	db DBTX
}

func NewMembershipBuilder(t *testing.T, db DBTX) *MembershipBuilder {
	return &MembershipBuilder{t: t, db: db}
}

func (b MembershipBuilder) Queries() *membership.Queries {
	return membership.New(b.db)
}

func (b MembershipBuilder) Create(groupID, userID, roleID uuid.UUID) (membership.Membership, error) {
	params := membership.CreateOrUpdateParams{
		GroupID: groupID,
		UserID:  userID,
		RoleID:  roleID,
	}

	result, err := b.Queries().CreateOrUpdate(b.t.Context(), params)
	if err != nil {
		return membership.Membership{}, err
	}

	return result, nil
}
