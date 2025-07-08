package membership

import (
	"clustron-backend/internal/grouprole"

	"github.com/google/uuid"
)

type MemberResponse struct {
	ID        uuid.UUID      `json:"id"`
	Username  string         `json:"username"`
	Email     string         `json:"email"`
	StudentID string         `json:"studentId"`
	Role      grouprole.Role `json:"role"`
}

type PendingMemberResponse struct {
	ID             uuid.UUID      `json:"id"`
	UserIdentifier string         `json:"userIdentifier"`
	Role           grouprole.Role `json:"role"`
}

type JoinResult interface {
	JoinType() JoinMemberResponseType
}

type JoinMemberResponseType string

const (
	JoinMemberResponseTypeMember  JoinMemberResponseType = "member"
	JoinMemberResponseTypePending JoinMemberResponseType = "pending"
)

func (m MemberResponse) JoinType() JoinMemberResponseType {
	return JoinMemberResponseTypeMember
}

func (p PendingMemberResponse) JoinType() JoinMemberResponseType {
	return JoinMemberResponseTypePending
}
