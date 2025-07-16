package membership

import (
	"clustron-backend/internal/grouprole"

	"github.com/google/uuid"
)

type MemberResponse struct {
	ID        uuid.UUID              `json:"id"`
	FullName  string                 `json:"fullName"`
	Email     string                 `json:"email"`
	StudentID string                 `json:"studentId"`
	Role      grouprole.RoleResponse `json:"role"`
}

type PendingMemberResponse struct {
	ID             uuid.UUID              `json:"id"`
	UserIdentifier string                 `json:"userIdentifier"`
	GroupID        uuid.UUID              `json:"groupId"`
	Role           grouprole.RoleResponse `json:"role"`
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

type JoinMemberErrorResponse struct {
	Member  string `json:"member"`
	Role    string `json:"role"`
	Message string `json:"message"`
}

type JoinMemberResponse struct {
	AddedSuccessNumber int64                     `json:"addedSuccessNumber"`
	AddedFailureNumber int64                     `json:"addedFailureNumber"`
	Errors             []JoinMemberErrorResponse `json:"errors"`
}
