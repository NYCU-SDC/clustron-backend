package grouprole

import "github.com/google/uuid"

type DefaultRole string

type AccessLevel string

const (
	RoleOwner   DefaultRole = "e02311a8-5a17-444a-b5bb-5c04afa8fa88" // Access Level: GROUP_OWNER
	RoleTA      DefaultRole = "524db082-9d0d-4515-b70c-af3766414bd7" // Access Level: GROUP_ADMIN
	RoleStudent DefaultRole = "de2ed988-a34f-40d3-af70-7e54fa266b37" // Access Level: USER
	RoleAuditor DefaultRole = "c5e8a9c9-0b71-434a-ae61-b66983736217" // Access Level: USER
)

const (
	AccessLevelOwner AccessLevel = "GROUP_OWNER"
	AccessLevelAdmin AccessLevel = "GROUP_ADMIN"
	AccessLevelUser  AccessLevel = "USER"
)

var AccessLevelRank = map[string]int{
	"GROUP_OWNER": 3,
	"GROUP_ADMIN": 2,
	"USER":        1,
}

var DefaultRoleToAccessLevel = map[DefaultRole]AccessLevel{
	RoleOwner:   AccessLevelOwner,
	RoleTA:      AccessLevelAdmin,
	RoleStudent: AccessLevelUser,
	RoleAuditor: AccessLevelUser,
}

type UserScope struct {
	Group
	Me struct {
		Type string // will be "membership" or "adminOverride"
		Role Role
	}
}

type Role struct {
	ID          uuid.UUID
	Role        string
	AccessLevel string
}

type RoleResponse struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	AccessLevel string `json:"accessLevel"`
}

func (r Role) ToResponse() RoleResponse {
	return RoleResponse{
		ID:          r.ID.String(),
		Role:        r.Role,
		AccessLevel: r.AccessLevel,
	}
}
