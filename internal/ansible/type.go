package ansible

import "github.com/google/uuid"

// AllowedLoginGroupDetail is a Clustron group whose members are allowed to log in to compute
// nodes. It maps to one entry in SSSD's simple_allow_groups (via the group's BASE ldap_cn).
type AllowedLoginGroupDetail struct {
	GroupID uuid.UUID
	Title   string
	LdapCN  string
}
