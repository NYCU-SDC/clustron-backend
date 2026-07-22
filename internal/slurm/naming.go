package slurm

import "fmt"

// BaseAccountName is the Slurm account holding a group's regular members. It is
// the -base child of the group's top-level account in the account hierarchy.
func BaseAccountName(groupCN string) string {
	return fmt.Sprintf("%s-base", groupCN)
}

// AdminAccountName is the Slurm account holding a group's owners and admins. It
// is the -admin child of the group's top-level account and equals the group's
// LDAP admin CN.
func AdminAccountName(groupCN string) string {
	return fmt.Sprintf("%s-admin", groupCN)
}
