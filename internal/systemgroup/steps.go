package systemgroup

import (
	"context"
	"errors"
	"strconv"

	"clustron-backend/internal"
	"clustron-backend/internal/ldap"
)

// CreateLDAPGroupStep creates the same-name, same-gid LDAP posixGroup.
func CreateLDAPGroupStep(client LDAPClient, name string, gid int64) internal.SagaStep {
	return internal.SagaStep{
		Name: "CreateLDAPSystemGroup",
		Action: func(ctx context.Context) error {
			return client.CreateGroup(name, strconv.FormatInt(gid, 10), []string{})
		},
		Compensate: func(ctx context.Context) error {
			return client.DeleteGroup(name)
		},
	}
}

// AddLDAPMemberStep adds uid to the group. An existing membership counts as done
// and is not undone on compensation, since this step did not create it.
func AddLDAPMemberStep(client LDAPClient, groupName, uid string) internal.SagaStep {
	var added bool
	return internal.SagaStep{
		Name: "AddUserToLDAPSystemGroup",
		Action: func(ctx context.Context) error {
			err := client.AddUserToGroup(groupName, uid)
			if errors.Is(err, ldap.ErrUserAlreadyInGroup) {
				return nil
			}
			if err != nil {
				return err
			}
			added = true
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if !added {
				return nil
			}
			err := client.RemoveUserFromGroup(groupName, uid)
			if errors.Is(err, ldap.ErrUserNotInGroup) {
				return nil
			}
			return err
		},
	}
}

// RemoveLDAPMemberStep removes uid from the group. A missing membership counts as
// done and is not re-added on compensation.
func RemoveLDAPMemberStep(client LDAPClient, groupName, uid string) internal.SagaStep {
	var removed bool
	return internal.SagaStep{
		Name: "RemoveUserFromLDAPSystemGroup",
		Action: func(ctx context.Context) error {
			err := client.RemoveUserFromGroup(groupName, uid)
			if errors.Is(err, ldap.ErrUserNotInGroup) {
				return nil
			}
			if err != nil {
				return err
			}
			removed = true
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if !removed {
				return nil
			}
			err := client.AddUserToGroup(groupName, uid)
			if errors.Is(err, ldap.ErrUserAlreadyInGroup) {
				return nil
			}
			return err
		},
	}
}
