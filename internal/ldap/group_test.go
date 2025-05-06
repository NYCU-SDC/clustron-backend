package ldap

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	groupName = "group1"
	gidNumber = "10000"
	user1     = "user_in_group1"
	user2     = "user_not_in_group1"
)

func TestClient_CreateGroup(t *testing.T) {
	tests := []struct {
		name      string
		groupName string
		gidNumber string
		members   []string
		error     error
	}{
		{
			name:      "Should create group successfully",
			groupName: groupName,
			gidNumber: gidNumber,
			members:   []string{user1},
			error:     nil,
		},
		{
			name:      "Should return ErrGroupNameExists when creating group with duplicate name",
			groupName: groupName,
			gidNumber: "99999",
			members:   nil,
			error:     ErrGroupNameExists,
		},
		{
			name:      "Should return ErrGidNumberInUse when creating group with duplicate gidNumber",
			groupName: "another_group",
			gidNumber: gidNumber,
			members:   nil,
			error:     ErrGidNumberInUse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")

			if tc.error != nil {
				setupGroup(t, client, groupName, gidNumber, []string{user1})
			}

			err := client.CreateGroup(tc.groupName, tc.gidNumber, tc.members)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_GetGroupInfo(t *testing.T) {
	tests := []struct {
		name      string
		groupName string
		error     error
	}{
		{
			name:      "Should return ErrGroupNotFound when group does not exist",
			groupName: "nonexistent",
			error:     ErrGroupNotFound,
		},
		{
			name:      "Should get group info successfully",
			groupName: groupName,
			error:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			//require.NoError(t, client.CreateUser(user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001"))
			//require.NoError(t, client.CreateGroup(groupName, gidNumber, []string{user1}))
			setupGroup(t, client, groupName, gidNumber, []string{user1})

			entry, err := client.GetGroupInfo(tc.groupName)
			if tc.error == nil {
				require.NoError(t, err)
				assert.Equal(t, groupName, entry.GetAttributeValue("cn"))
				assert.Contains(t, entry.GetAttributeValues("memberUid"), user1)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_DeleteGroup(t *testing.T) {
	tests := []struct {
		name      string
		groupName string
		error     error
	}{
		{
			name:      "Should delete group successfully",
			groupName: groupName,
			error:     nil,
		},
		{
			name:      "Should return error when deleting nonexistent group",
			groupName: "ghost_group",
			error:     ErrGroupNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			setupGroup(t, client, groupName, gidNumber, []string{user1})

			err := client.DeleteGroup(tc.groupName)
			if tc.error == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestClient_AddUserToGroup(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		error error
	}{
		{
			name:  "Should return ErrUserAlreadyInGroup when adding same user again",
			user:  user1,
			error: ErrUserAlreadyInGroup,
		},
		{
			name:  "Should add user to group successfully",
			user:  user2,
			error: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			setupUser(t, client, user2, "CN2", "SN2", "ssh-rsa AAAA2", "10002")
			setupGroup(t, client, groupName, gidNumber, []string{user1})

			err := client.AddUserToGroup(groupName, tc.user)
			if tc.error == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_RemoveUserFromGroup(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		error error
	}{
		{
			name:  "Should remove user from group successfully",
			user:  user1,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotInGroup when removing nonexistent user",
			user:  user2,
			error: ErrUserNotInGroup,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			setupUser(t, client, user2, "CN2", "SN2", "ssh-rsa AAAA2", "10002")
			setupGroup(t, client, groupName, gidNumber, []string{user1})

			err := client.RemoveUserFromGroup(groupName, tc.user)
			if tc.error == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_GetGroupsForUser(t *testing.T) {
	tests := []struct {
		name string
		uid  string
		err  error
	}{
		{
			name: "Should return ErrUserNotFound when user does not exist",
			uid:  "ghost_user",
			err:  ErrUserNotFound,
		},
		{
			name: "Should get groups for user successfully",
			uid:  user1,
			err:  nil,
		},
		{
			name: "Should return ErrUserNoGroup when user exists but is not in any group",
			uid:  user2,
			err:  ErrUserNoGroup,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			setupUser(t, client, user2, "CN2", "SN2", "ssh-rsa AAAA2", "10002")
			setupGroup(t, client, groupName, gidNumber, []string{user1})
			setupGroup(t, client, "group2", "10001", []string{user1})

			groups, err := client.GetGroupsForUser(tc.uid)
			if tc.err == nil {
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(groups), 1)
			} else {
				assert.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestClient_GetUsedGidNumbers(t *testing.T) {
	tests := []struct {
		name         string
		groups       []string
		expectedGIDs []string
	}{
		{
			name:         "Should return empty list when no groups exist",
			groups:       []string{},
			expectedGIDs: []string{},
		},
		{
			name:         "Should return gidNumber from single group",
			groups:       []string{"10000"},
			expectedGIDs: []string{"10000"},
		},
		{
			name:         "Should return multiple gidNumbers",
			groups:       []string{"10000", "10001"},
			expectedGIDs: []string{"10000", "10001"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			for _, gid := range tc.groups {
				require.NoError(t, client.CreateGroup(fmt.Sprintf("group_%s", gid), gid, []string{}))
			}

			gids, err := client.GetUsedGidNumbers()
			require.NoError(t, err)

			for _, gid := range tc.expectedGIDs {
				assert.Contains(t, gids, gid)
			}
		})
	}
}
