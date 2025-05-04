package ldap

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGroupFlow(t *testing.T) {
	type testCase struct {
		name    string
		execute func(t *testing.T)
	}

	const (
		groupName = "test_group"
		gidNumber = "20001"
		user1     = "test_user1"
		user2     = "test_user2"
	)

	require.NoError(t, client.CreateUser(user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001"))
	require.NoError(t, client.CreateUser(user2, "CN2", "SN2", "ssh-rsa AAAA2", "10002"))

	tests := []testCase{
		{
			name: "Should create group successfully",
			execute: func(t *testing.T) {
				err := client.CreateGroup(groupName, gidNumber, []string{user1})
				require.NoError(t, err)
			},
		},
		{
			name: "Should return ErrGroupNameExists when creating group with duplicate name",
			execute: func(t *testing.T) {
				err := client.CreateGroup(groupName, "99999", nil)
				assert.ErrorIs(t, err, ErrGroupNameExists)
			},
		},
		{
			name: "Should return ErrGidNumberInUse when creating group with duplicate gidNumber",
			execute: func(t *testing.T) {
				err := client.CreateGroup("another_group", gidNumber, nil)
				assert.ErrorIs(t, err, ErrGidNumberInUse)
			},
		},
		{
			name: "Should get group info successfully",
			execute: func(t *testing.T) {
				entry, err := client.GetGroupInfo(groupName)
				require.NoError(t, err)
				assert.Equal(t, groupName, entry.GetAttributeValue("cn"))
				assert.Contains(t, entry.GetAttributeValues("memberUid"), user1)
			},
		},
		{
			name: "Should return ErrGroupNotFound when getting info for nonexistent group",
			execute: func(t *testing.T) {
				_, err := client.GetGroupInfo("nonexistent")
				assert.ErrorIs(t, err, ErrGroupNotFound)
			},
		},
		{
			name: "Should add user to group successfully",
			execute: func(t *testing.T) {
				err := client.AddUserToGroup(groupName, user2)
				assert.NoError(t, err)
			},
		},
		{
			name: "Should return ErrUserAlreadyInGroup when adding same user twice",
			execute: func(t *testing.T) {
				err := client.AddUserToGroup(groupName, user2)
				assert.ErrorIs(t, err, ErrUserAlreadyInGroup)
			},
		},
		{
			name: "Should get groups for user",
			execute: func(t *testing.T) {
				groups, err := client.GetGroupsForUser(user2)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(groups), 1)
			},
		},
		{
			name: "Should remove user from group successfully",
			execute: func(t *testing.T) {
				err := client.RemoveUserFromGroup(groupName, user2)
				assert.NoError(t, err)
			},
		},
		{
			name: "Should return ErrUserNotInGroup when removing nonexistent user",
			execute: func(t *testing.T) {
				err := client.RemoveUserFromGroup(groupName, "ghost")
				assert.ErrorIs(t, err, ErrUserNotInGroup)
			},
		},
		{
			name: "Should list used gidNumbers including current group",
			execute: func(t *testing.T) {
				nums, err := client.GetUsedGidNumbers()
				require.NoError(t, err)
				assert.Contains(t, nums, gidNumber)
			},
		},
		{
			name: "Should delete group successfully",
			execute: func(t *testing.T) {
				err := client.DeleteGroup(groupName)
				assert.NoError(t, err)
			},
		},
		{
			name: "Should return error when deleting nonexistent group",
			execute: func(t *testing.T) {
				err := client.DeleteGroup("ghost_group")
				assert.Error(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.execute(t)
		})
	}
}
