package ldap

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGroupFlow(t *testing.T) {
	groupName := "test_group"
	gidNumber := "20001"
	user1 := "test_user1"
	user2 := "test_user2"

	require.NoError(t, client.CreateUser(user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001"))
	require.NoError(t, client.CreateUser(user2, "CN2", "SN2", "ssh-rsa AAAA2", "10002"))

	err := client.CreateGroup(groupName, gidNumber, []string{user1})
	require.NoError(t, err)

	err = client.CreateGroup(groupName, "99999", nil)
	assert.ErrorIs(t, err, ErrGroupNameExists)

	err = client.CreateGroup("another_group", gidNumber, nil)
	assert.ErrorIs(t, err, ErrGidNumberInUse)

	entry, err := client.GetGroupInfo(groupName)
	require.NoError(t, err)
	assert.Equal(t, groupName, entry.GetAttributeValue("cn"))
	assert.Contains(t, entry.GetAttributeValues("memberUid"), user1)

	_, err = client.GetGroupInfo("nonexistent")
	assert.ErrorIs(t, err, ErrGroupNotFound)

	err = client.AddUserToGroup(groupName, user2)
	assert.NoError(t, err)

	err = client.AddUserToGroup(groupName, user2)
	assert.ErrorIs(t, err, ErrUserAlreadyInGroup)

	groups, err := client.GetGroupsForUser(user2)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(groups), 1)

	err = client.RemoveUserFromGroup(groupName, user2)
	assert.NoError(t, err)

	err = client.RemoveUserFromGroup(groupName, "ghost")
	assert.ErrorIs(t, err, ErrUserNotInGroup)

	gids, err := client.GetUsedGidNumbers()
	assert.NoError(t, err)
	assert.Contains(t, gids, gidNumber)

	err = client.DeleteGroup(groupName)
	assert.NoError(t, err)

	err = client.DeleteGroup("ghost_group")
	assert.Error(t, err)
}
