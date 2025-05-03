package ldap

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserFlow(t *testing.T) {
	uid := "test_user"
	cn := "Test"
	sn := "User"
	uidNumber := "12345"
	pubkey1 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey1"
	pubkey2 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey2"

	err := client.CreateUser(uid, cn, sn, pubkey1, uidNumber)
	require.NoError(t, err)

	err = client.CreateUser(uid, "CN", "SN", pubkey1, "54321")
	assert.ErrorIs(t, err, ErrUserExists)

	err = client.CreateUser("another_user", "CN", "SN", pubkey1, uidNumber)
	assert.ErrorIs(t, err, ErrUidNumberInUse)

	entry, err := client.GetUserInfo(uid)
	require.NoError(t, err)
	assert.Equal(t, uid, entry.GetAttributeValue("uid"))
	assert.Equal(t, cn, entry.GetAttributeValue("cn"))

	_, err = client.GetUserInfo("nonexistent")
	assert.ErrorIs(t, err, ErrUserNotFound)

	err = client.UpdateUser(uid, "UpdatedCN", "UpdatedSN")
	assert.NoError(t, err)

	entry, _ = client.GetUserInfo(uid)
	assert.Equal(t, "UpdatedCN", entry.GetAttributeValue("cn"))

	err = client.UpdateUser("nonexistent", "CN", "SN")
	assert.ErrorIs(t, err, ErrUserNotFound)

	err = client.AddSSHPublicKey(uid, pubkey2)
	assert.NoError(t, err)

	entry, _ = client.GetUserInfo(uid)
	assert.Contains(t, entry.GetAttributeValues("sshPublicKey"), pubkey2)

	err = client.DeleteSSHPublicKey(uid, pubkey1)
	assert.NoError(t, err)

	entry, _ = client.GetUserInfo(uid)
	assert.NotContains(t, entry.GetAttributeValues("sshPublicKey"), pubkey1)

	err = client.AddSSHPublicKey("ghost", pubkey1)
	assert.ErrorIs(t, err, ErrUserNotFound)

	err = client.DeleteSSHPublicKey("ghost", pubkey2)
	assert.ErrorIs(t, err, ErrUserNotFound)

	uids, err := client.GetUsedUidNumbers()
	assert.NoError(t, err)
	assert.Contains(t, uids, uidNumber)

	err = client.DeleteUser(uid)
	assert.NoError(t, err)

	err = client.DeleteUser("ghost")
	assert.ErrorIs(t, err, ErrUserNotFound)
}
