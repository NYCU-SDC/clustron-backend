package ldap

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserFlow(t *testing.T) {
	type testCase struct {
		name    string
		execute func(t *testing.T)
	}

	const (
		uid       = "test_user"
		uidNumber = "12345"
		pubkey1   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey1"
		pubkey2   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey2"
	)

	tests := []testCase{
		{
			name: "Should create user successfully",
			execute: func(t *testing.T) {
				err := client.CreateUser(uid, "Test", "User", pubkey1, uidNumber)
				require.NoError(t, err)
			},
		},
		{
			name: "Should return ErrUserExists for duplicate uid",
			execute: func(t *testing.T) {
				err := client.CreateUser(uid, "Other", "User", pubkey1, "54321")
				assert.ErrorIs(t, err, ErrUserExists)
			},
		},
		{
			name: "Should return ErrUidNumberInUse for duplicate uidNumber",
			execute: func(t *testing.T) {
				err := client.CreateUser("another_user", "CN", "SN", pubkey1, uidNumber)
				assert.ErrorIs(t, err, ErrUidNumberInUse)
			},
		},
		{
			name: "Should get user info successfully",
			execute: func(t *testing.T) {
				entry, err := client.GetUserInfo(uid)
				require.NoError(t, err)
				assert.Equal(t, uid, entry.GetAttributeValue("uid"))
				assert.Equal(t, "Test", entry.GetAttributeValue("cn"))
			},
		},
		{
			name: "Should return ErrUserNotFound for nonexistent user",
			execute: func(t *testing.T) {
				_, err := client.GetUserInfo("nonexistent")
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "Should update user successfully",
			execute: func(t *testing.T) {
				err := client.UpdateUser(uid, "UpdatedCN", "UpdatedSN")
				assert.NoError(t, err)

				entry, _ := client.GetUserInfo(uid)
				assert.Equal(t, "UpdatedCN", entry.GetAttributeValue("cn"))
			},
		},
		{
			name: "Should return ErrUserNotFound for update on nonexistent user",
			execute: func(t *testing.T) {
				err := client.UpdateUser("ghost", "CN", "SN")
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "Should add SSH public key successfully",
			execute: func(t *testing.T) {
				err := client.AddSSHPublicKey(uid, pubkey2)
				assert.NoError(t, err)

				entry, _ := client.GetUserInfo(uid)
				assert.Contains(t, entry.GetAttributeValues("sshPublicKey"), pubkey2)
			},
		},
		{
			name: "Should delete SSH public key successfully",
			execute: func(t *testing.T) {
				err := client.DeleteSSHPublicKey(uid, pubkey1)
				assert.NoError(t, err)

				entry, _ := client.GetUserInfo(uid)
				assert.NotContains(t, entry.GetAttributeValues("sshPublicKey"), pubkey1)
			},
		},
		{
			name: "Should return ErrUserNotFound when adding key to nonexistent user",
			execute: func(t *testing.T) {
				err := client.AddSSHPublicKey("ghost", pubkey1)
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "Should return ErrUserNotFound when deleting key from nonexistent user",
			execute: func(t *testing.T) {
				err := client.DeleteSSHPublicKey("ghost", pubkey2)
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "Should list used uidNumbers",
			execute: func(t *testing.T) {
				uids, err := client.GetUsedUidNumbers()
				assert.NoError(t, err)
				assert.Contains(t, uids, uidNumber)
			},
		},
		{
			name: "Should delete user successfully",
			execute: func(t *testing.T) {
				err := client.DeleteUser(uid)
				assert.NoError(t, err)
			},
		},
		{
			name: "Should return ErrUserNotFound when deleting nonexistent user",
			execute: func(t *testing.T) {
				err := client.DeleteUser("ghost")
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.execute)
	}
}
