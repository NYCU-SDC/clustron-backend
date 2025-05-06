package ldap

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	user      = "user"
	uidNumber = "10000"
	pubkey1   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey1"
	pubkey2   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey1"
)

func TestClient_CreateUser(t *testing.T) {
	tests := []struct {
		name  string
		error error
	}{
		{
			name:  "Should create user successfully",
			error: nil,
		},
		{
			name:  "Should return ErrUserExists for duplicate uid",
			error: ErrUserExists,
		},
		{
			name:  "Should return ErrUidNumberInUse for duplicate uidNumber",
			error: ErrUidNumberInUse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			if tc.error != nil {
				setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)
			}

			err := client.CreateUser(user, "CN", "SN", pubkey1, uidNumber)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_GetUserInfo(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		error error
	}{
		{
			name:  "Should get user info successfully",
			uid:   user,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotFound for nonexistent user",
			uid:   "nonexistent",
			error: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			entry, err := client.GetUserInfo(tc.uid)
			if tc.error == nil {
				require.NoError(t, err)
				assert.Equal(t, user, entry.GetAttributeValue("uid"))
				assert.Equal(t, "CN", entry.GetAttributeValue("cn"))
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_UpdateUser(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		error error
	}{
		{
			name:  "Should update user successfully",
			uid:   user,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotFound for update on nonexistent user",
			uid:   "nonexistent",
			error: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			err := client.UpdateUser(tc.uid, "UpdatedCN", "UpdatedSN")
			if tc.error == nil {
				require.NoError(t, err)
				entry, _ := client.GetUserInfo(tc.uid)
				assert.Equal(t, "UpdatedCN", entry.GetAttributeValue("cn"))
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_DeleteUser(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		error error
	}{
		{
			name:  "Should delete user successfully",
			uid:   user,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotFound when deleting nonexistent user",
			uid:   "nonexistent",
			error: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			err := client.DeleteUser(tc.uid)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_GetUsedUidNumbers(t *testing.T) {
	tests := []struct {
		name         string
		expectedUIDs []string
	}{
		{
			name:         "Should return empty list when no groups exist",
			expectedUIDs: []string{},
		},
		{
			name:         "Should return gidNumber from single group",
			expectedUIDs: []string{"10000"},
		},
		{
			name:         "Should return multiple gidNumbers",
			expectedUIDs: []string{"10000", "10001"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			for _, uid := range tc.expectedUIDs {
				require.NoError(t, client.CreateUser(fmt.Sprintf("user_%s", uid), "CN", "SN", pubkey1, uid))
			}

			uids, err := client.GetUsedUidNumbers()
			require.NoError(t, err)

			fmt.Println(uids)
			fmt.Println(tc.expectedUIDs)
			for _, uid := range tc.expectedUIDs {
				assert.Contains(t, uids, uid)
			}
		})
	}
}

func TestClient_AddSSHPublicKey(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		error error
	}{
		{
			name:  "Should add SSH public key successfully",
			uid:   user,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotFound when adding SSH public key for nonexistent user",
			uid:   "nonexistent",
			error: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", "", uidNumber)

			err := client.AddSSHPublicKey(tc.uid, pubkey2)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

func TestClient_DeleteSSHPublicKey(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		error error
	}{
		{
			name:  "Should delete SSH public key successfully",
			uid:   user,
			error: nil,
		},
		{
			name:  "Should return ErrUserNotFound when deleting SSH public key for nonexistent user",
			uid:   "nonexistent",
			error: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			err := client.DeleteSSHPublicKey(tc.uid, pubkey1)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}

/*
func TestUserFlow(t *testing.T) {
	type testCase struct {
		name    string
		execute func(t *testing.T)
	}

	client, done := newTestClient(t)
	defer done()

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
*/
