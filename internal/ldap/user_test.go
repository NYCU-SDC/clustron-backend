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
	pubkey2   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAkey2"
)

func TestClient_CreateUser(t *testing.T) {
	tests := []struct {
		name      string
		uid       string
		uidNumber string
		error     error
	}{
		{
			name:      "Should create user successfully",
			uid:       user,
			uidNumber: uidNumber,
			error:     nil,
		},
		{
			name:      "Should return ErrUserExists for duplicate uid",
			uid:       user,
			uidNumber: "99999",
			error:     ErrUserExists,
		},
		{
			name:      "Should return ErrUidNumberInUse for duplicate uidNumber",
			uid:       "another_user",
			uidNumber: uidNumber,
			error:     ErrUidNumberInUse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			if tc.error != nil {
				setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)
			}

			err := client.CreateUser(tc.uid, "CN", "SN", pubkey1, tc.uidNumber)
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
		name   string
		uid    string
		pubKey string
		error  error
	}{
		{
			name:   "Should add SSH public key successfully",
			uid:    user,
			pubKey: pubkey2,
			error:  nil,
		},
		{
			name:   "Should return ErrUserNotFound when adding SSH public key for nonexistent user",
			uid:    "nonexistent",
			pubKey: pubkey2,
			error:  ErrUserNotFound,
		},
		{
			name:   "Should return ErrPublicKeyExists when adding duplicate SSH public key",
			uid:    user,
			pubKey: pubkey1,
			error:  ErrPublicKeyExists,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			err := client.AddSSHPublicKey(tc.uid, tc.pubKey)
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
		name   string
		uid    string
		pubKey string
		error  error
	}{
		{
			name:   "Should delete SSH public key successfully",
			uid:    user,
			pubKey: pubkey1,
			error:  nil,
		},
		{
			name:   "Should return ErrUserNotFound when deleting SSH public key for nonexistent user",
			uid:    "nonexistent",
			pubKey: pubkey1,
			error:  ErrUserNotFound,
		},
		{
			name:   "Should return ErrPublicKeyNotFound when deleting nonexistent SSH public key",
			uid:    user,
			pubKey: pubkey2,
			error:  ErrPublicKeyNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClient(t)
			defer done()

			setupUser(t, client, user, "CN", "SN", pubkey1, uidNumber)

			err := client.DeleteSSHPublicKey(tc.uid, tc.pubKey)
			if tc.error == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.error)
			}
		})
	}
}
