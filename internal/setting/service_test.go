package setting_test

import (
	ldaputil "clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/setting/mocks"
	"context"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"
	"testing"
)

var exampleFingerprint = "Sr7R03NsrTQ3vXO7XcRZzpJfixXJnwZXPi48i6XsLOY"

func TestService_GetSettingByUserID(t *testing.T) {
	testCases := []struct {
		name             string
		userID           uuid.UUID
		ldapUID          int64
		ldapEntry        *ldap.Entry
		expectedErr      error
		expectedUserInfo setting.LDAPUserInfo
		setupMock        func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry)
	}{
		{
			name:    "Valid UserID with existing setting",
			userID:  uuid.New(),
			ldapUID: 10001,
			ldapEntry: &ldap.Entry{
				DN: "uid=testuser,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "uidNumber", Values: []string{"10001"}},
					{Name: "uid", Values: []string{"testuser"}},
					{Name: "cn", Values: []string{"Test User"}},
					{Name: "sn", Values: []string{"User"}},
					{Name: "sshPublicKey", Values: []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC.."}},
				},
			},
			expectedErr: nil,
			expectedUserInfo: setting.LDAPUserInfo{
				Username: "testuser",
				PublicKey: []string{
					"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..",
				},
			},

			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:    "Valid UserID with existing setting with multiple SSH keys",
			userID:  uuid.New(),
			ldapUID: 10001,
			ldapEntry: &ldap.Entry{
				DN: "uid=testuser,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "uidNumber", Values: []string{"10001"}},
					{Name: "uid", Values: []string{"testuser"}},
					{Name: "cn", Values: []string{"Test User"}},
					{Name: "sn", Values: []string{"User"}},
					{Name: "sshPublicKey", Values: []string{
						"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..",
						"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB..",
					}},
				},
			},
			expectedErr: nil,
			expectedUserInfo: setting.LDAPUserInfo{
				Username: "testuser",
				PublicKey: []string{
					"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..",
					"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB..",
				},
			},

			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
	}

	logger := zaptest.NewLogger(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(logger, querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry)
			}

			userInfo, err := service.GetLDAPUserInfoByUserID(context.Background(), tc.userID)
			if tc.expectedErr != nil {
				if err == nil || err.Error() != tc.expectedErr.Error() {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if userInfo.Username != tc.expectedUserInfo.Username {
					t.Errorf("expected username %s, got %s", tc.expectedUserInfo.Username, userInfo.Username)
				}
				if len(userInfo.PublicKey) != len(tc.expectedUserInfo.PublicKey) {
					t.Errorf("expected %d public keys, got %d", len(tc.expectedUserInfo.PublicKey), len(userInfo.PublicKey))
				} else {
					for i, key := range userInfo.PublicKey {
						if key != tc.expectedUserInfo.PublicKey[i] {
							t.Errorf("expected public key %s, got %s", tc.expectedUserInfo.PublicKey[i], key)
						}
					}
				}
			}
		})
	}
}

func Test_GetLDAPUserInfoByUserID(t *testing.T) {
	exampleLDAPEntry := &ldap.Entry{
		DN: "uid=testuser,ou=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uidNumber", Values: []string{"10001"}},
			{Name: "uid", Values: []string{"testuser"}},
			{Name: "cn", Values: []string{"Test User"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "sshPublicKey", Values: []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC.."}},
		},
	}
	testCases := []struct {
		name             string
		userID           uuid.UUID
		ldapUID          int64
		ldapEntry        *ldap.Entry
		expectedHasErr   bool
		expectedUserInfo setting.LDAPUserInfo
		setupMock        func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry)
	}{
		{
			name:           "Valid UserID with existing setting",
			userID:         uuid.New(),
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: false,
			expectedUserInfo: setting.LDAPUserInfo{
				Username: "testuser",
				PublicKey: []string{
					"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..",
				},
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:           "UserID with no ldap UID mapping",
			userID:         uuid.New(),
			ldapUID:        0,
			ldapEntry:      nil,
			expectedHasErr: true,
			expectedUserInfo: setting.LDAPUserInfo{
				Username:  "",
				PublicKey: nil,
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(int64(0), assert.AnError)
			},
		},
		{
			name:           "LDAP UID with no corresponding LDAP entry",
			userID:         uuid.New(),
			ldapUID:        10002,
			ldapEntry:      nil,
			expectedHasErr: true,
			expectedUserInfo: setting.LDAPUserInfo{
				Username:  "",
				PublicKey: nil,
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(nil, ldaputil.ErrUserNotFound)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(zaptest.NewLogger(t), querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry)
			}

			ldapUserInfo, err := service.GetLDAPUserInfoByUserID(context.Background(), tc.userID)
			if tc.expectedHasErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ldapUserInfo.Username != tc.expectedUserInfo.Username {
					t.Errorf("expected username %s, got %s", tc.expectedUserInfo.Username, ldapUserInfo.Username)
				}
				if len(ldapUserInfo.PublicKey) != len(tc.expectedUserInfo.PublicKey) {
					t.Errorf("expected %d public keys, got %d", len(tc.expectedUserInfo.PublicKey), len(ldapUserInfo.PublicKey))
				} else {
					for i, key := range ldapUserInfo.PublicKey {
						if key != tc.expectedUserInfo.PublicKey[i] {
							t.Errorf("expected public key %s, got %s", tc.expectedUserInfo.PublicKey[i], key)
						}
					}
				}
			}
		})
	}
}

func Test_GetPublicKeysByUserID(t *testing.T) {
	exampleLDAPEntry := &ldap.Entry{
		DN: "uid=testuser,ou=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uidNumber", Values: []string{"10001"}},
			{Name: "uid", Values: []string{"testuser"}},
			{Name: "cn", Values: []string{"Test User"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "sshPublicKey", Values: []string{exampleValidKey}},
		},
	}

	testCases := []struct {
		name           string
		userID         uuid.UUID
		ldapUID        int64
		ldapEntry      *ldap.Entry
		expectedHasErr bool
		expectedPubKey []setting.LDAPPublicKey
		setupMock      func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry)
	}{
		{
			name:           "Valid UserID with existing public keys",
			userID:         uuid.New(),
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: false,
			expectedPubKey: []setting.LDAPPublicKey{
				{
					Fingerprint: exampleFingerprint,
					PublicKey:   exampleValidKey,
					Title:       "title",
				},
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:           "UserID with no ldap UID mapping",
			userID:         uuid.New(),
			ldapUID:        0,
			ldapEntry:      nil,
			expectedHasErr: true,
			expectedPubKey: nil,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(int64(0), assert.AnError)
			},
		},
		{
			name:           "LDAP UID with no corresponding LDAP entry",
			userID:         uuid.New(),
			ldapUID:        10002,
			ldapEntry:      nil,
			expectedHasErr: true,
			expectedPubKey: nil,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(nil, ldaputil.ErrUserNotFound)
			},
		},
		{
			name:    "LDAP Entry with no public keys",
			userID:  uuid.New(),
			ldapUID: 10003,
			ldapEntry: &ldap.Entry{
				DN: "uid=nokeys,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "uidNumber", Values: []string{"10003"}},
					{Name: "uid", Values: []string{"nokeys"}},
					{Name: "cn", Values: []string{"No Keys"}},
					{Name: "sn", Values: []string{"User"}},
				},
			},
			expectedHasErr: false,
			expectedPubKey: []setting.LDAPPublicKey{},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(zaptest.NewLogger(t), querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry)
			}

			pubKeys, err := service.GetPublicKeysByUserID(context.Background(), tc.userID)
			if tc.expectedHasErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(pubKeys) != len(tc.expectedPubKey) {
					t.Errorf("expected %d public keys, got %d", len(tc.expectedPubKey), len(pubKeys))
				} else {
					for i, key := range pubKeys {
						if key != tc.expectedPubKey[i] {
							t.Errorf("expected public key %s, got %s", tc.expectedPubKey[i], key)
						}
					}
				}
			}
		})
	}
}

func Test_GetPublicKeyByFingerprint(t *testing.T) {
	exampleLDAPEntry := &ldap.Entry{
		DN: "uid=testuser,ou=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uidNumber", Values: []string{"10001"}},
			{Name: "uid", Values: []string{"testuser"}},
			{Name: "cn", Values: []string{"Test User"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "sshPublicKey", Values: []string{exampleValidKey}},
		},
	}

	testCases := []struct {
		name           string
		userID         uuid.UUID
		fingerprint    string
		ldapUID        int64
		ldapEntry      *ldap.Entry
		expectedHasErr bool
		expectedPubKey setting.LDAPPublicKey
		setupMock      func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry)
	}{
		{
			name:           "Valid UserID and fingerprint",
			userID:         uuid.New(),
			fingerprint:    exampleFingerprint,
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: false,
			expectedPubKey: setting.LDAPPublicKey{
				Fingerprint: exampleFingerprint,
				PublicKey:   exampleValidKey,
				Title:       "title",
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:           "Valid UserID but fingerprint not found",
			userID:         uuid.New(),
			fingerprint:    "NonExistentFingerprint",
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: true,
			expectedPubKey: setting.LDAPPublicKey{},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(zaptest.NewLogger(t), querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry)
			}

			pubKey, err := service.GetPublicKeyByFingerprint(context.Background(), tc.userID, tc.fingerprint)
			if tc.expectedHasErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if pubKey != tc.expectedPubKey {
					t.Errorf("expected public key %v, got %v", tc.expectedPubKey, pubKey)
				}
			}
		})
	}
}

func Test_AddPublicKey(t *testing.T) {
	exampleLDAPEntry := &ldap.Entry{
		DN: "uid=testuser,ou=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uidNumber", Values: []string{"10001"}},
			{Name: "uid", Values: []string{"testuser"}},
			{Name: "cn", Values: []string{"Test User"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "sshPublicKey", Values: []string{exampleValidKey}},
		},
	}
	testCases := []struct {
		name           string
		userID         uuid.UUID
		newPublicKey   string
		title          string
		ldapUID        int64
		ldapEntry      *ldap.Entry
		expectedHasErr bool
		expectedPubKey setting.LDAPPublicKey
		setupMock      func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, newKey string)
	}{
		{
			name:         "Add valid new public key",
			userID:       uuid.New(),
			newPublicKey: exampleValidKey,
			title:        "title",
			ldapUID:      10001,
			ldapEntry: &ldap.Entry{
				DN: "uid=testuser,ou=users,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "uidNumber", Values: []string{"10001"}},
					{Name: "uid", Values: []string{"testuser"}},
					{Name: "cn", Values: []string{"Test User"}},
					{Name: "sn", Values: []string{"User"}},
				},
			},
			expectedHasErr: false,
			expectedPubKey: setting.LDAPPublicKey{
				Fingerprint: exampleFingerprint,
				PublicKey:   exampleValidKey,
				Title:       "title",
			},
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, newKey string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
				ldapClient.On("AddSSHPublicKey", entry.GetAttributeValue("uid"), newKey).Return(nil)
			},
		},
		{
			name:           "Add invalid public key",
			userID:         uuid.New(),
			newPublicKey:   "invalid-key-format",
			title:          "new-key",
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: true,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, newKey string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:           "Add duplicate public key",
			userID:         uuid.New(),
			newPublicKey:   exampleValidKey,
			title:          "title",
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: true,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, newKey string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
		{
			name:           "LDAP UID not found for user",
			userID:         uuid.New(),
			newPublicKey:   exampleValidKey,
			title:          "title",
			ldapUID:        0,
			ldapEntry:      nil,
			expectedHasErr: true,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, newKey string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(int64(0), assert.AnError)
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(zaptest.NewLogger(t), querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry, tc.newPublicKey)
			}

			ldapPublicKey, err := service.AddPublicKey(context.Background(), tc.userID, tc.newPublicKey, tc.title)
			if tc.expectedHasErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ldapPublicKey.PublicKey != tc.expectedPubKey.PublicKey || ldapPublicKey.Title != tc.expectedPubKey.Title {
					t.Errorf("expected public key %v, got %v", tc.expectedPubKey, ldapPublicKey)
				}
			}
		})
	}
}

func Test_DeletePublicKey(t *testing.T) {
	exampleLDAPEntry := &ldap.Entry{
		DN: "uid=testuser,ou=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uidNumber", Values: []string{"10001"}},
			{Name: "uid", Values: []string{"testuser"}},
			{Name: "cn", Values: []string{"Test User"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "sshPublicKey", Values: []string{exampleValidKey}},
		},
	}
	testCases := []struct {
		name           string
		userID         uuid.UUID
		fingerprint    string
		ldapUID        int64
		ldapEntry      *ldap.Entry
		expectedHasErr bool
		setupMock      func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, fingerprint string)
	}{
		{
			name:           "Delete existing public key",
			userID:         uuid.New(),
			fingerprint:    exampleFingerprint,
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: false,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, fingerprint string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
				ldapClient.On("DeleteSSHPublicKey", entry.GetAttributeValue("uid"), exampleValidKey).Return(nil)
			},
		},
		{
			name:           "Delete non-existing public key",
			userID:         uuid.New(),
			fingerprint:    "NonExistentFingerprint",
			ldapUID:        10001,
			ldapEntry:      exampleLDAPEntry,
			expectedHasErr: true,
			setupMock: func(store *mocks.Querier, ldapClient *mocks.LDAPClient, userID uuid.UUID, ldapUID int64, entry *ldap.Entry, fingerprint string) {
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUID).Return(entry, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			querier := new(mocks.Querier)
			userStore := new(mocks.UserStore)
			ldapClient := new(mocks.LDAPClient)
			service := setting.NewService(zaptest.NewLogger(t), querier, userStore, ldapClient)

			if tc.setupMock != nil {
				tc.setupMock(querier, ldapClient, tc.userID, tc.ldapUID, tc.ldapEntry, tc.fingerprint)
			}

			err := service.DeletePublicKey(context.Background(), tc.userID, tc.fingerprint)
			if tc.expectedHasErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
