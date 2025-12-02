package setting_test

import (
	"clustron-backend/internal/setting"
	"clustron-backend/internal/setting/mocks"
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"
	"testing"
)

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
				ldapUIDStr := fmt.Sprintf("%d", ldapUID)
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUIDStr).Return(entry, nil)
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
				ldapUIDStr := fmt.Sprintf("%d", ldapUID)
				store.On("GetUIDByUserID", mock.Anything, userID).Return(ldapUID, nil)
				ldapClient.On("GetUserInfoByUIDNumber", ldapUIDStr).Return(entry, nil)
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
