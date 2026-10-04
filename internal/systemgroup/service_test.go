package systemgroup_test

import (
	"context"
	"errors"
	"testing"

	"clustron-backend/internal/ansible"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/systemgroup"
	"clustron-backend/internal/systemgroup/mocks"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type serviceMocks struct {
	querier     *mocks.Querier
	ldap        *mocks.LDAPClient
	settings    *mocks.SettingStore
	localGroups *mocks.LocalGroupStore
}

func newService() (*systemgroup.Service, serviceMocks) {
	m := serviceMocks{
		querier:     new(mocks.Querier),
		ldap:        new(mocks.LDAPClient),
		settings:    new(mocks.SettingStore),
		localGroups: new(mocks.LocalGroupStore),
	}
	m.localGroups.On("ListLocalGroups", mock.Anything).Return([]ansible.LocalGroup{
		{ServerName: "node01", Name: "docker", GIDNumber: 999},
	}, nil)
	return systemgroup.NewService(zap.NewNop(), m.querier, m.ldap, m.settings, m.localGroups, nil), m
}

var errQuery = errors.New("query failed")

func TestService_Register_CompensatesLDAPWhenInsertFails(t *testing.T) {
	svc, m := newService()
	m.ldap.On("CreateGroup", "docker", "999", []string{}).Return(nil)
	m.querier.On("Create", mock.Anything, systemgroup.CreateParams{Name: "docker", GidNumber: 999}).Return(systemgroup.SystemGroup{}, errQuery)
	m.ldap.On("DeleteGroup", "docker").Return(nil)

	_, err := svc.Register(context.Background(), "docker", "")

	require.Error(t, err)
	m.ldap.AssertExpectations(t)
}

func TestService_AddMember_CompensatesLDAPWhenInsertFails(t *testing.T) {
	svc, m := newService()
	groupID, userID := uuid.New(), uuid.New()
	m.querier.On("GetByID", mock.Anything, groupID).Return(systemgroup.SystemGroup{ID: groupID, Name: "docker", GidNumber: 999}, nil)
	m.settings.On("GetLDAPUserInfoByUserID", mock.Anything, userID).Return(setting.LDAPUserInfo{Username: "alice"}, nil)
	m.ldap.On("AddUserToGroup", "docker", "alice").Return(nil)
	m.querier.On("AddMember", mock.Anything, systemgroup.AddMemberParams{SystemGroupID: groupID, UserID: userID}).Return(errQuery)
	m.ldap.On("RemoveUserFromGroup", "docker", "alice").Return(nil)

	err := svc.AddMember(context.Background(), groupID, userID)

	require.Error(t, err)
	m.ldap.AssertExpectations(t)
}

func TestService_RemoveMember_RestoresRowWhenLDAPFails(t *testing.T) {
	svc, m := newService()
	groupID, userID := uuid.New(), uuid.New()
	params := systemgroup.RemoveMemberParams{SystemGroupID: groupID, UserID: userID}
	ldapErr := errors.New("ldap down")
	m.querier.On("GetByID", mock.Anything, groupID).Return(systemgroup.SystemGroup{ID: groupID, Name: "docker", GidNumber: 999}, nil)
	m.querier.On("RemoveMember", mock.Anything, params).Return(int64(1), nil)
	m.settings.On("GetLDAPUserInfoByUserID", mock.Anything, userID).Return(setting.LDAPUserInfo{Username: "alice"}, nil)
	m.ldap.On("RemoveUserFromGroup", "docker", "alice").Return(ldapErr)
	m.querier.On("AddMember", mock.Anything, systemgroup.AddMemberParams{SystemGroupID: groupID, UserID: userID}).Return(nil)

	err := svc.RemoveMember(context.Background(), groupID, userID)

	assert.ErrorIs(t, err, ldapErr)
	m.querier.AssertExpectations(t)
}

func TestService_RemoveMember_NonMemberReturnsNotFoundWithoutLDAP(t *testing.T) {
	svc, m := newService()
	groupID, userID := uuid.New(), uuid.New()
	m.querier.On("GetByID", mock.Anything, groupID).Return(systemgroup.SystemGroup{ID: groupID, Name: "docker", GidNumber: 999}, nil)
	m.querier.On("RemoveMember", mock.Anything, systemgroup.RemoveMemberParams{SystemGroupID: groupID, UserID: userID}).Return(int64(0), nil)

	err := svc.RemoveMember(context.Background(), groupID, userID)

	assert.ErrorIs(t, err, handlerutil.ErrNotFound)
	m.settings.AssertNotCalled(t, "GetLDAPUserInfoByUserID", mock.Anything, mock.Anything)
	m.ldap.AssertNotCalled(t, "RemoveUserFromGroup", mock.Anything, mock.Anything)
}
