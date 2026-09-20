package systemgroup

import (
	"context"
	"errors"
	"testing"

	"clustron-backend/internal"
	"clustron-backend/internal/ansible"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"
	sg "clustron-backend/internal/systemgroup"
	"clustron-backend/internal/systemgroup/mocks"
	"clustron-backend/test/integration"
	dbtestdata "clustron-backend/test/testdata/database"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var dockerOnAllNodes = []ansible.LocalGroup{
	{ServerName: "node01", Name: "docker", GIDNumber: 999},
	{ServerName: "node02", Name: "docker", GIDNumber: 999},
}

type fixture struct {
	service  *sg.Service
	ldap     *mocks.LDAPClient
	settings *mocks.SettingStore
}

func newFixture(db sg.DBTX, logger *zap.Logger) fixture {
	ldapClient := new(mocks.LDAPClient)
	settings := new(mocks.SettingStore)
	localGroups := new(mocks.LocalGroupStore)
	localGroups.On("ListLocalGroups", mock.Anything).Return(dockerOnAllNodes, nil)

	return fixture{
		service:  sg.NewService(logger, sg.New(db), ldapClient, settings, localGroups, nil),
		ldap:     ldapClient,
		settings: settings,
	}
}

func (f fixture) registerDocker(t *testing.T) sg.SystemGroup {
	t.Helper()
	f.ldap.On("CreateGroup", "docker", "999", []string{}).Return(nil)
	group, err := f.service.Register(context.Background(), "docker", "")
	require.NoError(t, err)
	return group
}

func TestSystemGroupService(t *testing.T) {
	resourceManager, logger, err := integration.GetOrInitResource()
	require.NoError(t, err)
	defer resourceManager.Cleanup(t.Context())

	ctx := context.Background()

	t.Run("register, add, remove and delete", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		user := dbtestdata.NewBuilder(t, db).User().Create()
		f := newFixture(db, logger)

		group := f.registerDocker(t)
		assert.Equal(t, int64(999), group.GidNumber)

		f.settings.On("GetLDAPUserInfoByUserID", mock.Anything, user.ID).Return(setting.LDAPUserInfo{Username: "alice"}, nil)
		f.ldap.On("AddUserToGroup", "docker", "alice").Return(nil)
		require.NoError(t, f.service.AddMember(ctx, group.ID, user.ID))
		members, err := f.service.ListMembers(ctx, group.ID)
		require.NoError(t, err)
		require.Len(t, members, 1)
		assert.Equal(t, user.ID, members[0].UserID)

		f.ldap.On("RemoveUserFromGroup", "docker", "alice").Return(nil)
		require.NoError(t, f.service.RemoveMember(ctx, group.ID, user.ID))
		members, err = f.service.ListMembers(ctx, group.ID)
		require.NoError(t, err)
		assert.Empty(t, members)

		f.ldap.On("DeleteGroup", "docker").Return(nil)
		require.NoError(t, f.service.Delete(ctx, group.ID))
		groups, err := f.service.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, groups)

		f.ldap.AssertExpectations(t)
	})

	t.Run("failed LDAP create leaves no row", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		f := newFixture(db, logger)
		ldapErr := errors.New("ldap down")
		f.ldap.On("CreateGroup", "docker", "999", []string{}).Return(ldapErr)

		_, err := f.service.Register(ctx, "docker", "")

		assert.ErrorIs(t, err, ldapErr)
		groups, err := f.service.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, groups)
	})

	t.Run("adding a user whose LDAP entry is missing returns ErrUserHasNoLDAPAccount", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		user := dbtestdata.NewBuilder(t, db).User().Create()
		f := newFixture(db, logger)
		group := f.registerDocker(t)
		f.settings.On("GetLDAPUserInfoByUserID", mock.Anything, user.ID).Return(setting.LDAPUserInfo{}, ldap.ErrUserNotFound)

		err := f.service.AddMember(ctx, group.ID, user.ID)

		assert.ErrorIs(t, err, internal.ErrUserHasNoLDAPAccount)
		f.ldap.AssertNotCalled(t, "AddUserToGroup", mock.Anything, mock.Anything)
	})

	t.Run("removing a member whose LDAP account is gone still removes the row", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		user := dbtestdata.NewBuilder(t, db).User().Create()
		f := newFixture(db, logger)
		group := f.registerDocker(t)
		f.settings.On("GetLDAPUserInfoByUserID", mock.Anything, user.ID).Return(setting.LDAPUserInfo{Username: "alice"}, nil).Once()
		f.ldap.On("AddUserToGroup", "docker", "alice").Return(nil)
		require.NoError(t, f.service.AddMember(ctx, group.ID, user.ID))
		f.settings.On("GetLDAPUserInfoByUserID", mock.Anything, user.ID).Return(setting.LDAPUserInfo{}, ldap.ErrUserNotFound).Once()

		err := f.service.RemoveMember(ctx, group.ID, user.ID)

		require.NoError(t, err)
		members, err := f.service.ListMembers(ctx, group.ID)
		require.NoError(t, err)
		assert.Empty(t, members)
		f.ldap.AssertNotCalled(t, "RemoveUserFromGroup", mock.Anything, mock.Anything)
	})

	t.Run("removing a non-member returns not found before any LDAP lookup", func(t *testing.T) {
		db := resourceManager.SetupPostgres(t)
		user := dbtestdata.NewBuilder(t, db).User().Create()
		f := newFixture(db, logger)
		group := f.registerDocker(t)
		f.settings.On("GetLDAPUserInfoByUserID", mock.Anything, user.ID).Return(setting.LDAPUserInfo{}, ldap.ErrUserNotFound)

		err := f.service.RemoveMember(ctx, group.ID, user.ID)

		assert.ErrorIs(t, err, handlerutil.ErrNotFound)
		f.settings.AssertNotCalled(t, "GetLDAPUserInfoByUserID", mock.Anything, mock.Anything)
	})
}
