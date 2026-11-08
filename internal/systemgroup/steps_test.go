package systemgroup_test

import (
	"context"
	"errors"
	"testing"

	"clustron-backend/internal"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/systemgroup"
	"clustron-backend/internal/systemgroup/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

var errLater = errors.New("later step failed")

func runWithFailingNextStep(step internal.SagaStep) error {
	saga := internal.NewSaga(zap.NewNop())
	saga.AddStep(step)
	saga.AddStep(internal.SagaStep{Name: "fail", Action: func(context.Context) error { return errLater }})
	return saga.Execute(context.Background())
}

func TestCreateLDAPGroupStep_CompensatesByDeleting(t *testing.T) {
	client := new(mocks.LDAPClient)
	client.On("CreateGroup", "docker", "999", []string{}).Return(nil)
	client.On("DeleteGroup", "docker").Return(nil)

	err := runWithFailingNextStep(systemgroup.CreateLDAPGroupStep(client, "docker", 999))

	assert.ErrorIs(t, err, errLater)
	client.AssertExpectations(t)
}

func TestAddLDAPMemberStep_CompensatesOnlyWhenAdded(t *testing.T) {
	client := new(mocks.LDAPClient)
	client.On("AddUserToGroup", "docker", "alice").Return(nil)
	client.On("RemoveUserFromGroup", "docker", "alice").Return(nil)

	err := runWithFailingNextStep(systemgroup.AddLDAPMemberStep(client, "docker", "alice"))

	assert.ErrorIs(t, err, errLater)
	client.AssertExpectations(t)
}

func TestAddLDAPMemberStep_AlreadyInGroupIsDoneAndNotCompensated(t *testing.T) {
	client := new(mocks.LDAPClient)
	client.On("AddUserToGroup", "docker", "alice").Return(ldap.ErrUserAlreadyInGroup)

	err := runWithFailingNextStep(systemgroup.AddLDAPMemberStep(client, "docker", "alice"))

	assert.ErrorIs(t, err, errLater)
	client.AssertNotCalled(t, "RemoveUserFromGroup", mock.Anything, mock.Anything)
}

func TestAddLDAPMemberStep_PropagatesLDAPError(t *testing.T) {
	client := new(mocks.LDAPClient)
	ldapErr := errors.New("ldap down")
	client.On("AddUserToGroup", "docker", "alice").Return(ldapErr)

	saga := internal.NewSaga(zap.NewNop())
	saga.AddStep(systemgroup.AddLDAPMemberStep(client, "docker", "alice"))
	err := saga.Execute(context.Background())

	assert.ErrorIs(t, err, ldapErr)
}

func TestRemoveLDAPMemberStep_CompensatesByReAdding(t *testing.T) {
	client := new(mocks.LDAPClient)
	client.On("RemoveUserFromGroup", "docker", "alice").Return(nil)
	client.On("AddUserToGroup", "docker", "alice").Return(nil)

	err := runWithFailingNextStep(systemgroup.RemoveLDAPMemberStep(client, "docker", "alice"))

	assert.ErrorIs(t, err, errLater)
	client.AssertExpectations(t)
}

func TestRemoveLDAPMemberStep_NotInGroupIsDoneAndNotCompensated(t *testing.T) {
	client := new(mocks.LDAPClient)
	client.On("RemoveUserFromGroup", "docker", "alice").Return(ldap.ErrUserNotInGroup)

	err := runWithFailingNextStep(systemgroup.RemoveLDAPMemberStep(client, "docker", "alice"))

	assert.ErrorIs(t, err, errLater)
	client.AssertNotCalled(t, "AddUserToGroup", mock.Anything, mock.Anything)
}
