// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	group "clustron-backend/internal/group"
	context "context"

	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// Auth is an autogenerated mock type for the Auth type
type Auth struct {
	mock.Mock
}

// GetUserGroupAccessLevel provides a mock function with given fields: ctx, userID, groupID
func (_m *Auth) GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error) {
	ret := _m.Called(ctx, userID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for GetUserGroupAccessLevel")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) (string, error)); ok {
		return rf(ctx, userID, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) string); ok {
		r0 = rf(ctx, userID, groupID)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, userID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserGroupRole provides a mock function with given fields: ctx, userID, groupID
func (_m *Auth) GetUserGroupRole(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (group.GroupRole, error) {
	ret := _m.Called(ctx, userID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for GetUserGroupRole")
	}

	var r0 group.GroupRole
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) (group.GroupRole, error)); ok {
		return rf(ctx, userID, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) group.GroupRole); ok {
		r0 = rf(ctx, userID, groupID)
	} else {
		r0 = ret.Get(0).(group.GroupRole)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, userID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewAuth creates a new instance of Auth. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuth(t interface {
	mock.TestingT
	Cleanup(func())
}) *Auth {
	mock := &Auth{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
