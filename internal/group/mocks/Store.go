// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	group "clustron-backend/internal/group"
	grouprole "clustron-backend/internal/grouprole"
	context "context"

	jwt "clustron-backend/internal/jwt"

	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

// Archive provides a mock function with given fields: ctx, groupID
func (_m *Store) Archive(ctx context.Context, groupID uuid.UUID) (group.Group, error) {
	ret := _m.Called(ctx, groupID)

	if len(ret) == 0 {
		panic("no return value specified for Archive")
	}

	var r0 group.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (group.Group, error)); ok {
		return rf(ctx, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) group.Group); ok {
		r0 = rf(ctx, groupID)
	} else {
		r0 = ret.Get(0).(group.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Create provides a mock function with given fields: ctx, _a1
func (_m *Store) Create(ctx context.Context, _a1 group.CreateParams) (group.Group, error) {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 group.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, group.CreateParams) (group.Group, error)); ok {
		return rf(ctx, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, group.CreateParams) group.Group); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Get(0).(group.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, group.CreateParams) error); ok {
		r1 = rf(ctx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByID provides a mock function with given fields: ctx, roleID
func (_m *Store) GetByID(ctx context.Context, roleID uuid.UUID) (grouprole.GroupRole, error) {
	ret := _m.Called(ctx, roleID)

	if len(ret) == 0 {
		panic("no return value specified for GetByID")
	}

	var r0 grouprole.GroupRole
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (grouprole.GroupRole, error)); ok {
		return rf(ctx, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) grouprole.GroupRole); ok {
		r0 = rf(ctx, roleID)
	} else {
		r0 = ret.Get(0).(grouprole.GroupRole)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTypeByUser provides a mock function with given fields: ctx, userRole, userID, groupID
func (_m *Store) GetTypeByUser(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, string, error) {
	ret := _m.Called(ctx, userRole, userID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for GetTypeByUser")
	}

	var r0 grouprole.GroupRole
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID, uuid.UUID) (grouprole.GroupRole, string, error)); ok {
		return rf(ctx, userRole, userID, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID, uuid.UUID) grouprole.GroupRole); ok {
		r0 = rf(ctx, userRole, userID, groupID)
	} else {
		r0 = ret.Get(0).(grouprole.GroupRole)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uuid.UUID, uuid.UUID) string); ok {
		r1 = rf(ctx, userRole, userID, groupID)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, uuid.UUID, uuid.UUID) error); ok {
		r2 = rf(ctx, userRole, userID, groupID)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetUserGroupAccessLevel provides a mock function with given fields: ctx, userID, groupID
func (_m *Store) GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error) {
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

// ListByIDWithUserScope provides a mock function with given fields: ctx, user, groupID
func (_m *Store) ListByIDWithUserScope(ctx context.Context, user jwt.User, groupID uuid.UUID) (grouprole.UserScope, error) {
	ret := _m.Called(ctx, user, groupID)

	if len(ret) == 0 {
		panic("no return value specified for ListByIDWithUserScope")
	}

	var r0 grouprole.UserScope
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, jwt.User, uuid.UUID) (grouprole.UserScope, error)); ok {
		return rf(ctx, user, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, jwt.User, uuid.UUID) grouprole.UserScope); ok {
		r0 = rf(ctx, user, groupID)
	} else {
		r0 = ret.Get(0).(grouprole.UserScope)
	}

	if rf, ok := ret.Get(1).(func(context.Context, jwt.User, uuid.UUID) error); ok {
		r1 = rf(ctx, user, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListWithUserScope provides a mock function with given fields: ctx, user, page, size, sort, sortBy
func (_m *Store) ListWithUserScope(ctx context.Context, user jwt.User, page int, size int, sort string, sortBy string) ([]grouprole.UserScope, int, error) {
	ret := _m.Called(ctx, user, page, size, sort, sortBy)

	if len(ret) == 0 {
		panic("no return value specified for ListWithUserScope")
	}

	var r0 []grouprole.UserScope
	var r1 int
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, jwt.User, int, int, string, string) ([]grouprole.UserScope, int, error)); ok {
		return rf(ctx, user, page, size, sort, sortBy)
	}
	if rf, ok := ret.Get(0).(func(context.Context, jwt.User, int, int, string, string) []grouprole.UserScope); ok {
		r0 = rf(ctx, user, page, size, sort, sortBy)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]grouprole.UserScope)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, jwt.User, int, int, string, string) int); ok {
		r1 = rf(ctx, user, page, size, sort, sortBy)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(context.Context, jwt.User, int, int, string, string) error); ok {
		r2 = rf(ctx, user, page, size, sort, sortBy)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Unarchive provides a mock function with given fields: ctx, groupID
func (_m *Store) Unarchive(ctx context.Context, groupID uuid.UUID) (group.Group, error) {
	ret := _m.Called(ctx, groupID)

	if len(ret) == 0 {
		panic("no return value specified for Unarchive")
	}

	var r0 group.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (group.Group, error)); ok {
		return rf(ctx, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) group.Group); ok {
		r0 = rf(ctx, groupID)
	} else {
		r0 = ret.Get(0).(group.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewStore creates a new instance of Store. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *Store {
	mock := &Store{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
