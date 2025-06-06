// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	context "context"

	membership "clustron-backend/internal/membership"

	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// MemberStore is an autogenerated mock type for the MemberStore type
type MemberStore struct {
	mock.Mock
}

// Add provides a mock function with given fields: ctx, groupId, memberIdentifier, role
func (_m *MemberStore) Add(ctx context.Context, groupId uuid.UUID, memberIdentifier string, role uuid.UUID) (membership.JoinResult, error) {
	ret := _m.Called(ctx, groupId, memberIdentifier, role)

	if len(ret) == 0 {
		panic("no return value specified for Add")
	}

	var r0 membership.JoinResult
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string, uuid.UUID) (membership.JoinResult, error)); ok {
		return rf(ctx, groupId, memberIdentifier, role)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string, uuid.UUID) membership.JoinResult); ok {
		r0 = rf(ctx, groupId, memberIdentifier, role)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(membership.JoinResult)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string, uuid.UUID) error); ok {
		r1 = rf(ctx, groupId, memberIdentifier, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Join provides a mock function with given fields: ctx, userId, groupId, role
func (_m *MemberStore) Join(ctx context.Context, userId uuid.UUID, groupId uuid.UUID, role uuid.UUID) (membership.MemberResponse, error) {
	ret := _m.Called(ctx, userId, groupId, role)

	if len(ret) == 0 {
		panic("no return value specified for Join")
	}

	var r0 membership.MemberResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (membership.MemberResponse, error)); ok {
		return rf(ctx, userId, groupId, role)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) membership.MemberResponse); ok {
		r0 = rf(ctx, userId, groupId, role)
	} else {
		r0 = ret.Get(0).(membership.MemberResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, userId, groupId, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Remove provides a mock function with given fields: ctx, groupID, userID
func (_m *MemberStore) Remove(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error {
	ret := _m.Called(ctx, groupID, userID)

	if len(ret) == 0 {
		panic("no return value specified for Remove")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) error); ok {
		r0 = rf(ctx, groupID, userID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Update provides a mock function with given fields: ctx, groupID, userID, role
func (_m *MemberStore) Update(ctx context.Context, groupID uuid.UUID, userID uuid.UUID, role uuid.UUID) (membership.MemberResponse, error) {
	ret := _m.Called(ctx, groupID, userID, role)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 membership.MemberResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (membership.MemberResponse, error)); ok {
		return rf(ctx, groupID, userID, role)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) membership.MemberResponse); ok {
		r0 = rf(ctx, groupID, userID, role)
	} else {
		r0 = ret.Get(0).(membership.MemberResponse)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, groupID, userID, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewMemberStore creates a new instance of MemberStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMemberStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *MemberStore {
	mock := &MemberStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
