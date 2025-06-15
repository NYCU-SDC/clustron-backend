package membership_test

// import (
// 	"clustron-backend/internal/grouprole"
// 	"clustron-backend/internal/membership"
// 	"clustron-backend/internal/membership/mocks"
// 	"clustron-backend/internal/user"
// 	"clustron-backend/internal/user/role"
// 	"context"
// 	"testing"

// 	"github.com/google/uuid"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// var mockUserId = uuid.New()

// func TestService_Join(t *testing.T) {
// 	userStore := mocks.NewUserStore(t)
// 	settingStore := mocks.NewSettingStore(t)
// 	groupRoleStore := mocks.NewGroupRoleStore(t)

// 	testCases := []struct {
// 		name           string
// 		userId         uuid.UUID
// 		groupId        uuid.UUID
// 		role           uuid.UUID
// 		mockSetup      func()
// 		expectedError  error
// 		expectedResult membership.JoinResult
// 	}{
// 		{
// 			name:    "Should join group successfully",
// 			userId:  mockUserId,
// 			groupId: uuid.New(),
// 			role:    uuid.New(),
// 			mockSetup: func() {
// 				// Mock user info & setting & group role
// 				userStore.On("GetByID", mock.Anything, mock.Anything).Return(
// 					user.User{ID: mockUserId, Email: "test@gmail.com", RoleName: role.User.String()}, nil, nil, nil)
// 				// u, err := s.userStore.GetByID(traceCtx, userId)
// 				// setting, err := s.settingStore.GetSettingByUserID(traceCtx, userId)
// 				// roleResponse, err := s.groupRoleStore.GetByID(traceCtx, member.RoleID)
// 			},
// 			expectedError: nil,
// 		},
// 	}

// 	service := membership.NewService(nil, nil, userStore, groupRoleStore, nil)
// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Setup mocks for this test case
// 			tc.mockSetup()

// 			// Execute test
// 			result, err := service.Join(context.Background(), tc.userId, tc.groupId, tc.role)

// 			// Assertions
// 			if tc.expectedError != nil {
// 				assert.ErrorIs(t, err, tc.expectedError)
// 			} else {
// 				assert.NoError(t, err)
// 				assert.NotNil(t, result)
// 			}
// 		})
// 	}
// }

// func TestService_Add(t *testing.T) {
// 	userStore := mocks.NewUserStore(t)
// 	groupRoleStore := mocks.NewGroupRoleStore(t)
// 	membershipStore := mocks.NewMembershipStore(t)

// 	// Test cases
// 	testCases := []struct {
// 		name             string
// 		userId           uuid.UUID
// 		groupId          uuid.UUID
// 		memberIdentifier string
// 		roleId           uuid.UUID
// 		mockSetup        func()
// 		expectedError    error
// 		expectedResult   membership.JoinResult
// 	}{
// 		{
// 			name:             "Should add member successfully",
// 			userId:           mockUserId,
// 			groupId:          uuid.New(),
// 			memberIdentifier: "test@google.com",
// 			roleId:           uuid.New(),
// 			mockSetup: func() {
// 				// Mock
// 				groupRoleStore.On("getByID", mock.Anything, mock.Anything).Return(grouprole.GroupRole{}, nil)

// 				// Mock user exists check
// 				userStore.On("ExistsByIdentifier", mock.Anything, "test@google.com").Return(true, nil)
// 				userStore.On("GetIdByEmail", mock.Anything, "test@google.com").Return(mockUserId, nil)

// 				// Mock Join

// 			},
// 			expectedError: nil,
// 		},
// 		// {
// 		// 	name:             "Should reject adding group owner",
// 		// 	userId:           uuid.New(),
// 		// 	groupId:          uuid.New(),
// 		// 	memberIdentifier: "test@google.com",
// 		// 	roleId:           uuid.New(),
// 		// 	mockSetup: func() {
// 		// 		// Mock access control check
// 		// 		store.On("IsGroupOwner", mock.Anything, mock.Anything).Return(true)
// 		// 	},
// 		// 	expectedError: handlerutil.ErrForbidden,
// 		// },
// 		// {
// 		// 	name:             "Should add pending member when user doesn't exist",
// 		// 	userId:           uuid.New(),
// 		// 	groupId:          uuid.New(),
// 		// 	memberIdentifier: "nonexistent@google.com",
// 		// 	roleId:           uuid.New(),
// 		// 	mockSetup: func() {
// 		// 		// Mock access control check
// 		// 		store.On("IsGroupOwner", mock.Anything, mock.Anything).Return(false)
// 		// 		store.On("HasGroupControlAccess", mock.Anything, mock.Anything, mock.Anything).Return(true)
// 		// 		store.On("CanAssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)

// 		// 		// Mock user exists check
// 		// 		userStore.On("ExistsByIdentifier", mock.Anything, "test@google.com").Return(false, nil)

// 		// 		// Mock JoinPending
// 		// 		store.On("JoinPending", mock.Anything, mock.Anything).Return(membership.PendingGroupMember{
// 		// 			ID:             uuid.New(),
// 		// 			UserIdentifier: "nonexistent@google.com",
// 		// 			GroupID:        uuid.New(),
// 		// 			RoleID:         uuid.New(),
// 		// 		}, nil)
// 		// 	},
// 		// 	expectedError: nil,
// 		// },
// 	}
// 	service := membership.NewService(nil, nil, userStore, groupRoleStore, nil)
// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			// Setup mocks for this test case
// 			tc.mockSetup()

// 			// Execute test
// 			result, err := service.Add(context.Background(), tc.userId, tc.groupId, tc.memberIdentifier, tc.roleId)

// 			// Assertions
// 			if tc.expectedError != nil {
// 				assert.ErrorIs(t, err, tc.expectedError)
// 			} else {
// 				assert.NoError(t, err)
// 				assert.NotNil(t, result)
// 			}
// 		})
// 	}
// }
