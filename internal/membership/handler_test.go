package membership_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/membership"
	"clustron-backend/internal/membership/mocks"
	"clustron-backend/internal/user/role"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestHandler_AddGroupMemberHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID, addMembersRequest membership.AddMembersRequest)
		body           membership.AddMembersRequest
		resourceID     string
		user           *jwt.User
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid request adds group member",
			body: membership.AddMembersRequest{
				Members: []membership.AddMemberRequest{
					{
						Member: "testuser@gmail.com",
						Role:   uuid.New(),
					},
				},
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			resourceID: uuid.New().String(),
			setupMock: func(store *mocks.Store, groupID uuid.UUID, addMembersRequest membership.AddMembersRequest) {
				for _, member := range addMembersRequest.Members {
					store.On("Add", mock.Anything, groupID, member.Member, member.Role).Return(membership.MemberResponse{
						ID: uuid.New(),
					}, nil).Once()
				}
			},
			expectedStatus: 200,
		},
		{
			name: "Invalid resource ID returns bad request",
			body: membership.AddMembersRequest{
				Members: []membership.AddMemberRequest{
					{
						Member: "",
						Role:   uuid.New(),
					},
				},
			},
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			resourceID:     "invalid-uuid",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, addMembersRequest membership.AddMembersRequest) {},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, resourceID, tc.body)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/groups/%s/members", tc.resourceID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.AddGroupMemberHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_RemoveGroupMemberHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID)
		resourceID     string
		memberID       string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid request removes group member",
			setupMock: func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {
				store.On("Remove", mock.Anything, groupID, memberID).Return(nil).Once()
			},
			resourceID:     uuid.New().String(),
			memberID:       uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			memberID:       uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
		{
			name:           "Invalid member ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			memberID:       "invalid-uuid",
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			memberID, err2 := uuid.Parse(tc.memberID)
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, resourceID, memberID)
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/groups/%s/members/%s", tc.resourceID, tc.memberID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("user_id", tc.memberID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.RemoveGroupMemberHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdateGroupMemberHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, newRoleID uuid.UUID)
		resourceID     string
		memberID       string
		body           membership.UpdateMemberRequest
		user           *jwt.User
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid request updates group member role",
			setupMock: func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, newRoleID uuid.UUID) {
				store.On("Update", mock.Anything, groupID, memberID, newRoleID).Return(membership.MemberResponse{
					ID: memberID,
				}, nil).Once()
			},
			resourceID:     uuid.New().String(),
			memberID:       uuid.New().String(),
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, newRoleID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			memberID:       uuid.New().String(),
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
		{
			name:           "Invalid member ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, newRoleID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			memberID:       "invalid-uuid",
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			memberID, err2 := uuid.Parse(tc.memberID)
			newRoleID := tc.body.Role
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, resourceID, memberID, newRoleID)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s/members/%s", tc.resourceID, tc.memberID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("user_id", tc.memberID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.UpdateGroupMemberHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_ListGroupMembersPagedHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid request lists group members",
			setupMock: func(store *mocks.Store, groupID uuid.UUID) {
				store.On("ListWithPaged", mock.Anything, groupID, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]membership.MemberResponse{
					{
						ID: uuid.New(),
					},
				}, nil).Once()
				store.On("CountByGroupID", mock.Anything, groupID).Return(int64(1), nil).Once()
			},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, resourceID)
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/groups/%s/members", tc.resourceID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			r.URL.Query().Add("page", "1")
			r.URL.Query().Add("size", "10")
			r.URL.Query().Add("sortBy", "id")
			r.URL.Query().Add("sortDirection", "asc")
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.ListGroupMembersPagedHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_ListPendingMembersPagedHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid request lists pending group members",
			setupMock: func(store *mocks.Store, groupID uuid.UUID) {
				store.On("ListPendingWithPaged", mock.Anything, groupID, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]membership.PendingMemberResponse{
					{
						ID: uuid.New(),
					},
				}, nil).Once()
				store.On("CountPendingByGroupID", mock.Anything, groupID).Return(int64(1), nil).Once()
			},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, resourceID)
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/groups/%s/pendingMembers", tc.resourceID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			r.URL.Query().Add("page", "1")
			r.URL.Query().Add("size", "10")
			r.URL.Query().Add("sortBy", "id")
			r.URL.Query().Add("sortDirection", "asc")
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.ListPendingMembersPagedHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdatePendingMemberHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, role uuid.UUID)
		resourceID     string
		memberID       string
		body           membership.UpdateMemberRequest
		user           *jwt.User
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid request approves pending member",
			setupMock: func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, role uuid.UUID) {
				store.On("UpdatePending", mock.Anything, groupID, memberID, role).Return(membership.PendingMemberResponse{
					ID: memberID,
				}, nil).Once()
			},
			resourceID:     uuid.New().String(),
			memberID:       uuid.New().String(),
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, role uuid.UUID) {},
			resourceID:     "invalid-uuid",
			memberID:       uuid.New().String(),
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
		{
			name:           "Invalid member ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID, role uuid.UUID) {},
			resourceID:     uuid.New().String(),
			memberID:       "invalid-uuid",
			body:           membership.UpdateMemberRequest{Role: uuid.New()},
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			memberID, err2 := uuid.Parse(tc.memberID)
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, resourceID, memberID, tc.body.Role)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s/pendingMembers/%s/", tc.resourceID, tc.memberID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("pending_id", tc.memberID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.UpdatePendingMemberHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_RemovePendingMemberHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID)
		resourceID     string
		memberID       string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid request removes pending member",
			setupMock: func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {
				store.On("RemovePending", mock.Anything, groupID, memberID).Return(nil).Once()
			},
			resourceID:     uuid.New().String(),
			memberID:       uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 200,
		},
		{
			name:           "Invalid resource ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			memberID:       uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
		{
			name:           "Invalid member ID returns bad request",
			setupMock:      func(store *mocks.Store, groupID uuid.UUID, memberID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			memberID:       "invalid-uuid",
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := &mocks.Store{}

			resourceID, err := uuid.Parse(tc.resourceID)
			memberID, err2 := uuid.Parse(tc.memberID)
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, resourceID, memberID)
			}

			h := membership.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/groups/%s/pendingMembers/%s/", tc.resourceID, tc.memberID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("pending_id", tc.memberID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.RemovePendingMemberHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}
