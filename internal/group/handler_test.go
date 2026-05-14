package group_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/group"
	"clustron-backend/internal/group/mocks"
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user/role"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestHandler_GetByIDHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid group ID returns group details",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {
				store.On("ListByIDWithLinks", mock.Anything, user, groupID).Return(group.ResponseWithLinks{}, nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			expectedStatus: 200,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, *tc.user, resourceID)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/groups/%s", tc.resourceID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.GetByIDHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdateTitleHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		returnedGroup  group.Group
		body           group.UpdateTitleRequest
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid group ID and title updates group title",
			setupMock: func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {
				store.On("UpdateTitle", mock.Anything, groupID, mock.Anything).Return(grouprole.GroupWithLdap{}, nil)
				store.On("GetTypeByUser", mock.Anything, user.Role, user.ID, groupID).Return(grouprole.GroupRole{}, "membership", nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			body: group.UpdateTitleRequest{
				Title: "New Group Title",
			},
			expectedStatus: 200,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.Admin.String()},
			body:           group.UpdateTitleRequest{Title: "New Group Title"},
			expectedStatus: 400,
		},
		{
			name:           "Empty title returns validation error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{Role: role.Admin.String()},
			body:           group.UpdateTitleRequest{Title: ""},
			expectedStatus: 400,
		},
		{
			name:           "Missing title in request body returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{Role: role.Admin.String()},
			customBody:     []byte(`{}`),
			expectedStatus: 400,
		},
		{
			name: "Forbidden when user does not have permission to update title",
			setupMock: func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {
				store.On("UpdateTitle", mock.Anything, groupID, mock.Anything).Return(grouprole.GroupWithLdap{}, handlerutil.ErrForbidden)
			},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.User.String()},
			body:           group.UpdateTitleRequest{Title: "New Group Title"},
			expectedStatus: 403,
		},
		{
			name:           "Missing user in context returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           nil,
			body:           group.UpdateTitleRequest{Title: "New Group Title"},
			expectedStatus: 500,
		},
		{
			name:           "Malformed JSON body returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			customBody:     []byte(`{"title": "New Group Title"`),
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, tc.user, resourceID)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s/title", tc.resourceID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.UpdateTitleHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.UpdateTitleHandler(w, r)
				}, tc.name)
			}
		})
	}
}

func TestHandler_UpdateDescriptionHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		returnedGroup  group.Group
		body           group.UpdateDescriptionRequest
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid group ID and description updates group description",
			setupMock: func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {
				store.On("UpdateDescription", mock.Anything, groupID, mock.Anything).Return(grouprole.GroupWithLdap{}, nil)
				store.On("GetTypeByUser", mock.Anything, user.Role, user.ID, groupID).Return(grouprole.GroupRole{}, "membership", nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			body: group.UpdateDescriptionRequest{
				Description: "New Group Description",
			},
			expectedStatus: 200,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.Admin.String()},
			body:           group.UpdateDescriptionRequest{Description: "New Group Description"},
			expectedStatus: 400,
		},
		{
			name:           "Empty description returns validation error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{Role: role.Admin.String()},
			body:           group.UpdateDescriptionRequest{Description: ""},
			expectedStatus: 400,
		},
		{
			name:           "Missing description in request body returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{Role: role.Admin.String()},
			customBody:     []byte(`{}`),
			expectedStatus: 400,
		},
		{
			name: "Forbidden when user does not have permission to update description",
			setupMock: func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {
				store.On("UpdateDescription", mock.Anything, groupID, mock.Anything).Return(grouprole.GroupWithLdap{}, handlerutil.ErrForbidden)
			},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.User.String()},
			body:           group.UpdateDescriptionRequest{Description: "New Group Description"},
			expectedStatus: 403,
		},
		{
			name:           "Missing user in context returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           nil,
			body:           group.UpdateDescriptionRequest{Description: "New Group Description"},
			expectedStatus: 500,
		},
		{
			name:           "Malformed JSON body returns error",
			setupMock:      func(store *mocks.Store, user *jwt.User, groupID uuid.UUID) {},
			resourceID:     uuid.New().String(),
			user:           &jwt.User{ID: uuid.New(), Role: role.Admin.String()},
			customBody:     []byte(`{"description": "New Group Description"`),
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, tc.user, resourceID)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s/description", tc.resourceID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
				h.UpdateDescriptionHandler(w, r)
				assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
			} else {
				assert.Panics(t, func() {
					h.UpdateDescriptionHandler(w, r)
				}, tc.name)
			}
		})
	}
}

func TestHandler_ArchiveHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid group ID archives group",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {
				store.On("Archive", mock.Anything, groupID).Return(group.Group{}, nil)
				store.On("GetTypeByUser", mock.Anything, user.Role, user.ID, groupID).Return(grouprole.GroupRole{}, "membership", nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			expectedStatus: 200,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, *tc.user, resourceID)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/groups/%s/arahive", tc.resourceID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.ArchiveHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UnarchiveHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID)
		resourceID     string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid group ID unarchives group",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {
				store.On("Unarchive", mock.Anything, groupID).Return(group.Group{}, nil)
				store.On("GetTypeByUser", mock.Anything, user.Role, user.ID, groupID).Return(grouprole.GroupRole{}, "membership", nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			expectedStatus: 200,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user jwt.User, groupID uuid.UUID) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, *tc.user, resourceID)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/groups/%s/unarchive", tc.resourceID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.UnarchiveHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_CreateLinkHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID, title string, url string)
		resourceID     string
		user           *jwt.User
		body           group.CreateLinkRequest
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid group ID creates link",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, title string, url string) {
				store.On("CreateLink", mock.Anything, groupID, title, url).Return(group.Link{}, nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			body: group.CreateLinkRequest{
				Title: "Test Link",
				Url:   "https://example.com",
			},
			expectedStatus: 201,
		},
		{
			name:           "Invalid group ID format returns error",
			setupMock:      func(store *mocks.Store, user jwt.User, groupID uuid.UUID, title string, url string) {},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, *tc.user, resourceID, tc.body.Title, tc.body.Url)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/groups/%s/link", tc.resourceID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.CreateLinkHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdateLinkHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID, title string, url string)
		resourceID     string
		linkID         string
		user           *jwt.User
		body           group.CreateLinkRequest
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid group and link ID updates link",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID, title string, url string) {
				store.On("UpdateLink", mock.Anything, groupID, linkID, title, url).Return(group.Link{}, nil)
			},
			resourceID: uuid.New().String(),
			linkID:     uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			body: group.CreateLinkRequest{
				Title: "Updated Link",
				Url:   "https://example.com/updated",
			},
			expectedStatus: 200,
		},
		{
			name: "Invalid group ID format returns error",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID, title string, url string) {
			},
			resourceID:     "invalid-uuid",
			linkID:         uuid.New().String(),
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
		{
			name: "Invalid link ID format returns error",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID, title string, url string) {
			},
			resourceID:     uuid.New().String(),
			linkID:         "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			groupID, err := uuid.Parse(tc.resourceID)
			linkID, err2 := uuid.Parse(tc.linkID)
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, *tc.user, groupID, linkID, tc.body.Title, tc.body.Url)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s/link/%s", tc.resourceID, tc.linkID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("link_id", tc.linkID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.UpdateLinkHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_DeleteLinkHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID)
		resourceID     string
		linkID         string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid group and link ID deletes link",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID) {
				store.On("DeleteLink", mock.Anything, groupID, linkID).Return(nil)
			},
			resourceID: uuid.New().String(),
			linkID:     uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			expectedStatus: 204,
		},
		{
			name: "Invalid group ID format returns error",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID) {
			},
			resourceID:     "invalid-uuid",
			linkID:         uuid.New().String(),
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
		{
			name: "Invalid link ID format returns error",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, linkID uuid.UUID) {
			},
			resourceID:     uuid.New().String(),
			linkID:         "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			groupID, err := uuid.Parse(tc.resourceID)
			linkID, err2 := uuid.Parse(tc.linkID)
			if tc.setupMock != nil && err == nil && err2 == nil {
				tc.setupMock(store, *tc.user, groupID, linkID)
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/groups/%s/link/%s", tc.resourceID, tc.linkID), nil)
			r.SetPathValue("group_id", tc.resourceID)
			r.SetPathValue("link_id", tc.linkID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.DeleteLinkHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_TransferGroupOwnerHandler(t *testing.T) {
	testCases := []struct {
		name           string
		setupMock      func(store *mocks.Store, user jwt.User, groupID uuid.UUID, newOwnerIdentifier string)
		resourceID     string
		user           *jwt.User
		body           group.TransferOwnerRequest
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid group ID and new owner ID transfers ownership",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, newOwnerIdentifier string) {
				store.On("TransferOwner", mock.Anything, groupID, newOwnerIdentifier, user).Return(grouprole.UserScope{}, nil)
			},
			resourceID: uuid.New().String(),
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.Admin.String(),
			},
			body: group.TransferOwnerRequest{
				Identifier: "testuser@gmail.com",
			},
			expectedStatus: 200,
		},
		{
			name: "Invalid group ID format returns error",
			setupMock: func(store *mocks.Store, user jwt.User, groupID uuid.UUID, newOwnerIdentifier string) {
			},
			resourceID:     "invalid-uuid",
			user:           &jwt.User{Role: role.User.String()},
			body:           group.TransferOwnerRequest{Identifier: ""},
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			resourceID, err := uuid.Parse(tc.resourceID)
			if tc.setupMock != nil && err == nil {
				tc.setupMock(store, *tc.user, resourceID, tc.body.Identifier)
			}

			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			h := group.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store, nil)
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/groups/%s/transfer", tc.resourceID), bytes.NewReader(requestBody))
			r.SetPathValue("group_id", tc.resourceID)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.TransferGroupOwnerHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}
