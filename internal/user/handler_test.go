package user_test

import (
	"bytes"
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/mocks"
	"clustron-backend/internal/user/role"
	"context"
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_GetMeHandler(t *testing.T) {
	testCases := []struct {
		name           string
		user           *jwt.User
		expectedStatus int
	}{
		{
			name: "Valid request returns user info",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing user in context returns error",
			user:           nil,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)

			h := user.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store)
			r := httptest.NewRequest(http.MethodPost, "/api/users/me", nil)
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.GetMeHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}

func TestHandler_UpdateFullNameHandler(t *testing.T) {
	testCases := []struct {
		name           string
		body           user.UpdateFullNameRequest
		user           *jwt.User
		setupMock      func(store *mocks.Store, userID uuid.UUID, fullName string)
		customBody     []byte
		expectedStatus int
	}{
		{
			name: "Valid request updates full name",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			body: user.UpdateFullNameRequest{
				FullName: "New Full Name",
			},
			setupMock: func(store *mocks.Store, userID uuid.UUID, fullName string) {
				store.On("UpdateFullName", mock.Anything, userID, mock.Anything).Return(user.User{
					ID:       userID,
					FullName: pgtype.Text{String: fullName, Valid: true},
				}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid full name length returns validation error",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			body: user.UpdateFullNameRequest{
				FullName: "",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid full name length returns validation error",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			body: user.UpdateFullNameRequest{
				FullName: string(make([]byte, 300)),
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty full name returns validation error",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			body: user.UpdateFullNameRequest{
				FullName: " ",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing user in context returns error",
			user: nil,
			body: user.UpdateFullNameRequest{
				FullName: "New Full Name",
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Malformed JSON body returns error",
			user: &jwt.User{
				ID:   uuid.New(),
				Role: role.User.String(),
			},
			customBody:     []byte(`{"full_name": "New Full Name"`),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			store := mocks.NewStore(t)
			if tc.setupMock != nil && tc.user != nil {
				tc.setupMock(store, tc.user.ID, tc.body.FullName)
			}
			h := user.NewHandler(logger, validator.New(), internal.NewProblemWriter(), store)
			var requestBody []byte
			if tc.customBody != nil {
				requestBody = tc.customBody
			} else {
				requestBody, err = json.Marshal(tc.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}
			r := httptest.NewRequest(http.MethodPut, "/api/users/fullname", bytes.NewReader(requestBody))
			w := httptest.NewRecorder()
			if tc.user != nil {
				r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, *tc.user))
			}

			h.UpdateFullNameHandler(w, r)
			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}
