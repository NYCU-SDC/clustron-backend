package group_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/NYCU-SDC/clustron-backend/internal"
	"github.com/NYCU-SDC/clustron-backend/internal/group"
	"github.com/NYCU-SDC/clustron-backend/internal/group/mocks"
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandler_CreateHandler(t *testing.T) {
	testCases := []struct {
		name       string
		user       jwt.User
		body       group.CreateRequest
		wantStatus int
	}{
		{
			name: "Should create group for admin",
			user: jwt.User{
				Role: pgtype.Text{String: "admin", Valid: true},
			},
			body: group.CreateRequest{
				Title:       "Test Group",
				Description: "Test Description",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "Should create group for organizer",
			user: jwt.User{
				Role: pgtype.Text{String: "organizer", Valid: true},
			},
			body: group.CreateRequest{
				Title:       "Test Group",
				Description: "Test Description",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "Should not create group for user",
			user: jwt.User{
				Role: pgtype.Text{String: "user", Valid: true},
			},
			body: group.CreateRequest{
				Title:       "Test Group",
				Description: "Test Description",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	store.On("CreateGroup", mock.Anything, mock.Anything).Return(group.Group{
		ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
		Title:       "Test Group",
		Description: pgtype.Text{String: "Test Description", Valid: true},
		IsArchived:  pgtype.Bool{Valid: true},
		CreatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
		UpdatedAt:   pgtype.Timestamptz{Time: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)},
	}, nil)
	auth := mocks.NewAuth(t)

	h := group.NewHandler(validator.New(), logger, store, auth)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodPost, "/groups", bytes.NewReader(requestBody))
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.CreateHandler(w, r)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}
