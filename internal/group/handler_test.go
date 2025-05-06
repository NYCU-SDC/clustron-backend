package group_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/NYCU-SDC/clustron-backend/internal"
	"github.com/NYCU-SDC/clustron-backend/internal/group"
	"github.com/NYCU-SDC/clustron-backend/internal/group/mocks"
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

func TestHandler_GetAllHandler(t *testing.T) {
	groups := []group.Group{
		// organizer, and user in this group
		{
			ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
			Title:       "Test Group 1",
			Description: pgtype.Text{String: "Test Description 1", Valid: true},
		},
		// organizer in this group
		{
			ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970f"),
			Title:       "Test Group 2",
			Description: pgtype.Text{String: "Test Description 2", Valid: true},
		},
		{
			ID:          uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970a"),
			Title:       "Test Group 3",
			Description: pgtype.Text{String: "Test Description 3", Valid: true},
		},
	}

	testCases := []struct {
		name       string
		user       jwt.User
		wantStatus int
		wantResult []string
	}{
		{
			name: "Should get all groups for admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
				Role: pgtype.Text{String: "admin", Valid: true},
			},
			wantStatus: http.StatusOK,
			wantResult: []string{
				"Test Group 1",
				"Test Group 2",
				"Test Group 3",
			},
		},
		{
			name: "Should get limited groups for organizer",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
				Role: pgtype.Text{String: "organizer", Valid: true},
			},
			wantStatus: http.StatusOK,
			wantResult: []string{
				"Test Group 1",
				"Test Group 2",
			},
		},
		{
			name: "Should get limited groups for user",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusOK,
			wantResult: []string{
				"Test Group 1",
			},
		},
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)

	// When admin call GetAll
	store.On("GetAll", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups, nil)
	store.On("GetAllGroupCount", mock.Anything).Return(len(groups), nil)

	// When organizer call GetAll
	store.On("GetByUserId", mock.Anything, testCases[1].user.ID, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups[0:2], nil)
	store.On("GetUserGroupsCount", mock.Anything, testCases[1].user.ID).Return(2, nil)

	// When user call GetAll
	store.On("GetByUserId", mock.Anything, testCases[2].user.ID, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(groups[0:1], nil)
	store.On("GetUserGroupsCount", mock.Anything, testCases[2].user.ID).Return(1, nil)

	auth := mocks.NewAuth(t)

	h := group.NewHandler(validator.New(), logger, store, auth)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/groups", nil)
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.GetAllHandler(w, r)

			assert.Equal(t, tc.wantStatus, w.Code)

			var got pagination.Response[group.Response]
			err := json.Unmarshal(w.Body.Bytes(), &got)
			if err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for i, g := range got.Items {
				assert.Equal(t, tc.wantResult[i], g.Title)
			}
		})
	}
}

func TestHandler_GetByIdHandler(t *testing.T) {
	groupId := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")
	testCases := []struct {
		name       string
		user       jwt.User
		wantStatus int
	}{
		{
			name: "Should get group for admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
				Role: pgtype.Text{String: "admin", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should get group for user in this group",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should not get group for user not in this group",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusNotFound,
		},
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	// Directly get group by ID
	store.On("GetById", mock.Anything, groupId).Return(group.Group{
		Title:       "Test Group",
		Description: pgtype.Text{String: "Test Description", Valid: true},
	}, nil)

	// Get group by ID for user in this group
	store.On("FindUserGroupById", mock.Anything, testCases[1].user.ID, groupId).Return(group.Group{
		Title:       "Test Group",
		Description: pgtype.Text{String: "Test Description", Valid: true},
	}, nil)

	// Get group by ID for user not in this group
	store.On("FindUserGroupById", mock.Anything, testCases[2].user.ID, groupId).Return(group.Group{},
		databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", "(user_id, group_id)", fmt.Sprintf("(%s, %s)", testCases[2].user.ID.String(), groupId), logger, "get membership"))

	auth := mocks.NewAuth(t)

	h := group.NewHandler(validator.New(), logger, store, auth)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/groups/%s", groupId.String()), nil)
			r.SetPathValue("group_id", groupId.String())
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.GetByIdHandler(w, r)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestHandler_ArchiveHandler(t *testing.T) {
	groupId := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")

	testCases := []struct {
		name       string
		user       jwt.User
		wantStatus int
	}{
		{
			name: "Should archive group for admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
				Role: pgtype.Text{String: "admin", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should archive group for organizer",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
				Role: pgtype.Text{String: "organizer", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should not archive group for organizer not in this group",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "Should not archive group for group-admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Should not archive group for user",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusForbidden,
		},
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	store.On("ArchiveGroup", mock.Anything, mock.Anything).Return(group.Group{
		Title:       "Test Group",
		Description: pgtype.Text{String: "Test Description", Valid: true},
	}, nil)

	auth := mocks.NewAuth(t)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[1].user.ID, groupId).Return(
		"organizer", nil)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[2].user.ID, groupId).Return(
		"", databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", testCases[2].user.ID.String(), groupId.String()), logger, "get membership"))
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[3].user.ID, groupId).Return(
		"group-admin", nil)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[4].user.ID, groupId).Return(
		"user", nil)

	h := group.NewHandler(validator.New(), logger, store, auth)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/groups/%s/archive", groupId.String()), nil)
			r.SetPathValue("group_id", groupId.String())
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.ArchiveHandler(w, r)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestHandler_UnarchiveHandler(t *testing.T) {
	groupId := uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")

	testCases := []struct {
		name       string
		user       jwt.User
		wantStatus int
	}{
		{
			name: "Should unarchive group for admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e9"),
				Role: pgtype.Text{String: "admin", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should unarchive group for organizer",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e3"),
				Role: pgtype.Text{String: "organizer", Valid: true},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Should not unarchive group for organizer not in this group",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e5"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "Should not unarchive group for group-admin",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e7"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Should not unarchive group for user",
			user: jwt.User{
				ID:   uuid.MustParse("a9e0fd99-10de-4ad1-b519-e8430ed089e2"),
				Role: pgtype.Text{String: "user", Valid: true},
			},
			wantStatus: http.StatusForbidden,
		},
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	store := mocks.NewStore(t)
	store.On("UnarchiveGroup", mock.Anything, mock.Anything).Return(group.Group{
		Title:       "Test Group",
		Description: pgtype.Text{String: "Test Description", Valid: true},
	}, nil)

	auth := mocks.NewAuth(t)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[1].user.ID, groupId).Return(
		"organizer", nil)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[2].user.ID, groupId).Return(
		"", databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", testCases[2].user.ID.String(), groupId.String()), logger, "get membership"))
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[3].user.ID, groupId).Return(
		"group-admin", nil)
	auth.On("GetUserGroupAccessLevel", mock.Anything, testCases[4].user.ID, groupId).Return(
		"user", nil)

	h := group.NewHandler(validator.New(), logger, store, auth)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/groups/%s/unarchive", groupId.String()), nil)
			r.SetPathValue("group_id", groupId.String())
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			h.UnarchiveHandler(w, r)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}
