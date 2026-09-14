package systemgroup_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustron-backend/internal"
	"clustron-backend/internal/systemgroup"
	"clustron-backend/internal/systemgroup/mocks"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newHandler(store *mocks.Store) *systemgroup.Handler {
	return systemgroup.NewHandler(zap.NewNop(), validator.New(), internal.NewProblemWriter(), store)
}

func TestHandler_RegisterHandler(t *testing.T) {
	id := uuid.New()
	testCases := []struct {
		name           string
		body           string
		setupMock      func(store *mocks.Store)
		expectedStatus int
	}{
		{
			name: "created",
			body: `{"name":"docker"}`,
			setupMock: func(store *mocks.Store) {
				store.On("Register", mock.Anything, "docker", "").Return(systemgroup.SystemGroup{ID: id, Name: "docker", GidNumber: 999}, nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "missing name",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "denylisted",
			body: `{"name":"sudo"}`,
			setupMock: func(store *mocks.Store) {
				store.On("Register", mock.Anything, "sudo", "").Return(systemgroup.SystemGroup{}, internal.ErrSystemGroupDenied)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "inconsistent gid",
			body: `{"name":"video"}`,
			setupMock: func(store *mocks.Store) {
				store.On("Register", mock.Anything, "video", "").Return(systemgroup.SystemGroup{},
					internal.ErrSystemGroupGIDInconsistent{Name: "video", GIDs: map[int64][]string{44: {"node01"}, 45: {"node02"}}})
			},
			expectedStatus: http.StatusConflict,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(mocks.Store)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/systemGroups", bytes.NewBufferString(tc.body))
			w := httptest.NewRecorder()

			newHandler(store).RegisterHandler(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, w.Body.String())
			if tc.setupMock == nil {
				store.AssertNotCalled(t, "Register", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestHandler_DiscoverHandler(t *testing.T) {
	store := new(mocks.Store)
	store.On("Discover", mock.Anything).Return()
	w := httptest.NewRecorder()

	newHandler(store).DiscoverHandler(w, httptest.NewRequest(http.MethodPost, "/api/systemGroups/discover", nil))

	assert.Equal(t, http.StatusAccepted, w.Code)
	store.AssertCalled(t, "Discover", mock.Anything)
}

func TestHandler_AddMemberHandler(t *testing.T) {
	groupID, userID := uuid.New(), uuid.New()

	t.Run("invalid user id", func(t *testing.T) {
		store := new(mocks.Store)
		r := httptest.NewRequest(http.MethodPost, "/api/systemGroups/x/members", bytes.NewBufferString(`{"userId":"nope"}`))
		r.SetPathValue("id", groupID.String())
		w := httptest.NewRecorder()

		newHandler(store).AddMemberHandler(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		store.AssertNotCalled(t, "AddMember", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("added", func(t *testing.T) {
		store := new(mocks.Store)
		store.On("AddMember", mock.Anything, groupID, userID).Return(nil)
		r := httptest.NewRequest(http.MethodPost, "/api/systemGroups/x/members", bytes.NewBufferString(`{"userId":"`+userID.String()+`"}`))
		r.SetPathValue("id", groupID.String())
		w := httptest.NewRecorder()

		newHandler(store).AddMemberHandler(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	})

	t.Run("user without ldap account", func(t *testing.T) {
		store := new(mocks.Store)
		store.On("AddMember", mock.Anything, groupID, userID).Return(internal.ErrUserHasNoLDAPAccount)
		r := httptest.NewRequest(http.MethodPost, "/api/systemGroups/x/members", bytes.NewBufferString(`{"userId":"`+userID.String()+`"}`))
		r.SetPathValue("id", groupID.String())
		w := httptest.NewRecorder()

		newHandler(store).AddMemberHandler(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_RemoveMemberHandler(t *testing.T) {
	groupID, userID := uuid.New(), uuid.New()
	store := new(mocks.Store)
	store.On("RemoveMember", mock.Anything, groupID, userID).Return(nil)
	r := httptest.NewRequest(http.MethodDelete, "/api/systemGroups/x/members/y", nil)
	r.SetPathValue("id", groupID.String())
	r.SetPathValue("user_id", userID.String())
	w := httptest.NewRecorder()

	newHandler(store).RemoveMemberHandler(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
}

func TestHandler_ListCandidatesHandler(t *testing.T) {
	store := new(mocks.Store)
	store.On("ListCandidates", mock.Anything).Return([]systemgroup.Candidate{{
		Name: "docker", Consistent: true, GIDNumber: 999,
		GIDs:           []systemgroup.GIDServers{{GIDNumber: 999, Servers: []string{"node01"}}},
		MissingServers: []string{},
	}}, nil)
	w := httptest.NewRecorder()

	newHandler(store).ListCandidatesHandler(w, httptest.NewRequest(http.MethodGet, "/api/systemGroups/candidates", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 1)
	assert.Equal(t, "docker", got[0]["name"])
	assert.Equal(t, float64(999), got[0]["gidNumber"])
	assert.Equal(t, []any{}, got[0]["missingServers"])
}
