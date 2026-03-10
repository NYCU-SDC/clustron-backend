package grouprole_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"clustron-backend/internal/grouprole"
	grouprolemocks "clustron-backend/internal/grouprole/mocks"
)

func TestHandler_CreateHandler(t *testing.T) {
	testCases := []struct {
		name           string
		request        grouprole.CreateRequest
		setupMock      func(store *grouprolemocks.Store)
		expectedStatus int
	}{
		{
			name:    "Create success",
			request: grouprole.CreateRequest{RoleName: "test", AccessLevel: "GROUP_OWNER"},
			setupMock: func(store *grouprolemocks.Store) {
				store.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(
					grouprole.GroupRole{ID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), RoleName: "test", AccessLevel: "GROUP_OWNER"}, nil,
				)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:    "Create store error",
			request: grouprole.CreateRequest{RoleName: "fail", AccessLevel: "GROUP_OWNER"},
			setupMock: func(store *grouprolemocks.Store) {
				store.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(grouprole.GroupRole{}, errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(grouprolemocks.Store)
			if tc.setupMock != nil {
				tc.setupMock(store)
			}
			logger := zap.NewNop()
			h := grouprole.NewHandler(logger, validator.New(), problem.New(), store)

			body, _ := json.Marshal(tc.request)
			r := httptest.NewRequest(http.MethodPost, "/grouprole", bytes.NewReader(body))
			w := httptest.NewRecorder()

			h.CreateHandler(w, r)

			resp := w.Result()
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}
