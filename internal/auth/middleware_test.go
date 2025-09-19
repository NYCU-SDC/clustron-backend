package auth_test

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth"
	"clustron-backend/internal/auth/mocks"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user/role"
	"context"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_PermissionMatrix(t *testing.T) {
	type EnforceCase struct {
		subject string
		object  string
		action  string
	}

	testCases := []struct {
		name           string
		user           jwt.User
		object         string
		action         string
		expectedStatus int
		enforceResult  bool
	}{
		{
			name:           "Admin can GET /api/v1/admin",
			user:           jwt.User{ID: uuid.New(), Role: role.Admin.String(), Email: "admin@test.com"},
			object:         "/api/v1/admin",
			action:         "GET",
			expectedStatus: http.StatusOK,
			enforceResult:  true,
		},
		{
			name:           "User forbidden to GET /api/v1/admin",
			user:           jwt.User{ID: uuid.New(), Role: role.User.String(), Email: "user@test.com"},
			object:         "/api/v1/admin",
			action:         "GET",
			expectedStatus: http.StatusForbidden,
			enforceResult:  false,
		},
		{
			name:           "User can GET /api/v1/user",
			user:           jwt.User{ID: uuid.New(), Role: role.User.String(), Email: "user@test.com"},
			object:         "/api/v1/user",
			action:         "GET",
			expectedStatus: http.StatusOK,
			enforceResult:  true,
		},
		{
			name:           "User forbidden to POST /api/v1/resource",
			user:           jwt.User{ID: uuid.New(), Role: role.User.String(), Email: "user@test.com"},
			object:         "/api/v1/resource",
			action:         "POST",
			expectedStatus: http.StatusForbidden,
			enforceResult:  false,
		},
		{
			name:           "Admin can DELETE /api/v1/resource",
			user:           jwt.User{ID: uuid.New(), Role: role.Admin.String(), Email: "admin@test.com"},
			object:         "/api/v1/resource",
			action:         "DELETE",
			expectedStatus: http.StatusOK,
			enforceResult:  true,
		},
		{
			name:           "User forbidden to DELETE /api/v1/resource",
			user:           jwt.User{ID: uuid.New(), Role: role.User.String(), Email: "user@test.com"},
			object:         "/api/v1/resource",
			action:         "DELETE",
			expectedStatus: http.StatusForbidden,
			enforceResult:  false,
		},
	}

	logger, err := logutil.ZapDevelopmentConfig().Build()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	problemWriter := internal.NewProblemWriter()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enforcer := mocks.NewCasbinEnforcer(t)
			enforcer.On("Enforce", tc.user.Role, tc.object, tc.action).Return(tc.enforceResult, nil)
			middleware := auth.NewMiddleware(logger, enforcer, problemWriter)
			handler := middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			r := httptest.NewRequest(tc.action, tc.object, nil)
			r = r.WithContext(context.WithValue(r.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			handler(w, r)

			res := w.Result()
			if res.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, res.StatusCode)
			}
		})
	}
}
