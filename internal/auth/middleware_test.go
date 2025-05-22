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

func TestMiddleware_HandlerFunc(t *testing.T) {
	type EnforceCase struct {
		subject string
		object  string
		action  string
	}

	testCase := []struct {
		name           string
		user           jwt.User
		expectedStatus int
		expectError    bool
		enforceCase    EnforceCase
	}{
		{
			name: "Should return 200 when token is valid",
			user: jwt.User{
				ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
				Role:  "user",
				Email: "test@gmail.com",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
			enforceCase: EnforceCase{
				subject: role.User.String(),
				object:  "/api/v1/user",
				action:  "GET",
			},
		},
		{
			name: "Should return 403 when does not have permission",
			user: jwt.User{
				ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
				Role:  role.User.String(),
				Email: "test@gmail.com",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
			enforceCase: EnforceCase{
				subject: role.User.String(),
				object:  "/api/v1/user",
				action:  "GET",
			},
		},
	}

	// Mock the dependencies
	logger, err := logutil.ZapDevelopmentConfig().Build()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	problemWriter := internal.NewProblemWriter()

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			enforcer := mocks.NewCasbinEnforcer(t)
			enforcer.On("Enforce", tc.enforceCase.subject, tc.enforceCase.object, tc.enforceCase.action).Return(tc.expectedStatus == http.StatusOK, nil)

			middleware := auth.NewMiddleware(logger, enforcer, problemWriter)
			handler := middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			r := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
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
