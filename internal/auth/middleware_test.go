package auth_test

import (
	"clustron-backend/internal"
	"clustron-backend/internal/auth"
	"clustron-backend/internal/auth/mocks"
	"clustron-backend/internal/user"
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_HandlerFunc(t *testing.T) {
	testCase := []struct {
		name           string
		user           user.User
		expectedStatus int
		expectError    bool
		enforcer       mocks.CasbinEnforcer
	}{
		{
			name: "Should return 200 when token is valid",
			user: user.User{
				ID:   uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
				Role: "user",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	// Mock the dependencies
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	problemWriter := internal.NewProblemWriter()

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			enforcer := mocks.NewCasbinEnforcer(t)
			enforcer.On("Enforce", tc.user.Role, "/api/v1/user", "GET").Return(true, nil)

			middleware := auth.NewMiddleware(logger, enforcer, problemWriter)
			handler := middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
			req = req.WithContext(context.WithValue(req.Context(), internal.UserContextKey, tc.user))
			w := httptest.NewRecorder()

			handler(w, req)

			res := w.Result()
			if res.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, res.StatusCode)
			}
		})
	}

}
