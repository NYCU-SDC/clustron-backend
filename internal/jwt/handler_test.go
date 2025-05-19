package jwt_test

import (
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/jwt/mocks"
	"fmt"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
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

func Test_RefreshTokenHandler(t *testing.T) {
	testCase := []struct {
		name           string
		query          string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "Should return 200 when refresh token is valid",
			query:          "7942c917-4770-43c1-a56a-952186b9970e",
			expectedStatus: http.StatusOK,
			expectError:    false,
		}, {
			name:           "Should return error when refresh token is empty",
			query:          "33a40641-45bb-4b47-aa33-113c7c562328",
			expectedStatus: http.StatusNotFound,
			expectError:    true,
		}, {
			name:           "Should return error when refresh token is invalid",
			query:          "a",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	// Mock the dependencies
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	problemWriter := internal.NewProblemWriter()

	issuer := mocks.NewJWTIssuer(t)

	jwtUser := jwt.User{
		ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
		Email: "testuser@testuser.com",
		Role:  "user",
	}

	issuer.On("GetUserByRefreshToken",
		mock.Anything,
		uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e"),
	).Return(jwtUser, nil)

	issuer.On("GetUserByRefreshToken",
		mock.Anything,
		mock.Anything,
	).Return(jwt.User{}, fmt.Errorf("%w", handlerutil.NewNotFoundError("refresh_token", "mock key", "mock value", "mock message")))

	issuer.On("New", mock.Anything, jwtUser).Return("123", nil)

	issuer.On("GenerateRefreshToken", mock.Anything, jwtUser).Return(jwt.RefreshToken{
		ID:             uuid.MustParse("257f5ce3-8c87-40df-b012-73e9a5820780"),
		UserID:         uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
		IsActive:       pgtype.Bool{Bool: true},
		ExpirationDate: pgtype.Timestamptz{Time: time.Now()},
	}, nil)

	issuer.On("InactivateRefreshToken", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(nil)

	h := jwt.NewHandler(logger, validator.New(), problemWriter, issuer)

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			query := tc.query
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/refreshToken/%s", query), nil)
			w := httptest.NewRecorder()

			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/refreshToken/{refreshToken}", h.RefreshToken)

			mux.ServeHTTP(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}

}
