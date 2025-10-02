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
	testCases := []struct {
		name           string
		query          string
		setupMock      func(issuer *mocks.JWTIssuer)
		expectedStatus int
	}{
		{
			name:  "Should return 200 when refresh token is valid",
			query: "7942c917-4770-43c1-a56a-952186b9970e",
			setupMock: func(issuer *mocks.JWTIssuer) {
				jwtUser := jwt.User{
					ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					Email: "testuser@testuser.com",
					Role:  "user",
				}
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(jwtUser, nil)
				issuer.On("New", mock.Anything, jwtUser).Return("123", nil)
				issuer.On("GenerateRefreshToken", mock.Anything, jwtUser).Return(jwt.RefreshToken{
					ID:             uuid.MustParse("257f5ce3-8c87-40df-b012-73e9a5820780"),
					UserID:         uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					IsActive:       pgtype.Bool{Bool: true},
					ExpirationDate: pgtype.Timestamptz{Time: time.Now()},
				}, nil)
				issuer.On("InactivateRefreshToken", mock.Anything, uuid.MustParse("7942c917-4770-43c1-a56a-952186b9970e")).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:  "Should return error when refresh token is empty",
			query: "33a40641-45bb-4b47-aa33-113c7c562328",
			setupMock: func(issuer *mocks.JWTIssuer) {
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("33a40641-45bb-4b47-aa33-113c7c562328")).Return(jwt.User{}, fmt.Errorf("%w", handlerutil.NewNotFoundError("refresh_token", "mock key", "mock value", "mock message")))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:  "Should return error when refresh token is invalid",
			query: "a",
			setupMock: func(issuer *mocks.JWTIssuer) {
				issuer.On("GetUserByRefreshToken", mock.Anything, mock.Anything).Return(jwt.User{}, fmt.Errorf("%w", handlerutil.NewNotFoundError("refresh_token", "mock key", "mock value", "mock message")))
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:  "Should return error when jwtIssuer returns error (internal error)",
			query: "e7e7e7e7-e7e7-4e7e-8e7e-e7e7e7e7e7e7",
			setupMock: func(issuer *mocks.JWTIssuer) {
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("e7e7e7e7-e7e7-4e7e-8e7e-e7e7e7e7e7e7")).Return(jwt.User{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:  "Should return error when New returns error (token generation failure)",
			query: "b7b7b7b7-b7b7-4b7b-8b7b-b7b7b7b7b7b7",
			setupMock: func(issuer *mocks.JWTIssuer) {
				jwtUser := jwt.User{
					ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					Email: "testuser@testuser.com",
					Role:  "user",
				}
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("b7b7b7b7-b7b7-4b7b-8b7b-b7b7b7b7b7b7")).Return(jwtUser, nil)
				issuer.On("New", mock.Anything, jwtUser).Return("", assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:  "Should return error when GenerateRefreshToken returns error",
			query: "c7c7c7c7-c7c7-4c7c-8c7c-c7c7c7c7c7c7",
			setupMock: func(issuer *mocks.JWTIssuer) {
				jwtUser := jwt.User{
					ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					Email: "testuser@testuser.com",
					Role:  "user",
				}
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("c7c7c7c7-c7c7-4c7c-8c7c-c7c7c7c7c7c7")).Return(jwtUser, nil)
				issuer.On("New", mock.Anything, jwtUser).Return("123", nil)
				issuer.On("GenerateRefreshToken", mock.Anything, jwtUser).Return(jwt.RefreshToken{}, assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:  "Should return error when InactivateRefreshToken returns error",
			query: "d7d7d7d7-d7d7-4d7d-8d7d-d7d7d7d7d7d7",
			setupMock: func(issuer *mocks.JWTIssuer) {
				jwtUser := jwt.User{
					ID:    uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					Email: "testuser@testuser.com",
					Role:  "user",
				}
				issuer.On("GetUserByRefreshToken", mock.Anything, uuid.MustParse("d7d7d7d7-d7d7-4d7d-8d7d-d7d7d7d7d7d7")).Return(jwtUser, nil)
				issuer.On("New", mock.Anything, jwtUser).Return("123", nil)
				issuer.On("GenerateRefreshToken", mock.Anything, jwtUser).Return(jwt.RefreshToken{
					ID:             uuid.MustParse("257f5ce3-8c87-40df-b012-73e9a5820780"),
					UserID:         uuid.MustParse("28f0874f-cdb7-4342-9685-fe932ed1dd79"),
					IsActive:       pgtype.Bool{Bool: true},
					ExpirationDate: pgtype.Timestamptz{Time: time.Now()},
				}, nil)
				issuer.On("InactivateRefreshToken", mock.Anything, uuid.MustParse("d7d7d7d7-d7d7-4d7d-8d7d-d7d7d7d7d7d7")).Return(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	logger := zap.NewNop()
	validate := validator.New()
	problemWriter := internal.NewProblemWriter()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &mocks.JWTIssuer{}
			if tc.setupMock != nil {
				tc.setupMock(issuer)
			}
			h := jwt.NewHandler(logger, validate, problemWriter, issuer)

			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/refreshToken/%s", tc.query), nil)
			w := httptest.NewRecorder()

			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/refreshToken/{refreshToken}", h.RefreshToken)
			mux.ServeHTTP(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code, tc.name)
		})
	}
}
