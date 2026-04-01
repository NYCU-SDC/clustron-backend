package jwt_test

import (
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/jwt/mocks"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestService_NewAndParseToken(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	s := jwt.NewService(logger, secret, "oauth-secret", time.Minute, time.Hour, nil)
	userID := uuid.New()
	user := jwt.User{ID: userID, Email: "test@example.com", Role: "user", StudentID: pgtype.Text{String: "123", Valid: true}}

	token, err := s.New(context.Background(), user)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := s.Parse(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, userID, parsed.ID)
	assert.Equal(t, user.Role, parsed.Role)
}

func TestService_Parse_InvalidToken(t *testing.T) {
	logger := zap.NewNop()
	s := jwt.NewService(logger, "test-secret", "oauth-secret", time.Minute, time.Hour, nil)
	_, err := s.Parse(context.Background(), "invalid.token.value")
	assert.Error(t, err)
}

func TestService_GetUserByRefreshToken(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	querier := mocks.NewQuerier(t)
	s := jwt.NewService(logger, secret, "oauth-secret", time.Minute, time.Hour, querier)

	id := uuid.New()
	user := jwt.User{ID: id, Email: "test@example.com", Role: "user", StudentID: pgtype.Text{String: "123", Valid: true}}

	testCases := []struct {
		name         string
		refreshToken jwt.RefreshToken
		userRowVals  []interface{}
		expired      bool
		expectErr    bool
		errContains  string
		setupMock    func()
	}{
		{
			name:         "valid refresh token",
			refreshToken: jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}},
			userRowVals:  []interface{}{user.ID, user.Email, user.Role, user.FullName, user.StudentID, user.CreatedAt, user.UpdatedAt},
			expired:      false,
			expectErr:    false,
			setupMock: func() {
				querier.On("GetByID", mock.Anything, id).Return(jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}, nil).Once()
				querier.On("GetUserByRefreshToken", mock.Anything, id).Return(jwt.User{ID: user.ID, Email: user.Email, Role: user.Role, StudentID: user.StudentID}, nil).Once()
			},
		},
		{
			name:         "expired refresh token",
			refreshToken: jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}},
			userRowVals:  nil,
			expired:      true,
			expectErr:    true,
			errContains:  "refresh token expired",
			setupMock: func() {
				querier.On("GetByID", mock.Anything, id).Return(jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}}, nil).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupMock()
			result, err := s.GetUserByRefreshToken(context.Background(), tc.refreshToken.ID)
			if tc.expectErr {
				assert.Error(t, err)
				if tc.errContains != "" && err != nil {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, user, result)
			}
		})
	}
}
