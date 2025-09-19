package jwt_test

import (
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/jwt/mocks"
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// generate the db mock using mockery
//go:generate mockery --name=DBTX --dir=. --output=internal/jwt/mocks

// mockRow is a minimal mock for pgx.Row
// It implements Scan to set the expected values

type mockRow struct {
	mock.Mock
	vals []interface{}
	err  error
}

func (m *mockRow) Scan(dest ...interface{}) error {
	for i := range dest {
		if i < len(m.vals) {
			switch d := dest[i].(type) {
			case *uuid.UUID:
				*d = m.vals[i].(uuid.UUID)
			case *pgtype.Bool:
				*d = m.vals[i].(pgtype.Bool)
			case *pgtype.Timestamptz:
				*d = m.vals[i].(pgtype.Timestamptz)
			case *string:
				*d = m.vals[i].(string)
			case *pgtype.Text:
				*d = m.vals[i].(pgtype.Text)
			case *pgtype.Int4:
				*d = m.vals[i].(pgtype.Int4)
			}
		}
	}
	return m.err
}

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
	mockDB := new(mocks.DBTX)
	s := jwt.NewService(logger, secret, "oauth-secret", time.Minute, time.Hour, mockDB)

	id := uuid.New()
	refresh := jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}
	user := jwt.User{ID: id, Email: "test@example.com", Role: "user", StudentID: pgtype.Text{String: "123", Valid: true}}

	// mock QueryRow for GetByID (refresh token)
	row := &mockRow{vals: []interface{}{refresh.ID, refresh.UserID, refresh.IsActive, refresh.ExpirationDate}, err: nil}
	mockDB.On("QueryRow", mock.Anything, "-- name: GetByID :one\nSELECT id, user_id, is_active, expiration_date FROM refresh_tokens WHERE id = $1\n", id).Return(row)
	// mock QueryRow for GetUserByRefreshToken (user lookup)
	userRow := &mockRow{vals: []interface{}{user.ID, user.Email, user.Role, user.UidNumber, user.StudentID, user.CreatedAt, user.UpdatedAt}, err: nil}
	mockDB.On("QueryRow", mock.Anything, "-- name: GetUserByRefreshToken :one\nSELECT u.id, u.email, u.role, u.uid_number, u.student_id, u.created_at, u.updated_at FROM refresh_tokens r JOIN users u ON r.user_id = u.id WHERE r.id = $1\n", id).Return(userRow).Once()

	result, err := s.GetUserByRefreshToken(context.Background(), id)
	assert.NoError(t, err)
	assert.Equal(t, user, result)

	// expired case
	expired := jwt.RefreshToken{ID: id, UserID: id, IsActive: pgtype.Bool{Bool: true, Valid: true}, ExpirationDate: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}}
	rowExpired := &mockRow{vals: []interface{}{expired.ID, expired.UserID, expired.IsActive, expired.ExpirationDate}, err: nil}
	mockDB.ExpectedCalls = nil // clear previous expectations
	mockDB.On("QueryRow", mock.Anything, "-- name: GetByID :one\nSELECT id, user_id, is_active, expiration_date FROM refresh_tokens WHERE id = $1\n", id).Return(rowExpired)

	_, err = s.GetUserByRefreshToken(context.Background(), id)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "refresh token expired")
	}
}
