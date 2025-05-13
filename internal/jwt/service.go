package jwt

import (
	"clustron-backend/internal"
	"clustron-backend/internal/user"
	"context"
	"errors"
	"fmt"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Store interface {
	GetByEmail(ctx context.Context, email string) (user.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (user.User, error)
}

type Service struct {
	logger                 *zap.Logger
	secret                 string
	expiration             time.Duration
	refreshTokenExpiration time.Duration
	userStore              Store
	tracer                 trace.Tracer
	queries                *Queries
}

func NewService(logger *zap.Logger, secret string, expiration, refreshTokenExpiration time.Duration, userStore Store, db DBTX) *Service {
	return &Service{
		logger:                 logger,
		secret:                 secret,
		expiration:             expiration,
		refreshTokenExpiration: refreshTokenExpiration,
		userStore:              userStore,
		tracer:                 otel.Tracer("jwt/service"),
		queries:                New(db),
	}
}

type claims struct {
	ID       uuid.UUID
	Username string
	Email    string
	Role     string
	jwt.RegisteredClaims
}

func (u User) HasRole(role string) bool {
	return u.Role.String == role
}

func (s Service) New(ctx context.Context, user User) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "New")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	jwtID := uuid.New()

	id := user.ID
	username := user.Username
	email := user.Email
	role := user.Role.String

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		ID:       id,
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "Clustron",
			Subject:   id.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expiration)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jwtID.String(),
		},
	})

	tokenString, err := token.SignedString([]byte(s.secret))
	if err != nil {
		logger.Error("Failed to sign token", zap.Error(err), zap.String("id", id.String()), zap.String("username", username), zap.String("role", role))
		return "", err
	}

	logger.Debug("Generated new JWT token", zap.String("id", id.String()), zap.String("username", username), zap.String("role", role))

	return tokenString, nil
}

func (s Service) Parse(ctx context.Context, tokenString string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "Parse")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenString, &claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.secret), nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			logger.Warn("Failed to parse JWT token due to malformed structure, this is not a JWT token", zap.String("error", err.Error()))
			return User{}, err
		case errors.Is(err, jwt.ErrSignatureInvalid):
			logger.Warn("Failed to parse JWT token due to invalid signature", zap.String("error", err.Error()))
			return User{}, err
		case errors.Is(err, jwt.ErrTokenExpired):
			expiredTime, getErr := token.Claims.GetExpirationTime()
			if getErr != nil {
				logger.Warn("Failed to parse JWT token due to expired timestamp", zap.String("error", err.Error()))
			} else {
				logger.Warn("Failed to parse JWT token due to expired timestamp", zap.String("error", err.Error()), zap.Time("expired_at", expiredTime.Time))
			}

			return User{}, err
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			notBeforeTime, getErr := token.Claims.GetNotBefore()
			if getErr != nil {
				logger.Warn("Failed to parse JWT token due to not valid yet timestamp", zap.String("error", err.Error()))
			} else {
				logger.Warn("Failed to parse JWT token due to not valid yet timestamp", zap.String("error", err.Error()), zap.Time("not_valid_yet", notBeforeTime.Time))
			}

			return User{}, err
		default:
			logger.Error("Failed to parse or validate JWT token", zap.Error(err))
			return User{}, err
		}
	}

	claims, ok := token.Claims.(*claims)
	if !ok {
		logger.Error("Failed to extract claims from JWT token")
		return User{}, fmt.Errorf("failed to extract claims from JWT token")
	}

	logger.Debug("Successfully parsed JWT token", zap.String("id", claims.ID.String()), zap.String("username", claims.Username), zap.String("role", claims.Role))

	jwtUser, err := s.userStore.GetByEmail(ctx, claims.Email)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "user", "email", claims.Email, logger, "get user by email")
		span.RecordError(err)
		return User{}, err
	}

	return User(jwtUser), nil
}

func (s Service) GetUserByRefreshToken(ctx context.Context, id uuid.UUID) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserByRefreshToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	refreshToken, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "refresh_token", "id", id.String(), logger, "get refresh token by id")
		span.RecordError(err)
		return User{}, err
	}

	// Check if the refresh token is expired
	if refreshToken.ExpirationDate.Time.Before(time.Now()) {
		err = fmt.Errorf("%w: refresh token expired", internal.ErrInvalidRefreshToken)
		span.RecordError(err)
		return User{}, err
	}

	// Check if the refresh token is active
	if !refreshToken.IsActive.Bool {
		err = fmt.Errorf("%w: refresh token is inactive", internal.ErrInvalidRefreshToken)
		span.RecordError(err)
		return User{}, err
	}

	jwtUser, err := s.queries.GetUserByRefreshToken(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "refresh_token", "id", id.String(), logger, "get user by refresh token")
		span.RecordError(err)
		return User{}, err
	}
	return jwtUser, nil
}

// GenerateRefreshToken Generate a new refresh token for the user
func (s Service) GenerateRefreshToken(ctx context.Context, user User) (RefreshToken, error) {
	traceCtx, span := s.tracer.Start(ctx, "GenerateRefreshToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Remove expired and inactive refresh tokens
	_, err := s.DeleteExpiredRefreshTokens(traceCtx)
	if err != nil {
		logger.Warn("Failed to delete expired refresh tokens", zap.Error(err))
	}

	expirationDate := time.Now()
	newDate := expirationDate.Add(s.refreshTokenExpiration)

	refreshToken, err := s.queries.Create(traceCtx, CreateParams{
		UserID:         user.ID,
		ExpirationDate: pgtype.Timestamptz{Time: newDate, Valid: true},
	})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "generate refresh token")
		span.RecordError(err)
		return RefreshToken{}, err
	}

	return refreshToken, nil
}

// InactivateRefreshToken Inactivate a refresh token
func (s Service) InactivateRefreshToken(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "InactivateRefreshToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	_, err := s.queries.Inactivate(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "refresh_token", "id", id.String(), logger, "inactivate refresh token")
		span.RecordError(err)
		return err
	}

	return nil
}

// DeleteExpiredRefreshTokens Remove expired and inactive refresh tokens
func (s Service) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	traceCtx, span := s.tracer.Start(ctx, "DeleteExpiredRefreshTokens")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	rowsAffected, err := s.queries.Delete(traceCtx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "delete expired refresh tokens")
		span.RecordError(err)
		return 0, err
	}

	logger.Debug("Deleted expired refresh tokens", zap.Int64("rows_affected", rowsAffected))
	return rowsAffected, nil
}
