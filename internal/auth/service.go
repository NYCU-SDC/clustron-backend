package auth

import (
	"clustron-backend/internal/config"
	"clustron-backend/internal/user"
	"context"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"time"
)

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries

	userStore userStore

	presetMap       map[string]config.PresetUserInfo
	tokenExpiration time.Duration
}

type userStore interface {
	Create(ctx context.Context, email, studentID string) (user.User, error)
	UpdateRoleByID(ctx context.Context, userID uuid.UUID, role string) error
	UpdateStudentID(ctx context.Context, userID uuid.UUID, studentID string) (user.User, error)
}

func NewService(logger *zap.Logger, db DBTX, userStore userStore, tokenExpiration time.Duration, presetMap map[string]config.PresetUserInfo) *Service {
	return &Service{
		logger:          logger,
		tracer:          otel.Tracer("membership/service"),
		queries:         New(db),
		userStore:       userStore,
		presetMap:       presetMap,
		tokenExpiration: tokenExpiration,
	}
}

func (s *Service) ExistsByIdentifier(ctx context.Context, identifier string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetLoginInfoByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsInfoByIdentifier(traceCtx, identifier)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "check login info existence by identifier")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}

func (s *Service) CreateInfo(ctx context.Context, userID uuid.UUID, providerType ProviderType, email, identifier string) (LoginInfo, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateLoginInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	loginInfo, err := s.queries.CreateInfo(traceCtx, CreateInfoParams{
		UserID:       userID,
		Providertype: providerType.String(),
		Identifier:   identifier,
		Email:        pgtype.Text{String: email, Valid: true},
	})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create login info")
		span.RecordError(err)
		return LoginInfo{}, err
	}

	if providerType == ProviderTypeNYCU {
		// Update the user role to Student if the provider is NYCU
		_, err := s.userStore.UpdateStudentID(traceCtx, userID, identifier)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", userID.String(), logger, "update user student ID")
			span.RecordError(err)
			return LoginInfo{}, err
		}
	}

	return loginInfo, nil
}

func (s *Service) FindOrCreateInfo(ctx context.Context, email, identifier string, providerType ProviderType) (LoginInfo, error) {
	traceCtx, span := s.tracer.Start(ctx, "FindOrCreateLoginInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Check if the login info already exists
	exists, err := s.ExistsByIdentifier(traceCtx, identifier)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "check login info existence")
		span.RecordError(err)
		return LoginInfo{}, err
	}
	if exists {
		// If it exists, return the login info
		loginInfo, err := s.queries.GetInfoByIdentifier(traceCtx, identifier)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "get login info by identifier")
			span.RecordError(err)
			return LoginInfo{}, err
		}
		return loginInfo, nil
	} else {
		// Check with email
		exists, err := s.queries.ExistsInfoByEmail(traceCtx, pgtype.Text{String: email, Valid: true})
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "check login info existence by email")
			span.RecordError(err)
			return LoginInfo{}, err
		}
		if exists {
			loginInfo, err := s.queries.GetInfoByEmail(traceCtx, pgtype.Text{String: email, Valid: true})
			if err != nil {
				err = databaseutil.WrapDBError(err, logger, "get login info by email")
				span.RecordError(err)
				return LoginInfo{}, err
			}
			return loginInfo, nil
		} else {
			// CreateInfo user
			studentID := ""
			if providerType == ProviderTypeNYCU {
				// For NYCU provider, we can use the identifier as student ID
				studentID = identifier
			}
			newUser, err := s.userStore.Create(ctx, email, studentID)
			if err != nil {
				err = databaseutil.WrapDBError(err, logger, "create user")
				span.RecordError(err)
				return LoginInfo{}, err
			}

			// CreateInfo new login info
			loginInfo, err := s.queries.CreateInfo(traceCtx, CreateInfoParams{
				UserID:       newUser.ID,
				Providertype: providerType.String(),
				Identifier:   identifier,
				Email:        pgtype.Text{String: email, Valid: true},
			})
			if err != nil {
				err = databaseutil.WrapDBError(err, logger, "create login info")
				span.RecordError(err)
				return LoginInfo{}, err
			}
			return loginInfo, nil
		}
	}
}

func (s *Service) GetTokenByID(ctx context.Context, id uuid.UUID) (LoginToken, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetTokenByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	token, err := s.queries.GetTokenByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get token by ID")
		span.RecordError(err)
		return LoginToken{}, err
	}

	return token, nil
}

func (s *Service) CreateToken(ctx context.Context, callback string, userID uuid.UUID) (LoginToken, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	nowDate := time.Now()
	expirationDate := nowDate.Add(s.tokenExpiration)

	token, err := s.queries.CreateToken(traceCtx, CreateTokenParams{
		Callback:  callback,
		UserID:    pgtype.UUID{Bytes: userID, Valid: userID != uuid.Nil},
		ExpiresAt: pgtype.Timestamptz{Time: expirationDate, Valid: true},
	})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create token")
		span.RecordError(err)
		return LoginToken{}, err
	}

	return token, nil
}

func (s *Service) InactivateToken(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "InactivateToken")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	_, err := s.queries.InactivateToken(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "login_tokens", "id", id.String(), logger, "inactivate token")
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) DeleteExpiredTokens(ctx context.Context) error {
	traceCtx, span := s.tracer.Start(ctx, "DeleteExpiredTokens")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.queries.DeleteExpiredTokens(traceCtx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "delete expired tokens")
		span.RecordError(err)
		return err
	}

	return nil
}
