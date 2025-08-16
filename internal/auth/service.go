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
)

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries

	presetMap map[string]config.PresetUserInfo
	userStore userStore
}

type userStore interface {
	Create(ctx context.Context, email, studentID string) (user.User, error)
	UpdateRoleByID(ctx context.Context, userID uuid.UUID, role string) error
	UpdateStudentID(ctx context.Context, userID uuid.UUID, studentID string) (user.User, error)
}

func NewService(logger *zap.Logger, db DBTX, userStore userStore, presetMap map[string]config.PresetUserInfo) *Service {
	return &Service{
		logger:    logger,
		tracer:    otel.Tracer("membership/service"),
		queries:   New(db),
		presetMap: presetMap,
		userStore: userStore,
	}
}

func (s *Service) ExistsByIdentifier(ctx context.Context, identifier string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetLoginInfoByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByIdentifier(traceCtx, identifier)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "check login info existence by identifier")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, providerType ProviderType, email, identifier string) (LoginInfo, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateLoginInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	loginInfo, err := s.queries.Create(traceCtx, CreateParams{
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

func (s *Service) FindOrCreate(ctx context.Context, email, identifier string, providerType ProviderType) (LoginInfo, error) {
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
		loginInfo, err := s.queries.GetByIdentifier(traceCtx, identifier)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "get login info by identifier")
			span.RecordError(err)
			return LoginInfo{}, err
		}
		return loginInfo, nil
	} else {
		// Check with email
		exists, err := s.queries.ExistsByEmail(traceCtx, pgtype.Text{String: email, Valid: true})
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "check login info existence by email")
			span.RecordError(err)
			return LoginInfo{}, err
		}
		if exists {
			loginInfo, err := s.queries.GetByEmail(traceCtx, pgtype.Text{String: email, Valid: true})
			if err != nil {
				err = databaseutil.WrapDBError(err, logger, "get login info by email")
				span.RecordError(err)
				return LoginInfo{}, err
			}
			return loginInfo, nil
		} else {
			// Create user
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

			// Create new login info
			loginInfo, err := s.queries.Create(traceCtx, CreateParams{
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
