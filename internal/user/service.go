package user

import (
	"clustron-backend/internal/config"
	"clustron-backend/internal/user/role"
	"context"
	"errors"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	queries   *Queries
	logger    *zap.Logger
	presetMap map[string]config.PresetUserInfo
	tracer    trace.Tracer
}

type ServiceInterface interface {
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
}

func NewService(logger *zap.Logger, presetMap map[string]config.PresetUserInfo, db DBTX) *Service {
	return &Service{
		queries:   New(db),
		logger:    logger,
		presetMap: presetMap,
		tracer:    otel.Tracer("user/service"),
	}
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	user, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by id")
		span.RecordError(err)
		return User{}, err
	}

	return user, nil
}

func (s *Service) Create(ctx context.Context, email, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	param := CreateParams{
		Email:     email,
		StudentID: pgtype.Text{String: studentID, Valid: studentID != ""},
	}

	presetRole, exist := s.presetMap[email]
	if exist {
		param.Role = presetRole.Role
	} else {
		param.Role = role.User.String()
	}

	user, err := s.queries.Create(traceCtx, param)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create user")
		span.RecordError(err)
		return User{}, err
	}
	return user, nil
}

func (s *Service) GetByEmail(ctx context.Context, email string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByEmail")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	user, err := s.queries.GetByEmail(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return User{}, err
	}

	return user, nil
}

func (s *Service) ExistsByIdentifier(ctx context.Context, email string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "ExistsByIdentifier")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByIdentifier(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}

func (s *Service) FindOrCreate(ctx context.Context, email, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "findOrCreateUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.ExistsByIdentifier(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return User{}, err
	}

	var jwtUser User
	if !exists {
		jwtUser, err = s.Create(traceCtx, email, studentID)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "create user")
			span.RecordError(err)
			return User{}, err
		}
	} else {
		jwtUser, err = s.GetByEmail(traceCtx, email)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "get user by email")
			return User{}, err
		}
	}

	return jwtUser, nil
}

func (s *Service) GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetIdByEmail")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	id, err := s.queries.GetIdByEmail(traceCtx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil
		}
		err = databaseutil.WrapDBError(err, logger, "get user id by email")
		span.RecordError(err)
		return uuid.Nil, err
	}

	return id, nil
}

func (s *Service) GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetIdByStudentId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	id, err := s.queries.GetIdByStudentId(traceCtx, pgtype.Text{String: studentID, Valid: studentID != ""})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil
		}
		err = databaseutil.WrapDBError(err, logger, "get user id by student id")
		span.RecordError(err)
		return uuid.Nil, err
	}

	return id, nil
}

func (s *Service) GetRoleByID(ctx context.Context, id uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetRoleByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetRoleByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get role by id")
		span.RecordError(err)
		return "", err
	}

	return role, nil
}
