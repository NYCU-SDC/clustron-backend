package user

import (
	"context"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	queries *Queries
	logger  *zap.Logger
	tracer  trace.Tracer
}

func NewService(logger *zap.Logger, db DBTX) *Service {
	return &Service{
		queries: New(db),
		logger:  logger,
		tracer:  otel.Tracer("user/service"),
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

func (s *Service) Create(ctx context.Context, username, email string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	param := CreateParams{
		Username: username,
		Email:    email,
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

func (s *Service) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "ExistsByEmail")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByEmail(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}
