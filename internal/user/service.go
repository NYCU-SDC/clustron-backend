package user

import (
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

func (s *Service) Create(ctx context.Context, username, email, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	param := CreateParams{
		Username:  username,
		Email:     email,
		StudentID: pgtype.Text{String: studentID, Valid: studentID != ""},
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

func (s *Service) FindOrCreate(ctx context.Context, username, email, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "findOrCreateUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.ExistsByEmail(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return User{}, err
	}

	var jwtUser User
	if !exists {
		jwtUser, err = s.Create(traceCtx, username, email, studentID)
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
		err = databaseutil.WrapDBError(err, logger, "get user id by student id")
		span.RecordError(err)
		return uuid.Nil, err
	}

	return id, nil
}
