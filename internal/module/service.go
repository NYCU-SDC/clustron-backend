package module

import (
	"context"
	"errors"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"

	"clustron-backend/internal"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries
}

func NewService(logger *zap.Logger, dbConn DBTX) *Service {
	return &Service{
		logger:  logger,
		tracer:  otel.Tracer("module/service"),
		queries: New(dbConn),
	}
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, title string, description string, environment []byte) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)
	desc := pgtype.Text{String: description, Valid: description != ""}

	module, err := s.queries.CreateModule(traceCtx, CreateModuleParams{
		UserID:      userID,
		Title:       title,
		Description: desc,
		Environment: environment,
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			logger.Warn("module title already exists", zap.String("title", title))
			span.RecordError(internal.ErrDatabaseConflict)
			return Module{}, internal.ErrDatabaseConflict
		}
		err = databaseutil.WrapDBError(err, logger, "failed to create module")
		span.RecordError(err)
		return Module{}, err
	}
	return module, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Get")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	module, err := s.queries.GetModule(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to get module")
		span.RecordError(err)
		return Module{}, err
	}
	return module, nil
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "List")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	modules, err := s.queries.ListModules(traceCtx, userID)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to list modules")
		span.RecordError(err)
		return nil, err
	}
	return modules, nil
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, userID uuid.UUID, title string, description string, environment []byte) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Update")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	existingModule, err := s.queries.GetModule(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to get module for update check")
		span.RecordError(err)
		return Module{}, err
	}

	if existingModule.UserID != userID {
		logger.Warn("user attempted to update module they do not own",
			zap.String("user_id", userID.String()),
			zap.String("module_owner", existingModule.UserID.String()))
		return Module{}, internal.ErrNotModuleOwner
	}

	desc := pgtype.Text{String: description, Valid: description != ""}

	updatedModule, err := s.queries.UpdateModule(traceCtx, UpdateModuleParams{
		ID:          id,
		UserID:      userID,
		Title:       title,
		Description: desc,
		Environment: environment,
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			logger.Warn("module title already exists during update", zap.String("title", title))
			span.RecordError(internal.ErrDatabaseConflict)
			return Module{}, internal.ErrDatabaseConflict
		}
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to update module")
		span.RecordError(err)
		return Module{}, err
	}
	return updatedModule, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Delete")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	existingModule, err := s.queries.GetModule(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to get module for delete check")
		span.RecordError(err)
		return err
	}

	if existingModule.UserID != userID {
		logger.Warn("user attempted to delete module they do not own",
			zap.String("user_id", userID.String()),
			zap.String("module_owner", existingModule.UserID.String()))
		return internal.ErrNotModuleOwner
	}

	if err := s.queries.DeleteModule(traceCtx, DeleteModuleParams{
		ID:     id,
		UserID: userID,
	}); err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to delete module")
		span.RecordError(err)
		return err
	}
	return nil
}
