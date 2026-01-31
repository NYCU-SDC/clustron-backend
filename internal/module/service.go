package module

import (
	"context"
	"errors"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"

	"github.com/google/uuid"
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

func (s *Service) Create(ctx context.Context, title string, description string, environment []byte) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()

	logger := logutil.WithContext(traceCtx, s.logger)
	desc := pgtype.Text{String: description, Valid: description != ""}

	module, err := s.queries.CreateModule(traceCtx, CreateModuleParams{
		Title:       title,
		Description: desc,
		Environment: environment,
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			logger.Warn("module title already exists", zap.String("title", title))
			span.RecordError(err)
			return Module{}, err
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

func (s *Service) ListPaged(ctx context.Context, page int, size int) ([]Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListPaged")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	limit := int32(size)
	offset := int32(page * size)
	params := ListModulesParams{Size: limit, Skip: offset}

	modules, err := s.queries.ListModules(traceCtx, params)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to list modules")
		span.RecordError(err)
		return nil, err
	}
	return modules, nil
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, title string, description string, environment []byte) (Module, error) {
	traceCtx, span := s.tracer.Start(ctx, "Update")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	desc := pgtype.Text{String: description, Valid: description != ""}

	updatedModule, err := s.queries.UpdateModule(traceCtx, UpdateModuleParams{
		ID:          id,
		Title:       title,
		Description: desc,
		Environment: environment,
	})

	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to update module")
		span.RecordError(err)
		return Module{}, err
	}
	return updatedModule, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Delete")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if err := s.queries.DeleteModule(traceCtx, id); err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "modules", "id", id.String(), logger, "failed to delete module")
		span.RecordError(err)
		return err
	}
	return nil
}
