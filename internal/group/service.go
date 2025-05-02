package group

import (
	"context"
	"github.com/NYCU-SDC/summer/pkg/database"
	"github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries
}

func NewService(logger *zap.Logger, db DBTX) *Service {
	return &Service{
		logger:  logger,
		tracer:  otel.Tracer("group/service"),
		queries: New(db),
	}
}

func (s *Service) GetAllGroupCount(ctx context.Context) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAllGroupCount")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.GetAllGroupsCount(ctx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get all groups count")
		span.RecordError(err)
		return 0, err
	}

	return int(count), nil
}

func (s *Service) GetUserGroupsCount(ctx context.Context, userId uuid.UUID) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupsCount")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.GetUserGroupsCount(traceCtx, userId)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get user groups count")
		span.RecordError(err)
		return 0, err
	}

	return int(count), nil
}

func (s *Service) GetAll(ctx context.Context, page int, size int, sort string, sortBy string) ([]Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAll")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var groups []Group
	var err error
	if sort == "desc" {
		params := GetWithPageDESCParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.GetWithPageDESC(ctx, params)
	} else {
		params := GetWithPageASCParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.GetWithPageASC(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get groups")
		span.RecordError(err)
		return nil, err
	}

	return groups, nil
}

func (s *Service) GetByUserId(ctx context.Context, userId uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByUserId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var groups []Group
	var err error
	if sort == "desc" {
		params := FindByUserWithPageDESCParams{
			UserID: userId,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.FindByUserWithPageDESC(ctx, params)
	} else {
		params := FindByUserWithPageASCParams{
			UserID: userId,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.FindByUserWithPageASC(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "user_id", userId.String(), logger, "failed to get groups by user id")
		span.RecordError(err)
		return nil, err
	}

	return groups, nil
}

func (s *Service) GetById(ctx context.Context, groupId uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetById")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.FindById(ctx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupId.String(), logger, "failed to get group by id")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) CreateGroup(ctx context.Context, group CreateParams) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateGroup")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	newGroup, err := s.queries.Create(ctx, group)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to create group")
		span.RecordError(err)
		return Group{}, err
	}

	return newGroup, nil
}

func (s *Service) ArchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "ArchiveGroup")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.Archive(ctx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupId.String(), logger, "failed to archive group")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) UnarchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "UnarchiveGroup")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.Unarchive(ctx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupId.String(), logger, "failed to unarchive group")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}
