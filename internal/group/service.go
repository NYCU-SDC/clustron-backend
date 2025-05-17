package group

import (
	"context"
	"fmt"
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
		params := GetAllWithPageDESCParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.GetAllWithPageDESC(ctx, params)
	} else {
		params := GetAllWithPageASCParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.GetAllWithPageASC(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get groups")
		span.RecordError(err)
		return nil, err
	}

	return groups, nil
}

func (s *Service) GetAllByUserId(ctx context.Context, userId uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, []GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAllByUserId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if sort == "desc" {
		params := FindByUserWithPageDESCParams{
			UserID: userId,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		res, err := s.queries.FindByUserWithPageDESC(ctx, params)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "user_id", userId.String(), logger, "failed to get groups by user id")
			span.RecordError(err)
			return nil, nil, err
		}
		groups := make([]Group, len(res))
		roles := make([]GroupRole, len(res))
		for i, r := range res {
			groups[i] = Group{
				ID:          r.ID,
				Title:       r.Title,
				Description: r.Description,
				IsArchived:  r.IsArchived,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
			}
			roles[i] = GroupRole{
				ID:          r.ID_2,
				Role:        r.Role,
				AccessLevel: r.AccessLevel,
			}
		}
		return groups, roles, nil
	} else {
		params := FindByUserWithPageASCParams{
			UserID: userId,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		res, err := s.queries.FindByUserWithPageASC(ctx, params)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "user_id", userId.String(), logger, "failed to get groups by user id")
			span.RecordError(err)
			return nil, nil, err
		}
		groups := make([]Group, len(res))
		roles := make([]GroupRole, len(res))
		for i, r := range res {
			groups[i] = Group{
				ID:          r.ID,
				Title:       r.Title,
				Description: r.Description,
				IsArchived:  r.IsArchived,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
			}
			roles[i] = GroupRole{
				ID:          r.ID_2,
				Role:        r.Role,
				AccessLevel: r.AccessLevel,
			}
		}
		return groups, roles, nil
	}
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

func (s *Service) FindUserGroupById(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "CheckIsUserInGroup")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.FindUserGroupById(ctx, FindUserGroupByIdParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", "user_id and group_id", userId.String()+" "+groupId.String(), logger, "get membership")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) GetUserGroupRole(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetUserGroupRole(ctx, GetUserGroupRoleParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupId.String(), userId.String()), logger, "get membership")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return role, nil
}

func (s *Service) GetUserGroupAccessLevel(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRelationShip")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetUserGroupMembership(ctx, GetUserGroupMembershipParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", userId.String(), groupId.String()), logger, "get membership")
		span.RecordError(err)
		return "", err
	}

	accessLevel, err := s.queries.AccessLevelFromRole(ctx, membership.RoleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_access_level", "role", membership.RoleID.String(), logger, "get access level")
		span.RecordError(err)
		return "", err
	}

	return accessLevel, nil
}

func (s *Service) GetUserAllMembership(ctx context.Context, userId uuid.UUID) ([]GetUserAllMembershipRow, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserAllMembership")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	memberships, err := s.queries.GetUserAllMembership(ctx, userId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", "user_id", userId.String(), logger, "get membership")
		span.RecordError(err)
		return nil, err
	}

	return memberships, nil
}

func (s *Service) GetUserGroupMembership(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (Membership, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupMembership")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetUserGroupMembership(ctx, GetUserGroupMembershipParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", userId.String(), groupId.String()), logger, "get membership")
		span.RecordError(err)
		return Membership{}, err
	}

	return membership, nil
}

func (s *Service) GetGroupRoleById(ctx context.Context, roleId uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetGroupRoleById")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetGroupRoleById(ctx, roleId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleId.String(), logger, "get group role by id")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return role, nil
}
