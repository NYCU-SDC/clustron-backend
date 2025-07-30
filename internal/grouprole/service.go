package grouprole

import (
	"clustron-backend/internal"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"fmt"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type SettingStore interface {
	GetSettingByUserID(ctx context.Context, userID uuid.UUID) (setting.Setting, error)
}

type Service struct {
	logger       *zap.Logger
	tracer       trace.Tracer
	queries      *Queries
	settingStore SettingStore
}

func NewService(logger *zap.Logger, db DBTX, settingStore SettingStore) *Service {
	return &Service{
		logger:       logger,
		tracer:       otel.Tracer("group/service"),
		queries:      New(db),
		settingStore: settingStore,
	}
}

func (s *Service) GetAll(ctx context.Context) ([]GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListGroupRoles")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	roles, err := s.queries.GetAll(ctx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to list group roles")
		span.RecordError(err)
		return nil, err
	}
	return roles, nil
}

func (s *Service) Create(ctx context.Context, role CreateParams) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByRoleName(ctx, role.RoleName)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_name", role.RoleName, logger, "check if group role exists")
		span.RecordError(err)
		return GroupRole{}, err
	}
	if exists {
		err = fmt.Errorf("role %s already exists, %w", role.RoleName, internal.ErrDatabaseConflict)
		span.RecordError(err)
		return GroupRole{}, err
	}

	createdRole, err := s.queries.Create(ctx, role)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_name", role.RoleName, logger, "create group role")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return createdRole, nil
}

func (s *Service) Update(ctx context.Context, role UpdateParams) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	updatedRole, err := s.queries.Update(ctx, role)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", role.ID.String(), logger, "update group role")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return updatedRole, nil
}

func (s *Service) Delete(ctx context.Context, roleID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeleteGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.queries.Delete(ctx, roleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "delete group role")
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) GetByID(ctx context.Context, roleID uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetByID(ctx, roleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "get group role by id")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return role, nil
}

func (s *Service) GetByUser(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groupRole, err := s.queries.GetUserGroupRole(ctx, GetUserGroupRoleParams{
		UserID:  userID,
		GroupID: groupID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get membership")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return groupRole, nil
}

func (s *Service) GetTypeByUser(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (GroupRole, string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetTypeByUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groupRole, err := s.GetByUser(traceCtx, userID, groupID)
	roleType := "membership"
	roleResponse := GroupRole{}
	if err != nil {
		// if the user is not a member of the group, check if the user is an admin
		if errors.As(err, &handlerutil.NotFoundError{}) {
			// if the user is an admin, return the group with admin override
			if userRole == role.Admin.String() {
				roleType = "adminOverride"
			} else {
				// if the user is not a member of the group and not an admin, return 404
				err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get group role by user id and group id")
				span.RecordError(err)
				return GroupRole{}, "", err
			}
		} else {
			// other errors
			return GroupRole{}, "", err
		}
	}
	// if roleResponse hasn't been set, it means the user is a member of the group
	if roleResponse == (GroupRole{}) && roleType != "adminOverride" {
		roleResponse = groupRole
	}

	return roleResponse, roleType, nil
}
