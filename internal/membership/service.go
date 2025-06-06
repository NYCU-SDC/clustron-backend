package membership

import (
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"fmt"
	"strings"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type GroupRoleStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (grouprole.GroupRole, error)
	GetByUser(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, error)
}

type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (user.User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
	ExistsByIdentifier(ctx context.Context, identifier string) (bool, error)
}

type SettingStore interface {
	GetSettingByUserID(ctx context.Context, userID uuid.UUID) (setting.Setting, error)
}

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	queries *Queries

	userStore      UserStore
	groupRoleStore GroupRoleStore
	settingStore   SettingStore
}

func NewService(logger *zap.Logger, db DBTX, userStore UserStore, groupRoleStore GroupRoleStore, settingStore SettingStore) *Service {
	return &Service{
		logger:         logger,
		tracer:         otel.Tracer("membership/service"),
		queries:        New(db),
		userStore:      userStore,
		groupRoleStore: groupRoleStore,
		settingStore:   settingStore,
	}
}

func (s *Service) ListWithPaged(ctx context.Context, groupId uuid.UUID, page int, size int, sort string, sortBy string) ([]Response, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListWithPaged")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.hasGroupControlAccess(traceCtx, groupId) {
		return nil, handlerutil.ErrForbidden
	}

	var members []Response
	if sort == "desc" {
		params := ListGroupMembersDescPagedParams{
			GroupID: groupId,
			Sortby:  sortBy,
			Size:    int32(size),
			Skip:    int32(page) * int32(size),
		}
		res, err := s.queries.ListGroupMembersDescPaged(traceCtx, params)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to list group members")
			span.RecordError(err)
			return nil, err
		}
		members = make([]Response, len(res))
		for i, member := range res {
			members[i] = Response{
				ID:        member.UserID,
				Username:  member.Username.String,
				Email:     member.Email,
				StudentID: member.StudentID.String,
				Role: grouprole.Role{
					ID:          member.RoleID,
					Role:        member.Role,
					AccessLevel: member.AccessLevel,
				},
			}
		}
	} else {
		params := ListGroupMembersAscPagedParams{
			GroupID: groupId,
			Sortby:  sortBy,
			Size:    int32(size),
			Skip:    int32(page) * int32(size),
		}
		res, err := s.queries.ListGroupMembersAscPaged(traceCtx, params)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to list group members")
			span.RecordError(err)
			return nil, err
		}
		members = make([]Response, len(res))
		for i, member := range res {
			members[i] = Response{
				ID:        member.UserID,
				Username:  member.Username.String,
				Email:     member.Email,
				StudentID: member.StudentID.String,
				Role: grouprole.Role{
					ID:          member.RoleID,
					Role:        member.Role,
					AccessLevel: member.AccessLevel,
				},
			}
		}
	}

	return members, nil
}

func (s *Service) Add(ctx context.Context, groupId uuid.UUID, memberIdentifier string, role uuid.UUID) (JoinResult, error) {
	traceCtx, span := s.tracer.Start(ctx, "Add")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the role is group owner (it should never be allowed to add another group owner)
	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, role)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group role")
		span.RecordError(err)
		return nil, err
	}
	isOwner := s.isGroupOwner(roleInfo)
	if isOwner {
		logger.Warn("Group role is owner, you cannot add the group owner")
		return nil, handlerutil.ErrForbidden
	}

	// check if the user has access to the group (group owner or group admin)
	if !s.hasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return nil, handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, role) {
		logger.Warn("The user's access is not allowed to add this member")
		return nil, handlerutil.ErrForbidden
	}

	// get user id by email or student id
	userExists, err := s.userStore.ExistsByIdentifier(traceCtx, memberIdentifier)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to check if user exists")
		span.RecordError(err)
		return nil, err
	}
	// if the user does not exist, add them as a pending member
	if !userExists {
		pendingMember, err := s.JoinPending(traceCtx, AddOrUpdatePendingParams{
			UserIdentifier: memberIdentifier,
			GroupID:        groupId,
			RoleID:         role,
		})
		if err != nil {
			return nil, err
		}
		return pendingMember, nil
	}

	var memberUserId uuid.UUID
	if strings.Contains(memberIdentifier, "@") {
		memberUserId, err = s.userStore.GetIdByEmail(traceCtx, memberIdentifier)
		if err != nil {
			return nil, err
		}
	} else {
		memberUserId, err = s.userStore.GetIdByStudentId(traceCtx, memberIdentifier)
		if err != nil {
			return nil, err
		}
	}

	// call Join
	member, err := s.Join(traceCtx, memberUserId, groupId, role)
	if err != nil {
		return nil, err
	}

	return member, nil
}

func (s *Service) JoinPending(ctx context.Context, params AddOrUpdatePendingParams) (PendingMemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "JoinPending")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	pendingMember, err := s.queries.AddOrUpdatePending(ctx, AddOrUpdatePendingParams{
		UserIdentifier: params.UserIdentifier,
		GroupID:        params.GroupID,
		RoleID:         params.RoleID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "user_identifier/group_id/role_id", fmt.Sprintf("%s/%s/%s", params.UserIdentifier, params.GroupID.String(), params.RoleID.String()), logger, "failed to add pending member")
		span.RecordError(err)
		return PendingMemberResponse{}, err
	}

	return PendingMemberResponse{
		ID:             pendingMember.ID,
		UserIdentifier: pendingMember.UserIdentifier,
		GroupID:        pendingMember.GroupID,
		RoleID:         pendingMember.RoleID,
	}, nil
}

func (s *Service) Join(ctx context.Context, userId uuid.UUID, groupId uuid.UUID, role uuid.UUID) (MemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "Join")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	member, err := s.queries.AddOrUpdate(traceCtx, AddOrUpdateParams{
		GroupID: groupId,
		UserID:  userId,
		RoleID:  role,
	})
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBError(err, logger, "failed to add member")
	}

	// get user info
	u, err := s.userStore.GetByID(traceCtx, userId)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"users",
			"user_id",
			userId.String(),
			logger,
			"failed to get user info",
		)
	}

	// get user setting
	userSetting, err := s.settingStore.GetSettingByUserID(traceCtx, userId)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"settings",
			"user_id",
			userId.String(),
			logger,
			"failed to get user setting",
		)
	}

	// get group role
	roleResponse, err := s.groupRoleStore.GetByID(traceCtx, member.RoleID)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"group_roles",
			"role_id",
			member.RoleID.String(),
			logger,
			"failed to get group role",
		)
	}

	return MemberResponse{
		ID:        u.ID,
		Username:  userSetting.Username.String,
		Email:     u.Email,
		StudentID: u.StudentID.String,
		Role:      grouprole.Role(roleResponse),
	}, nil
}

func (s *Service) Remove(ctx context.Context, groupId uuid.UUID, userId uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Remove")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetMembershipByUser(traceCtx, GetMembershipByUserParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		return err
	}

	// check if the role is group owner (it should never be allowed to remove the group owner)
	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, membership.RoleID)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group role")
		span.RecordError(err)
		return err
	}

	isOwner := s.isGroupOwner(roleInfo)
	if isOwner {
		logger.Warn("Group role is owner, you cannot remove the group owner")
		return handlerutil.ErrForbidden
	}

	// check if the user has access to the group (group owner or group admin)
	if !s.hasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, membership.RoleID) {
		logger.Warn("The user's access is not allowed to remove this member")
		return handlerutil.ErrForbidden
	}

	err = s.queries.Delete(traceCtx, DeleteParams{
		GroupID: groupId,
		UserID:  userId,
	})
	if err != nil {
		span.RecordError(err)
		return databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id/user_id", fmt.Sprintf("%s/%s", groupId, userId), logger, "failed to remove group member")
	}

	return nil
}

func (s *Service) Update(ctx context.Context, groupId uuid.UUID, userId uuid.UUID, role uuid.UUID) (MemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "Update")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the role is group owner (it should never be allowed to update to group owner)
	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, role)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group role")
		span.RecordError(err)
		return MemberResponse{}, err
	}
	isOwner := s.isGroupOwner(roleInfo)
	if isOwner {
		logger.Warn("Group role is owner, you cannot update the group owner")
		return MemberResponse{}, handlerutil.ErrForbidden
	}

	// check if the user has access to the group (group owner or group admin)
	if !s.hasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return MemberResponse{}, handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, role) {
		logger.Warn("The user's access is not allowed to update this member")
		return MemberResponse{}, handlerutil.ErrForbidden
	}

	updatedMembership, err := s.queries.UpdateMembershipRole(ctx, UpdateMembershipRoleParams{
		GroupID: groupId,
		UserID:  userId,
		RoleID:  role,
	})
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"memberships",
			"group_id/user_id",
			fmt.Sprintf("%s/%s", groupId, userId),
			logger,
			"failed to update membership",
		)
	}

	u, err := s.userStore.GetByID(traceCtx, userId)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"users",
			"user_id",
			userId.String(),
			logger,
			"failed to get user info",
		)
	}

	userSetting, err := s.settingStore.GetSettingByUserID(traceCtx, userId)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"settings",
			"user_id",
			userId.String(),
			logger,
			"failed to get user setting",
		)
	}

	roleResponse, err := s.groupRoleStore.GetByID(traceCtx, updatedMembership.RoleID)
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"group_roles",
			"role_id",
			updatedMembership.RoleID.String(),
			logger,
			"failed to get group role",
		)
	}

	return MemberResponse{
		ID:        u.ID,
		Username:  userSetting.Username.String,
		Email:     u.Email,
		StudentID: u.StudentID.String,
		Role:      grouprole.Role(roleResponse),
	}, nil
}

func (s *Service) CountByGroupID(ctx context.Context, groupID uuid.UUID) (int64, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.CountByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id", groupID.String(), logger, "count memberships by group id")
		span.RecordError(err)
		return 0, err
	}

	return count, nil
}

func (s *Service) GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRelationShip")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetMembershipByUser(traceCtx, GetMembershipByUserParams{
		UserID:  userID,
		GroupID: groupID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get membership")
		span.RecordError(err)
		return "", err
	}

	return membership.AccessLevel, nil
}

func (s *Service) canAssignRole(ctx context.Context, groupId uuid.UUID, roleId uuid.UUID) bool {
	traceCtx, span := s.tracer.Start(ctx, "CanAssignRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.Error("failed to get user from context", zap.Error(err))
		return false
	}

	if jwtUser.Role == string(role.Admin) {
		return true
	}

	accessLevel, err := s.GetUserGroupAccessLevel(traceCtx, jwtUser.ID, groupId)
	if err != nil {
		logger.Error("failed to get user group access level", zap.Error(err))
		return false
	}
	targetRole, err := s.groupRoleStore.GetByID(traceCtx, roleId)
	if err != nil {
		logger.Error("failed to get member role by id", zap.Error(err))
		return false
	}
	return grouprole.AccessLevelRank[accessLevel] > grouprole.AccessLevelRank[targetRole.AccessLevel]
}

func (s *Service) hasGroupControlAccess(ctx context.Context, groupId uuid.UUID) bool {
	traceCtx, span := s.tracer.Start(ctx, "HasGroupControlAccess")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.Error("failed to get user from context", zap.Error(err))
		return false
	}

	if jwtUser.Role == string(role.Admin) {
		return true
	}

	accessLevel, err := s.GetUserGroupAccessLevel(traceCtx, jwtUser.ID, groupId)
	if err != nil {
		logger.Error("failed to get user group access level", zap.Error(err))
		return false
	}

	return accessLevel == string(grouprole.AccessLevelOwner) || accessLevel == string(grouprole.AccessLevelAdmin)
}

func (s *Service) isGroupOwner(role grouprole.GroupRole) bool {
	return role.AccessLevel == string(grouprole.AccessLevelOwner)
}
