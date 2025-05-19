package group

import (
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user"
	"context"
	"errors"
	"fmt"
	"strings"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
}

type Service struct {
	logger    *zap.Logger
	tracer    trace.Tracer
	queries   *Queries
	userStore user.ServiceInterface
}

func NewService(logger *zap.Logger, db DBTX, userStore user.ServiceInterface) *Service {
	return &Service{
		logger:    logger,
		tracer:    otel.Tracer("group/service"),
		queries:   New(db),
		userStore: userStore,
	}
}

func (s *Service) CountAll(ctx context.Context) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "CountAll")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.CountAll(ctx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get all groups count")
		span.RecordError(err)
		return 0, err
	}

	return int(count), nil
}

func (s *Service) CountByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "CountByUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.CountByUser(traceCtx, userID)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get user groups count")
		span.RecordError(err)
		return 0, err
	}

	return int(count), nil
}

func (s *Service) ListWithUserScope(ctx context.Context, user jwt.User, page int, size int, sort string, sortBy string) ([]UserScope, int /* totalCount */, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListWithUserScope")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var response []UserScope
	var totalCount int
	if user.Role.String == "admin" { // TODO: the string comparison should be replaced with a enum.
		groups, err := s.ListPaged(traceCtx, page, size, sort, sortBy)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "Get all groups")
			span.RecordError(err)
			return nil, 0, err
		}

		totalCount, err = s.CountAll(traceCtx)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "Get all groups count")
			span.RecordError(err)
			return nil, 0, err
		}

		roles, err := s.ListUserMemberships(traceCtx, user.ID)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "Get all groups membership")
			span.RecordError(err)
			return nil, 0, err
		}

		groupRoleMap := buildRoleGroupIDMap(roles)
		response = buildUserScopeGroups(groups, groupRoleMap, true)
	} else {
		groups, roles, err := s.listByUserID(traceCtx, user.ID, page, size, sort, sortBy)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "Get all groups by user id")
			span.RecordError(err)
			return nil, 0, err
		}

		totalCount, err = s.CountByUser(traceCtx, user.ID)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "Get all groups count")
			span.RecordError(err)
			return nil, 0, err
		}

		// join the groups and roles
		response = make([]UserScope, len(groups))
		for i, group := range groups {
			response[i] = UserScope{
				Group: Group{
					ID:          group.ID,
					Title:       group.Title,
					Description: group.Description,
					IsArchived:  group.IsArchived,
					CreatedAt:   group.CreatedAt,
					UpdatedAt:   group.UpdatedAt,
				},
			}
			role := roles[i]
			response[i].Me.Type = "membership"
			response[i].Me.Role = Role{
				ID:          role.ID,
				Role:        role.Role.String,
				AccessLevel: role.AccessLevel,
			}
		}
	}

	return response, totalCount, nil
}

func buildRoleGroupIDMap(roles []ListMembershipsByUserRow) map[uuid.UUID]Role {
	m := make(map[uuid.UUID]Role)
	for _, r := range roles {
		m[r.GroupID] = Role{
			ID:          r.RoleID,
			Role:        r.Role.String,
			AccessLevel: r.AccessLevel,
		}
	}

	return m
}

func buildUserScopeGroups(groups []Group, roleMap map[uuid.UUID]Role, isAdmin bool) []UserScope {
	result := make([]UserScope, len(groups))
	for i, g := range groups {
		scope := UserScope{
			Group: Group{
				ID:          g.ID,
				Title:       g.Title,
				Description: g.Description,
				IsArchived:  g.IsArchived,
				CreatedAt:   g.CreatedAt,
				UpdatedAt:   g.UpdatedAt,
			},
		}

		if role, ok := roleMap[g.ID]; ok {
			scope.Me.Type = "membership"
			scope.Me.Role = role
		} else if isAdmin {
			scope.Me.Type = "adminOverride"
		}

		result[i] = scope
	}
	return result
}

func (s *Service) ListPaged(ctx context.Context, page int, size int, sort string, sortBy string) ([]Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListPaged")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var groups []Group
	var err error
	if sort == "desc" {
		params := ListDescPagedParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.ListDescPaged(ctx, params)
	} else {
		params := ListAscPagedParams{
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		groups, err = s.queries.ListAscPaged(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get groups")
		span.RecordError(err)
		return nil, err
	}

	return groups, nil
}

func (s *Service) ListByIDWithUserScope(ctx context.Context, user jwt.User, groupID uuid.UUID) (UserScope, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListByIDWithUserScope")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var group Group
	var err error
	if user.Role.String != "admin" { // TODO: the string comparison should be replaced with a enum.
		group, err = s.GetUserGroupByID(traceCtx, user.ID, groupID)
	} else {
		group, err = s.Get(traceCtx, groupID)
	}
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group by id")
		span.RecordError(err)
		return UserScope{}, err
	}

	roleResponse, roleType, err := s.GetUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group role type")
		span.RecordError(err)
		return UserScope{}, err
	}

	response := UserScope{
		Group: Group{
			ID:          group.ID,
			Title:       group.Title,
			Description: group.Description,
			IsArchived:  group.IsArchived,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		},
	}
	response.Me.Type = roleType
	response.Me.Role = roleResponse

	return response, nil
}

func (s *Service) listByUserID(ctx context.Context, userID uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, []GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "listByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if sort == "desc" {
		params := ListIfMemberDescPagedParams{
			UserID: userID,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		res, err := s.queries.ListIfMemberDescPaged(ctx, params)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "user_id", userID.String(), logger, "failed to get groups by user id")
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
		params := ListIfMemberAscPagedParams{
			UserID: userID,
			Sortby: sortBy,
			Size:   int32(size),
			Page:   int32(page),
		}
		res, err := s.queries.ListIfMemberAscPaged(ctx, params)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "user_id", userID.String(), logger, "failed to get groups by user id")
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

func (s *Service) Get(ctx context.Context, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Get")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.Get(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to get group by id")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) Create(ctx context.Context, group CreateParams) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
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

func (s *Service) Archive(ctx context.Context, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Archive")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.Archive(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to archive group")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) Unarchive(ctx context.Context, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Unarchive")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.Unarchive(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to unarchive group")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) GetUserGroupByID(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "CheckIsUserInGroup")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.queries.GetIfMember(ctx, GetIfMemberParams{
		UserID:  userID,
		GroupID: groupID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", "user_id and group_id", userID.String()+" "+groupID.String(), logger, "get membership")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) GetUserGroupRole(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetUserGroupRole(ctx, GetUserGroupRoleParams{
		UserID:  userID,
		GroupID: groupID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get membership")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return role, nil
}

func (s *Service) GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRelationShip")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetMembershipsByUser(ctx, GetMembershipsByUserParams{
		UserID:  userID,
		GroupID: groupID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", userID.String(), groupID.String()), logger, "get membership")
		span.RecordError(err)
		return "", err
	}

	return membership.AccessLevel, nil
}

func (s *Service) ListUserMemberships(ctx context.Context, userID uuid.UUID) ([]ListMembershipsByUserRow, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListUserMemberships")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	memberships, err := s.queries.ListMembershipsByUser(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", "user_id", userID.String(), logger, "get membership")
		span.RecordError(err)
		return nil, err
	}

	return memberships, nil
}

func (s *Service) GetGroupRoleByID(ctx context.Context, roleID uuid.UUID) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetGroupRoleByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	role, err := s.queries.GetGroupRoleByID(ctx, roleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "get group role by id")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return role, nil
}

func (s *Service) GetUserGroupRoleType(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (Role, string, error) {
	role, err := s.GetUserGroupRole(ctx, userID, groupID)
	roleType := "membership"
	roleResponse := Role{}
	if err != nil {
		// if the user is not a member of the group, check if the user is an admin
		if errors.As(err, &handlerutil.NotFoundError{}) {
			// if the user is an admin, return the group with admin override
			if userRole == "admin" { // TODO: the string comparison should be replaced with a enum.
				roleType = "adminOverride"
			} else {
				// if the user is not a member of the group and not an admin, return 404
				return Role{}, "", err
			}
		} else {
			// other errors
			return Role{}, "", err
		}
	}
	// if roleResponse hasn't been set, it means the user is a member of the group
	if roleResponse == (Role{}) && roleType != "adminOverride" {
		roleResponse = Role{
			ID:          role.ID,
			Role:        role.Role.String,
			AccessLevel: role.AccessLevel,
		}
	}

	return roleResponse, roleType, nil
}

func (s *Service) ListGroupMembersPaged(ctx context.Context, groupId uuid.UUID, page int, size int, sort string, sortBy string) ([]Membership, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetGroupMembers")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var members []Membership
	var err error
	if sort == "desc" {
		params := ListGroupMembersDescPagedParams{
			GroupID: groupId,
			Sortby:  sortBy,
			Size:    int32(size),
			Page:    int32(page),
		}
		members, err = s.queries.ListGroupMembersDescPaged(ctx, params)
	} else {
		params := ListGroupMembersAscPagedParams{
			GroupID: groupId,
			Sortby:  sortBy,
			Size:    int32(size),
			Page:    int32(page),
		}
		members, err = s.queries.ListGroupMembersAscPaged(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get members")
		span.RecordError(err)
		return nil, err
	}

	return members, nil
}

func (s *Service) AddGroupMember(ctx context.Context, userIdentifier string, groupId uuid.UUID, role string) (Membership, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddGroupMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// map role to access level
	accessLevel, ok := DefaultRoleToAccessLevel[DefaultRole(role)]
	if !ok {
		span.RecordError(fmt.Errorf("invalid role: %s", role))
		return Membership{}, databaseutil.WrapDBErrorWithKeyValue(
			fmt.Errorf("invalid role: %s", role), "group_role", "role", role, logger, "invalid role")
	}

	// create group_role
	groupRole, err := s.queries.CreateRole(ctx, CreateRoleParams{
		Role:        pgtype.Text{String: role, Valid: true},
		AccessLevel: string(accessLevel),
	})
	if err != nil {
		span.RecordError(err)
		return Membership{}, databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role", role, logger, "invalid role")
	}

	// get user id by email or student id
	var userId uuid.UUID
	if strings.Contains(userIdentifier, "@") {
		userId, err = s.userStore.GetIdByEmail(ctx, userIdentifier)
	} else {
		userId, err = s.userStore.GetIdByStudentId(ctx, userIdentifier)
	}

	// user not registered, adding to the pending_group_members table
	if err != nil {
		_, err = s.queries.AddPendingGroupMember(ctx, AddPendingGroupMemberParams{
			UserIdentifier: userIdentifier,
			GroupID:        groupId,
			RoleID:         groupRole.ID,
		})
		if err != nil {
			span.RecordError(err)
			return Membership{}, databaseutil.WrapDBError(
				err,
				logger,
				"failed to add pending member",
			)
		}
		return Membership{}, nil
	}

	// add member to group
	member, err := s.queries.AddGroupMember(ctx, AddGroupMemberParams{
		GroupID: groupId,
		UserID:  userId,
		RoleID:  groupRole.ID,
	})
	if err != nil {
		span.RecordError(err)
		return Membership{}, databaseutil.WrapDBError(err, logger, "failed to add member")
	}

	return member, nil
}

func (s *Service) RemoveGroupMember(ctx context.Context, groupId uuid.UUID, userId uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "RemoveGroupMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	err := s.queries.RemoveGroupMember(ctx, RemoveGroupMemberParams{
		GroupID: groupId,
		UserID:  userId,
	})
	if err != nil {
		span.RecordError(err)
		return databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id/user_id", fmt.Sprintf("%s/%s", groupId, userId), logger, "failed to remove group member")
	}

	return nil
}

func (s *Service) UpdateGroupMember(ctx context.Context, groupId uuid.UUID, userId uuid.UUID, role string) (MemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateGroupMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	roleId, err := s.queries.GetRoleIdByGroupAndUser(traceCtx, GetRoleIdByGroupAndUserParams{
		GroupID: groupId,
		UserID:  userId,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id/user_id", fmt.Sprintf("%s/%s", groupId, userId), logger, "failed to get role_id")
		span.RecordError(err)
		return MemberResponse{}, err
	}

	updatedRole, err := s.queries.UpdateGroupMemberRole(ctx, UpdateGroupMemberRoleParams{
		ID:   roleId,
		Role: role,
	})
	if err != nil {
		span.RecordError(err)
		return MemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"group_roles",
			"role_id",
			roleId.String(),
			logger,
			"failed to update role",
		)
	}

	u, err := s.userStore.GetByID(ctx, userId)
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

	return MemberResponse{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		StudentID: u.StudentID.String,
		Role: Role{
			ID:          updatedRole.ID,
			Role:        updatedRole.Role.String,
			AccessLevel: updatedRole.AccessLevel,
		},
	}, nil
}
