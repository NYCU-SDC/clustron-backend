package group

import (
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"fmt"
	"strconv"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const StartGidNumber = 10000

type RoleStore interface {
	GetTypeByUser(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, string, error)
	GetByID(ctx context.Context, roleID uuid.UUID) (grouprole.GroupRole, error)
}

type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (user.User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
	GetAvailableUidNumber(ctx context.Context) (int, error)
	SetUidNumber(ctx context.Context, userID uuid.UUID, uidNumber int) error
}

type SettingStore interface {
	GetSettingByUserID(ctx context.Context, userID uuid.UUID) (setting.Setting, error)
	GetPublicKeysByUserID(ctx context.Context, userID uuid.UUID) ([]setting.PublicKey, error)
}

type Service struct {
	logger       *zap.Logger
	tracer       trace.Tracer
	queries      *Queries
	userStore    UserStore
	roleStore    RoleStore
	settingStore SettingStore
	ldapClient   ldap.LDAPClient
}

func NewService(logger *zap.Logger, db DBTX, userStore UserStore, settingStore SettingStore, roleStore RoleStore, ldapClient ldap.LDAPClient) *Service {
	return &Service{
		logger:       logger,
		tracer:       otel.Tracer("group/service"),
		queries:      New(db),
		userStore:    userStore,
		roleStore:    roleStore,
		settingStore: settingStore,
		ldapClient:   ldapClient,
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

func (s *Service) ListWithUserScope(ctx context.Context, user jwt.User, page int, size int, sort string, sortBy string) ([]grouprole.UserScope, int /* totalCount */, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListWithUserScope")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var response []grouprole.UserScope
	var totalCount int
	if user.Role == role.Admin.String() {
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
		response = make([]grouprole.UserScope, len(groups))
		for i, group := range groups {
			response[i] = grouprole.UserScope{
				Group: grouprole.Group{
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
			response[i].Me.Role = grouprole.Role(role)
		}
	}

	return response, totalCount, nil
}

func buildRoleGroupIDMap(roles []ListMembershipsByUserRow) map[uuid.UUID]grouprole.Role {
	m := make(map[uuid.UUID]grouprole.Role)
	for _, r := range roles {
		m[r.GroupID] = grouprole.Role{
			ID:          r.RoleID,
			RoleName:    r.RoleName,
			AccessLevel: r.AccessLevel,
		}
	}

	return m
}

func buildUserScopeGroups(groups []Group, roleMap map[uuid.UUID]grouprole.Role, isAdmin bool) []grouprole.UserScope {
	result := make([]grouprole.UserScope, len(groups))
	for i, g := range groups {
		scope := grouprole.UserScope{
			Group: grouprole.Group{
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
	if sort == "asc" {
		logger.Info("list in asc, sortBy", zap.String("sortBy", sortBy))
		params := ListAscPagedParams{
			Size: int32(size),
			Skip: int32(page) * int32(size),
		}
		groups, err = s.queries.ListAscPaged(ctx, params)
	} else {
		logger.Info("list in desc, sortBy", zap.String("sortBy", sortBy))
		params := ListDescPagedParams{
			Size: int32(size),
			Skip: int32(page) * int32(size),
		}
		groups, err = s.queries.ListDescPaged(ctx, params)
	}
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get groups")
		span.RecordError(err)
		return nil, err
	}

	return groups, nil
}

func (s *Service) ListByIDWithUserScope(ctx context.Context, user jwt.User, groupID uuid.UUID) (WithLinks, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListByIDWithUserScope")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Get group by ID
	var group Group
	var err error
	if user.Role != role.Admin.String() {
		group, err = s.GetUserGroupByID(traceCtx, user.ID, groupID)
	} else {
		group, err = s.Get(traceCtx, groupID)
	}
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group by id")
		span.RecordError(err)
		return WithLinks{}, err
	}

	// Get link by group ID
	links, err := s.queries.ListLinksByGroup(traceCtx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "links", "group_id", groupID.String(), logger, "Get group links")
		span.RecordError(err)
		return WithLinks{}, err
	}

	// Get user role in the group
	roleResponse, roleType, err := s.roleStore.GetTypeByUser(traceCtx, user.Role, user.ID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group role type")
		span.RecordError(err)
		return WithLinks{}, err
	}

	response := WithLinks{
		// Basic user scope with group information
		UserScope: grouprole.UserScope{
			Group: grouprole.Group{
				ID:          group.ID,
				Title:       group.Title,
				Description: group.Description,
				IsArchived:  group.IsArchived,
				CreatedAt:   group.CreatedAt,
				UpdatedAt:   group.UpdatedAt,
			},
		},
	}

	// Set the user's role and type in the response
	response.Me.Type = roleType
	response.Me.Role = grouprole.Role(roleResponse)

	// Convert links to the response format
	response.Links = make([]Link, len(links))
	for i, link := range links {
		response.Links[i] = Link{
			ID:    link.ID,
			Title: link.Title,
			Url:   link.Url,
		}
	}

	return response, nil
}

func (s *Service) listByUserID(ctx context.Context, userID uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, []GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "listByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if sort == "asc" {
		params := ListIfMemberAscPagedParams{
			UserID: userID,
			Size:   int32(size),
			Skip:   int32(page) * int32(size),
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
				RoleName:    r.RoleName,
				AccessLevel: r.AccessLevel,
			}
		}
		return groups, roles, nil
	} else {
		params := ListIfMemberDescPagedParams{
			UserID: userID,
			Size:   int32(size),
			Skip:   int32(page) * int32(size),
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
				RoleName:    r.RoleName,
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

	group, err := s.queries.GetByID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to get group by id")
		span.RecordError(err)
		return Group{}, err
	}

	return group, nil
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, group CreateParams) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Create")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	newGroup, err := s.queries.Create(ctx, group)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to create group")
		span.RecordError(err)
		return Group{}, err
	}

	userSetting, err := s.settingStore.GetSettingByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", userID.String(), logger, "failed to get user setting")
		span.RecordError(err)
		return Group{}, err
	}

	// Create LDAP group
	groupName := newGroup.ID.String()
	gidNumber, err := s.GetAvailableGidNumber(ctx)
	if err != nil {
		logger.Warn("get available gid number failed", zap.Error(err))
	}
	uidNumber, err := s.userStore.GetAvailableUidNumber(ctx)
	logger.Info("gidNumber", zap.Int("gidNumber", gidNumber))
	if err != nil {
		logger.Warn("get available gid number failed", zap.Error(err))
	} else {
		err = s.ldapClient.CreateGroup(groupName, strconv.Itoa(gidNumber), []string{})
		if err != nil {
			logger.Warn("create LDAP group failed", zap.String("group", groupName), zap.Error(err))
		} else {
			err = s.queries.UpdateGidNumber(ctx, UpdateGidNumberParams{
				ID:        newGroup.ID,
				GidNumber: pgtype.Int4{Int32: int32(gidNumber), Valid: true},
			})
			if err != nil {
				logger.Warn("set gid number failed", zap.Error(err))
			}
		}

		// get public key
		publicKeys, err := s.settingStore.GetPublicKeysByUserID(ctx, userID)
		if err != nil {
			logger.Warn("get public key failed", zap.Error(err))
		}
		// create LDAP user
		err = s.ldapClient.CreateUser(userSetting.LinuxUsername.String, userSetting.FullName.String, userSetting.FullName.String, "", strconv.Itoa(uidNumber))
		// add public key to LDAP user
		for _, publicKey := range publicKeys {
			err = s.ldapClient.AddSSHPublicKey(userSetting.LinuxUsername.String, publicKey.PublicKey)
			if err != nil {
				logger.Warn("add public key to LDAP user failed", zap.String("publicKey", publicKey.PublicKey), zap.Error(err))
			}
		}
		if err != nil {
			if errors.Is(err, ldap.ErrUserExists) {
				logger.Info("user already exists", zap.String("uid", userSetting.LinuxUsername.String))
			} else {
				logger.Warn("create LDAP user failed", zap.String("userID", userID.String()), zap.Int("uid", uidNumber), zap.Error(err))
			}
		} else {
			err = s.userStore.SetUidNumber(ctx, userID, uidNumber)
			if err != nil {
				logger.Warn("set uid number failed", zap.Error(err))
			}
		}
		// add user to LDAP group
		if groupName != "" && uidNumber != 0 {
			err = s.ldapClient.AddUserToGroup(groupName, userSetting.LinuxUsername.String)
			if err != nil {
				logger.Warn("add user to LDAP group failed", zap.String("group", groupName), zap.Int("uid", uidNumber), zap.Error(err))
			}
		}
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

func (s *Service) GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRelationShip")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetMembershipByUser(ctx, GetMembershipByUserParams{
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

func (s *Service) GetByID(ctx context.Context, roleID uuid.UUID) (grouprole.GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetGroupRoleByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groupRole, err := s.roleStore.GetByID(ctx, roleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "get group role by id")
		span.RecordError(err)
		return grouprole.GroupRole{}, err
	}

	return groupRole, nil
}

func (s *Service) GetTypeByUser(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetUserGroupRoleType")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groupRole, roleType, err := s.roleStore.GetTypeByUser(traceCtx, userRole, userID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get membership")
		span.RecordError(err)
		return grouprole.GroupRole{}, "", err
	}

	return groupRole, roleType, nil
}

/*
To find the lowest unused gidNumber >= StartGidNumber for LDAP groups.
It queries all used gidNumbers, builds a set, and returns the first available one.
*/
func (s *Service) GetAvailableGidNumber(ctx context.Context) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAvailableGidNumber")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	usedGidNumbers, err := s.queries.ListGidNumbers(ctx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get available gid number")
		span.RecordError(err)
		return 0, err
	}

	next := StartGidNumber
	usedSet := make(map[int32]struct{}, len(usedGidNumbers))
	for _, n := range usedGidNumbers {
		usedSet[int32(n.Int32)] = struct{}{}
	}

	for {
		if _, ok := usedSet[int32(next)]; !ok {
			return int(next), nil
		}
		next++
	}
}
