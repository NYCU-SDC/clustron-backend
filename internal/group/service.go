package group

import (
	"clustron-backend/internal"
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"fmt"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"strconv"
	"strings"

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

type MembershipStore interface {
	HasGroupControlAccess(ctx context.Context, groupId uuid.UUID) bool
	GetByUser(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, error)
	GetOwnerByGroupID(ctx context.Context, groupID uuid.UUID) (uuid.UUID, error)
	UpdateRole(ctx context.Context, groupID uuid.UUID, userID uuid.UUID, roleID uuid.UUID) error
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
	memberStore  MembershipStore
	ldapClient   ldap.LDAPClient
}

func NewService(logger *zap.Logger, db DBTX, userStore UserStore, settingStore SettingStore, roleStore RoleStore, membershipStore MembershipStore, ldapClient ldap.LDAPClient) *Service {
	return &Service{
		logger:       logger,
		tracer:       otel.Tracer("group/service"),
		queries:      New(db),
		userStore:    userStore,
		roleStore:    roleStore,
		settingStore: settingStore,
		memberStore:  membershipStore,
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

func (s *Service) ListByIDWithUserScope(ctx context.Context, user jwt.User, groupID uuid.UUID) (grouprole.UserScope, error) {
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
		return grouprole.UserScope{}, err
	}

	// Get user role in the group
	roleResponse, roleType, err := s.roleStore.GetTypeByUser(traceCtx, user.Role, user.ID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group role type")
		span.RecordError(err)
		return grouprole.UserScope{}, err
	}

	// Basic user scope with group information
	response := grouprole.UserScope{
		Group: grouprole.Group{
			ID:          group.ID,
			Title:       group.Title,
			Description: group.Description,
			IsArchived:  group.IsArchived,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		},
	}

	// Set the user's role and type in the response
	response.Me.Type = roleType
	response.Me.Role = grouprole.Role(roleResponse)

	return response, nil
}

func (s *Service) ListByIDWithLinks(ctx context.Context, user jwt.User, groupID uuid.UUID) (ResponseWithLinks, error) {
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
		return ResponseWithLinks{}, err
	}

	// Get link by group ID
	links, err := s.queries.ListLinksByGroup(traceCtx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "links", "group_id", groupID.String(), logger, "Get group links")
		span.RecordError(err)
		return ResponseWithLinks{}, err
	}

	// Get user role in the group
	roleResponse, roleType, err := s.roleStore.GetTypeByUser(traceCtx, user.Role, user.ID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "Get group role type")
		span.RecordError(err)
		return ResponseWithLinks{}, err
	}

	response := ResponseWithLinks{
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
	traceCtx, span := s.tracer.Start(ctx, "CreateInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var (
		newGroup  Group
		groupName string
		err       error
		gidNumber int
		uidNumber int
	)

	saga := internal.NewSaga(s.logger)

	saga.AddStep(internal.SagaStep{
		Name: "CreateGroup",
		Action: func(ctx context.Context) error {
			newGroup, err = s.queries.Create(ctx, group)
			if err != nil {
				err = databaseutil.WrapDBError(err, logger, "failed to create group")
				span.RecordError(err)
				return err
			}
			groupName = newGroup.ID.String()
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if newGroup.ID == uuid.Nil {
				return nil
			}
			err := s.queries.Delete(ctx, newGroup.ID)
			if err != nil {
				s.logger.Warn("failed to delete group in compensation", zap.Error(err), zap.String("group_id", newGroup.ID.String()))
			}
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "GetSettingByUserID",
		Action: func(ctx context.Context) error {
			_, err := s.settingStore.GetSettingByUserID(ctx, userID)
			if err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", userID.String(), logger, "failed to get user setting")
				span.RecordError(err)
				return err
			}
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "GetAvailableGidNumber",
		Action: func(ctx context.Context) error {
			gidNumber, err = s.GetAvailableGidNumber(ctx)
			if err != nil {
				logger.Warn("get available gid number failed", zap.Error(err))
				return err
			}
			logger.Info("gidNumber", zap.Int("gidNumber", gidNumber))
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "GetAvailableUidNumber",
		Action: func(ctx context.Context) error {
			uidNumber, err = s.userStore.GetAvailableUidNumber(ctx)
			if err != nil {
				logger.Warn("get available uid number failed", zap.Error(err))
				return err
			}
			logger.Info("uidNumber", zap.Int("uidNumber", uidNumber))
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "CreateLDAPGroup",
		Action: func(ctx context.Context) error {
			if groupName == "" {
				groupName = newGroup.ID.String()
			}
			err = s.ldapClient.CreateGroup(groupName, strconv.Itoa(gidNumber), []string{})
			if err != nil {
				logger.Warn("create LDAP group failed", zap.String("group", groupName), zap.Error(err))
				return err
			}
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if groupName == "" {
				return nil
			}
			err = s.ldapClient.DeleteGroup(groupName)
			if err != nil {
				s.logger.Warn("failed to delete LDAP group in compensation", zap.Error(err), zap.String("group_name", groupName))
			}
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "UpdateGidNumber",
		Action: func(ctx context.Context) error {
			if gidNumber == 0 {
				return fmt.Errorf("gid number is not set")
			}
			err = s.queries.UpdateGidNumber(ctx, UpdateGidNumberParams{
				ID:        newGroup.ID,
				GidNumber: pgtype.Int4{Int32: int32(gidNumber), Valid: true},
			})
			if err != nil {
				logger.Warn("set gid number failed", zap.Error(err))
				return err
			}
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if newGroup.ID == uuid.Nil {
				return nil
			}
			err = s.queries.UpdateGidNumber(ctx, UpdateGidNumberParams{
				ID:        newGroup.ID,
				GidNumber: pgtype.Int4{Int32: 0, Valid: false},
			})
			if err != nil {
				s.logger.Warn("failed to reset gid number in compensation", zap.Error(err), zap.String("group_id", newGroup.ID.String()))
			}
			return nil
		},
	})

	err = saga.Execute(traceCtx)
	if err != nil {
		s.logger.Error("saga execution failed", zap.Error(err))
		return Group{}, err
	}

	return newGroup, nil
}

func (s *Service) Archive(ctx context.Context, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Archive")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var (
		group   Group
		err     error
		members []Membership
	)

	members, err = s.queries.GetMembersByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to get members by group id")
		span.RecordError(err)
		return Group{}, err
	}

	saga := internal.NewSaga(s.logger)

	saga.AddStep(internal.SagaStep{
		Name: "ArchiveGroup",
		Action: func(ctx context.Context) error {
			group, err = s.queries.Archive(ctx, groupID)
			if err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to archive group")
				span.RecordError(err)
				return err
			}

			return nil
		},
		Compensate: func(ctx context.Context) error {
			_, err := s.queries.Unarchive(ctx, group.ID)
			if err != nil {
				s.logger.Warn("failed to unarchive group in compensation", zap.Error(err), zap.String("group_id", group.ID.String()))
			}
			return err
		},
	})

	for _, member := range members {
		saga.AddStep(internal.SagaStep{
			Name: "RemoveUsersFromLDAPGroup",
			Action: func(ctx context.Context) error {
				userSetting, err := s.settingStore.GetSettingByUserID(ctx, member.UserID)
				if err != nil {
					err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", member.UserID.String(), logger, "failed to get user setting")
					span.RecordError(err)
					return err
				}

				err = s.ldapClient.RemoveUserFromGroup(group.ID.String(), userSetting.LinuxUsername.String)
				if err != nil {
					logger.Error("remove user from LDAP group failed", zap.String("group", group.ID.String()), zap.String("user", userSetting.LinuxUsername.String), zap.Error(err))
					span.RecordError(err)
					return err
				}
				return nil
			},
			Compensate: func(ctx context.Context) error {
				userSetting, err := s.settingStore.GetSettingByUserID(ctx, member.UserID)
				if err != nil {
					err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", member.UserID.String(), logger, "failed to get user setting")
					span.RecordError(err)
					return err
				}

				err = s.ldapClient.AddUserToGroup(group.ID.String(), userSetting.LinuxUsername.String)
				if err != nil {
					logger.Error("add user back to LDAP group failed", zap.String("group", group.ID.String()), zap.String("user", userSetting.LinuxUsername.String), zap.Error(err))
					span.RecordError(err)
					return err
				}
				return nil
			},
		})
	}

	err = saga.Execute(traceCtx)
	if err != nil {
		s.logger.Error("saga execution failed", zap.Error(err))
		return Group{}, err
	}

	return group, nil
}

func (s *Service) Unarchive(ctx context.Context, groupID uuid.UUID) (Group, error) {
	traceCtx, span := s.tracer.Start(ctx, "Unarchive")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	var (
		group   Group
		err     error
		members []Membership
	)

	members, err = s.queries.GetMembersByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to get members by group id")
		span.RecordError(err)
		return Group{}, err
	}

	saga := internal.NewSaga(s.logger)

	saga.AddStep(internal.SagaStep{
		Name: "UnarchiveGroup",
		Action: func(ctx context.Context) error {
			group, err = s.queries.Unarchive(ctx, groupID)
			if err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "groups", "group_id", groupID.String(), logger, "failed to unarchive group")
				span.RecordError(err)
				return err
			}

			return nil
		},
		Compensate: func(ctx context.Context) error {
			_, err := s.queries.Archive(ctx, groupID)
			if err != nil {
				s.logger.Warn("failed to archive group in compensation", zap.Error(err), zap.String("group_id", groupID.String()))
			}
			return err
		},
	})

	for _, member := range members {
		saga.AddStep(internal.SagaStep{
			Name: "AddUsersToLDAPGroup",
			Action: func(ctx context.Context) error {
				userSetting, err := s.settingStore.GetSettingByUserID(ctx, member.UserID)
				if err != nil {
					err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", member.UserID.String(), logger, "failed to get user setting")
					span.RecordError(err)
					return err
				}

				err = s.ldapClient.AddUserToGroup(group.ID.String(), userSetting.LinuxUsername.String)
				if err != nil {
					logger.Error("add user to LDAP group failed", zap.String("group", group.ID.String()), zap.String("user", userSetting.LinuxUsername.String), zap.Error(err))
					span.RecordError(err)
					return err
				}
				return nil
			},
			Compensate: func(ctx context.Context) error {
				userSetting, err := s.settingStore.GetSettingByUserID(ctx, member.UserID)
				if err != nil {
					err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", member.UserID.String(), logger, "failed to get user setting")
					span.RecordError(err)
					return err
				}

				err = s.ldapClient.RemoveUserFromGroup(group.ID.String(), userSetting.LinuxUsername.String)
				if err != nil {
					logger.Error("remove user from LDAP group failed", zap.String("group", group.ID.String()), zap.String("user", userSetting.LinuxUsername.String), zap.Error(err))
					span.RecordError(err)
					return err
				}
				return nil
			},
		})
	}

	err = saga.Execute(traceCtx)
	if err != nil {
		s.logger.Error("saga execution failed", zap.Error(err))
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

func (s *Service) TransferOwner(ctx context.Context, groupID uuid.UUID, newOwnerIdentifier string, user jwt.User) (grouprole.UserScope, error) {
	traceCtx, span := s.tracer.Start(ctx, "TransferOwner")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.memberStore.GetByUser(traceCtx, user.ID, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), user.ID.String()), logger, "get membership")
		span.RecordError(err)
		return grouprole.UserScope{}, err
	}
	if membership.AccessLevel != grouprole.AccessLevelOwner.String() || user.Role != role.Admin.String() {
		err = fmt.Errorf("user %s is not the owner of group %s", user.ID.String(), groupID.String())
		logger.Error("transfer owner failed", zap.Error(err))
		span.RecordError(err)
		return grouprole.UserScope{}, err
	}

	var newOwnerID uuid.UUID
	if strings.Contains(newOwnerIdentifier, "@") {
		newOwnerID, err = s.userStore.GetIdByEmail(traceCtx, newOwnerIdentifier)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to get user by email")
			span.RecordError(err)
			return grouprole.UserScope{}, err
		}
	} else {
		newOwnerID, err = s.userStore.GetIdByStudentId(traceCtx, newOwnerIdentifier)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to get user by student id")
			span.RecordError(err)
			return grouprole.UserScope{}, err
		}
	}

	var oldOwnerID uuid.UUID
	oldOwnerID, err = s.memberStore.GetOwnerByGroupID(traceCtx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "membership", "group_id", groupID.String(), logger, "get group owner")
		span.RecordError(err)
		return grouprole.UserScope{}, err
	}

	err = s.memberStore.UpdateRole(traceCtx, groupID, newOwnerID, uuid.MustParse(grouprole.RoleOwner.String()))
	if err != nil {
		return grouprole.UserScope{}, err
	}
	err = s.memberStore.UpdateRole(traceCtx, groupID, oldOwnerID, uuid.MustParse(grouprole.RoleStudent.String()))
	if err != nil {
		return grouprole.UserScope{}, err
	}

	userScope, err := s.ListByIDWithUserScope(traceCtx, user, groupID)
	if err != nil {
		return grouprole.UserScope{}, err
	}

	return userScope, nil
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

func (s *Service) CreateLink(ctx context.Context, groupID uuid.UUID, title string, Url string) (Link, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateLink")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.memberStore.HasGroupControlAccess(traceCtx, groupID) {
		logger.Warn("The user's access is not allowed to control this group")
		return Link{}, handlerutil.ErrForbidden
	}

	// create the link
	newLink, err := s.queries.CreateLink(traceCtx, CreateLinkParams{
		GroupID: groupID,
		Title:   title,
		Url:     Url,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "links", "group_id", groupID.String(), logger, "create link")
		span.RecordError(err)
		return Link{}, err
	}

	return newLink, nil
}

func (s *Service) UpdateLink(ctx context.Context, groupID uuid.UUID, linkID uuid.UUID, title string, Url string) (Link, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateLink")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.memberStore.HasGroupControlAccess(traceCtx, groupID) {
		logger.Warn("The user's access is not allowed to control this group")
		return Link{}, handlerutil.ErrForbidden
	}

	// update the link
	updatedLink, err := s.queries.UpdateLink(traceCtx, UpdateLinkParams{
		ID:    linkID,
		Title: title,
		Url:   Url,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "links", "link_id", linkID.String(), logger, "update link")
		span.RecordError(err)
		return Link{}, err
	}

	return updatedLink, nil
}

func (s *Service) DeleteLink(ctx context.Context, groupID uuid.UUID, linkID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeleteLink")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.memberStore.HasGroupControlAccess(traceCtx, groupID) {
		logger.Warn("The user's access is not allowed to control this group")
		return handlerutil.ErrForbidden
	}

	// delete the link
	err := s.queries.DeleteLink(traceCtx, linkID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "links", "link_id", linkID.String(), logger, "delete link")
		span.RecordError(err)
		return err
	}

	return nil
}
