package membership

import (
	"clustron-backend/internal"
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/setting"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:generate mockery --name GroupRoleStore
type GroupRoleStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (grouprole.GroupRole, error)
	GetByUser(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, error)
}

//go:generate mockery --name UserStore
type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (user.User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
	ExistsByIdentifier(ctx context.Context, identifier string) (bool, error)
}

//go:generate mockery --name SettingStore
type SettingStore interface {
	GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (setting.LDAPUserInfo, error)
	GetAllUserByUIDNumber(ctx context.Context, uidNumbers []int64) (map[int64]setting.User, error)
}

type GroupStore interface {
	GetLDAPBaseGroupCNByGroupID(ctx context.Context, groupID uuid.UUID) (string, error)
	GetLDAPAdminGroupCNByGroupID(ctx context.Context, groupID uuid.UUID) (string, error)
}

type LDAPClient interface {
	AddUserToGroup(groupCN string, username string) error
	RemoveUserFromGroup(groupCN string, username string) error
	GetGroupInfo(groupCN string) (*ldap.Entry, error)
	GetAllUserByUIDList(uidList []string) ([]*ldap.Entry, error)
}

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	db      *pgxpool.Pool
	queries *Queries

	userStore      UserStore
	groupRoleStore GroupRoleStore
	groupStore     GroupStore
	settingStore   SettingStore
	ldapClient     LDAPClient
}

func NewService(logger *zap.Logger, db *pgxpool.Pool, userStore UserStore, groupRoleStore GroupRoleStore, settingStore SettingStore, groupStore GroupStore, ldapClient LDAPClient) *Service {
	return &Service{
		logger:         logger,
		tracer:         otel.Tracer("membership/service"),
		db:             db,
		queries:        New(db),
		userStore:      userStore,
		groupRoleStore: groupRoleStore,
		settingStore:   settingStore,
		groupStore:     groupStore,
		ldapClient:     ldapClient,
	}
}

func (s *Service) ListWithPaged(ctx context.Context, groupId uuid.UUID, page int, size int, sortDir string, sortBy string) ([]Response, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListWithPaged")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		return nil, handlerutil.ErrForbidden
	}

	// get base group member list from LDAP
	ldapBaseGroupCN, err := s.groupStore.GetLDAPBaseGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupId.String(), logger, "get LDAP base group CN by group ID")
		logger.Error("get ldap base group cn failed", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	baseEntries, err := s.getLDAPMember(ldapBaseGroupCN)
	if err != nil {
		logger.Error("get ldap base group info failed", zap.String("group_cn", ldapBaseGroupCN), zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	// get admin group member list from LDAP
	ldapAdminGroupCN, err := s.groupStore.GetLDAPAdminGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupId.String(), logger, "get LDAP admin group CN by group ID")
		logger.Error("get ldap admin group cn failed", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	adminEntries, err := s.getLDAPMember(ldapAdminGroupCN)
	if err != nil {
		logger.Error("get ldap admin group info failed", zap.String("group_cn", ldapAdminGroupCN), zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	ldapEntryMap := make(map[int64]*ldap.Entry)
	allUIDNumbers := make([]int64, 0)

	processEntries := func(entries []*ldap.Entry) {
		for _, entry := range entries {
			var uidNum int64
			if _, err := fmt.Sscanf(entry.GetAttributeValue("uidNumber"), "%d", &uidNum); err == nil {
				if _, exists := ldapEntryMap[uidNum]; !exists {
					ldapEntryMap[uidNum] = entry
					allUIDNumbers = append(allUIDNumbers, uidNum)
				}
			}
		}
	}

	processEntries(baseEntries)
	processEntries(adminEntries)

	dbUserMap, err := s.settingStore.GetAllUserByUIDNumber(traceCtx, allUIDNumbers)
	if err != nil {
		logger.Warn("failed to fetch user IDs from DB, proceeding with LDAP data only", zap.Error(err))
	}

	allMembers := make([]Response, 0)
	for uidNum, entry := range ldapEntryMap {
		res := Response{
			UIDNumber: uidNum,
			UID:       entry.GetAttributeValue("uid"),
		}

		if userInfo, exist := dbUserMap[uidNum]; exist {
			res.ID = userInfo.ID
			res.FullName = userInfo.FullName.String
			res.Email = userInfo.Email
			res.StudentID = userInfo.StudentID.String
			res.OnlyInLDAP = false
			member, err := s.GetByUser(traceCtx, userInfo.ID, groupId)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					res.Role = grouprole.RoleResponse{
						ID:          uuid.Nil.String(),
						RoleName:    grouprole.RoleUnknown.String(),
						AccessLevel: grouprole.AccessLevelUnknown.String(),
					}
				}
			}
			res.Role = grouprole.RoleResponse{
				ID:          member.ID.String(),
				RoleName:    member.RoleName,
				AccessLevel: member.AccessLevel,
			}
		} else {
			res.OnlyInLDAP = true
			res.FullName = entry.GetAttributeValue("cn")
			res.Role = grouprole.RoleResponse{
				ID:          uuid.Nil.String(),
				RoleName:    grouprole.RoleUnknown.String(),
				AccessLevel: grouprole.AccessLevelUnknown.String(),
			}
		}
		allMembers = append(allMembers, res)
	}

	sort.Slice(allMembers, func(i, j int) bool {
		if sortDir == "desc" {
			return allMembers[i].UIDNumber > allMembers[j].UIDNumber
		}
		return allMembers[i].UIDNumber < allMembers[j].UIDNumber
	})

	totalCount := len(allMembers)
	startIndex := page * size
	endIndex := startIndex + size

	if startIndex >= totalCount {
		return []Response{}, nil
	}
	if endIndex > totalCount {
		endIndex = totalCount
	}

	pagedMembers := allMembers[startIndex:endIndex]

	return pagedMembers, nil
}

func (s *Service) GetByUser(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (grouprole.GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Get user role
	membership, err := s.queries.GetByUser(traceCtx, GetByUserParams{
		UserID:  userId,
		GroupID: groupId,
	})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get user role")
		span.RecordError(err)
		return grouprole.GroupRole{}, err
	}

	return grouprole.GroupRole{
		ID:          membership.RoleID,
		RoleName:    membership.RoleName,
		AccessLevel: membership.AccessLevel,
	}, nil
}

func (s *Service) GetOwnerByGroupID(ctx context.Context, groupId uuid.UUID) (uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetOwnerByGroupID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Get group owner
	membership, err := s.queries.GetOwnerByGroupID(traceCtx, groupId)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group members")
		span.RecordError(err)
		return uuid.UUID{}, err
	}

	return membership, nil
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
	if !s.HasGroupControlAccess(traceCtx, groupId) {
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
		pendingMember, err := s.JoinPending(traceCtx, CreateOrUpdatePendingParams{
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
	member, err := s.Join(traceCtx, memberUserId, groupId, role, false)
	if err != nil {
		return nil, err
	}

	return member, nil
}

func (s *Service) JoinPending(ctx context.Context, params CreateOrUpdatePendingParams) (PendingMemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "JoinPending")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	pendingMember, err := s.queries.CreateOrUpdatePending(ctx, CreateOrUpdatePendingParams{
		UserIdentifier: params.UserIdentifier,
		GroupID:        params.GroupID,
		RoleID:         params.RoleID,
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "user_identifier/group_id/role_id", fmt.Sprintf("%s/%s/%s", params.UserIdentifier, params.GroupID.String(), params.RoleID.String()), logger, "failed to add pending member")
		span.RecordError(err)
		return PendingMemberResponse{}, err
	}

	// get role information
	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, pendingMember.RoleID)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group role")
		span.RecordError(err)
		return PendingMemberResponse{}, err
	}

	return PendingMemberResponse{
		ID:             pendingMember.ID,
		UserIdentifier: pendingMember.UserIdentifier,
		GroupID:        pendingMember.GroupID,
		Role: grouprole.RoleResponse{
			ID:          roleInfo.ID.String(),
			RoleName:    roleInfo.RoleName,
			AccessLevel: roleInfo.AccessLevel,
		},
	}, nil
}

func (s *Service) Join(ctx context.Context, userId uuid.UUID, groupId uuid.UUID, role uuid.UUID, isArchived bool) (MemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "Join")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		logger.Error("begin transaction failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			logger.Warn("failed to rollback transaction", zap.Error(err))
		}
	}(tx, ctx)

	q := s.queries.WithTx(tx)

	baseCN, err := s.groupStore.GetLDAPBaseGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		logger.Error("get ldap base group cn failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	adminCN, err := s.groupStore.GetLDAPAdminGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		logger.Error("get ldap admin group cn failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	member, err := q.CreateOrUpdate(traceCtx, CreateOrUpdateParams{
		GroupID: groupId,
		UserID:  userId,
		RoleID:  role,
	})

	u, err := s.userStore.GetByID(traceCtx, userId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "user_id", userId.String(), logger, "failed to get user info")
		logger.Error("get user info failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	ldapUserInfo, err := s.settingStore.GetLDAPUserInfoByUserID(traceCtx, userId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "user_id", userId.String(), logger, "failed to get ldap user info")
		logger.Error("get ldap user info failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, member.RoleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_roles", "role_id", member.RoleID.String(), logger, "failed to get group role")
		logger.Error("get group role failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	saga := internal.NewSaga(s.logger)

	// Add user to LDAP admin group
	accessLevel := grouprole.AccessLevel(roleInfo.AccessLevel)
	if accessLevel == grouprole.AccessLevelOwner || accessLevel == grouprole.AccessLevelAdmin {
		saga.AddStep(internal.SagaStep{
			Name: "AddUserToLDAPAdminGroup",
			Action: func(ctx context.Context) error {
				err = s.ldapClient.AddUserToGroup(adminCN, ldapUserInfo.Username)
				if err != nil {
					logger.Error("add user to ldap admin group failed", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				logger.Debug("add user to ldap admin group succeeded", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username))
				return nil
			},
			Compensate: func(ctx context.Context) error {
				err = s.ldapClient.RemoveUserFromGroup(adminCN, ldapUserInfo.Username)
				if err != nil {
					logger.Error("remove user from ldap admin group failed", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				logger.Debug("add user to ldap admin group succeeded", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username))
				return nil
			},
		})
	} else {
		saga.AddStep(internal.SagaStep{
			Name: "AddUserToLDAPBaseGroup",
			Action: func(ctx context.Context) error {
				err = s.ldapClient.AddUserToGroup(baseCN, ldapUserInfo.Username)
				if err != nil {
					logger.Error("add user to ldap base group failed", zap.String("group", baseCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				return nil
			},
			Compensate: func(ctx context.Context) error {
				err = s.ldapClient.RemoveUserFromGroup(baseCN, ldapUserInfo.Username)
				if err != nil {
					logger.Error("remove user from ldap base group failed", zap.String("group", baseCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				return nil
			},
		})
	}

	err = saga.Execute(ctx)
	if err != nil {
		logger.Error("saga execution failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		logger.Error("commit transaction failed", zap.Error(err))
		span.RecordError(err)
		return MemberResponse{}, err
	}

	return MemberResponse{
		ID:        u.ID,
		FullName:  u.FullName.String,
		Email:     u.Email,
		StudentID: u.StudentID.String,
		Role: grouprole.RoleResponse{
			ID:          roleInfo.ID.String(),
			RoleName:    roleInfo.RoleName,
			AccessLevel: roleInfo.AccessLevel,
		},
	}, nil
}

func (s *Service) Remove(ctx context.Context, groupId uuid.UUID, userId uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Remove")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	membership, err := s.queries.GetByUser(traceCtx, GetByUserParams{
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
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, membership.RoleID) {
		logger.Warn("The user's access is not allowed to remove this member")
		return handlerutil.ErrForbidden
	}

	// Remove the user from LDAP group
	baseCN, err := s.groupStore.GetLDAPBaseGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupId.String(), logger, "get LDAP base group CN by group ID")
		logger.Error("get ldap base group cn failed", zap.Error(err))
		span.RecordError(err)
		return err
	}

	adminCN, err := s.groupStore.GetLDAPAdminGroupCNByGroupID(traceCtx, groupId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_group", "group_id", groupId.String(), logger, "get LDAP admin group CN by group ID")
		logger.Error("get ldap admin group cn failed", zap.Error(err))
		span.RecordError(err)
		return err
	}

	ldapUserInfo, err := s.settingStore.GetLDAPUserInfoByUserID(traceCtx, userId)

	saga := internal.NewSaga(s.logger)
	saga.AddStep(internal.SagaStep{
		Name: "RemoveUserFromLDAPGroup",
		Action: func(ctx context.Context) error {
			err = s.ldapClient.RemoveUserFromGroup(baseCN, ldapUserInfo.Username)
			if err != nil {
				logger.Warn("remove user from LDAP group failed", zap.String("group", baseCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
				return err
			}
			return nil
		},
		Compensate: func(ctx context.Context) error {
			err = s.ldapClient.AddUserToGroup(baseCN, ldapUserInfo.Username)
			if err != nil {
				logger.Warn("add user to LDAP group failed", zap.String("group", baseCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
				return err
			}
			return nil
		},
	})

	if grouprole.AccessLevel(roleInfo.AccessLevel) == grouprole.AccessLevelOwner || grouprole.AccessLevel(roleInfo.AccessLevel) == grouprole.AccessLevelAdmin {
		saga.AddStep(internal.SagaStep{
			Name: "RemoveUserFromLDAPAdminGroup",
			Action: func(ctx context.Context) error {
				err = s.ldapClient.RemoveUserFromGroup(adminCN, ldapUserInfo.Username)
				if err != nil {
					logger.Warn("remove user from LDAP admin group failed", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				return nil
			},
			Compensate: func(ctx context.Context) error {
				err = s.ldapClient.AddUserToGroup(adminCN, ldapUserInfo.Username)
				if err != nil {
					logger.Warn("add user to LDAP admin group failed", zap.String("group", adminCN), zap.String("username", ldapUserInfo.Username), zap.Error(err))
					return err
				}
				return nil
			},
		})
	}

	saga.AddStep(internal.SagaStep{
		Name: "DeleteMembership",
		Action: func(ctx context.Context) error {
			err = s.queries.Delete(traceCtx, DeleteParams{
				GroupID: groupId,
				UserID:  userId,
			})
			if err != nil {
				span.RecordError(err)
				return databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id/user_id", fmt.Sprintf("%s/%s", groupId, userId), logger, "failed to remove group member")
			}
			return nil
		},
		Compensate: func(ctx context.Context) error {
			_, err = s.queries.CreateOrUpdate(traceCtx, CreateOrUpdateParams{
				GroupID: groupId,
				UserID:  userId,
				RoleID:  membership.RoleID,
			})
			if err != nil {
				span.RecordError(err)
				return databaseutil.WrapDBErrorWithKeyValue(err, "memberships", "group_id/user_id", fmt.Sprintf("%s/%s", groupId, userId), logger, "failed to restore group member")
			}
			return nil
		},
	})

	err = saga.Execute(ctx)
	if err != nil {
		logger.Warn("saga execution failed", zap.Error(err))
		span.RecordError(err)
		return err
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
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return MemberResponse{}, handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, role) {
		logger.Warn("The user's access is not allowed to update this member")
		return MemberResponse{}, handlerutil.ErrForbidden
	}

	updatedMembership, err := s.queries.UpdateRole(ctx, UpdateRoleParams{
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
		FullName:  u.FullName.String,
		Email:     u.Email,
		StudentID: u.StudentID.String,
		Role: grouprole.RoleResponse{
			ID:          roleResponse.ID.String(),
			RoleName:    roleResponse.RoleName,
			AccessLevel: roleResponse.AccessLevel,
		},
	}, nil
}

func (s *Service) UpdateRole(ctx context.Context, groupId uuid.UUID, userId uuid.UUID, role uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "UpdateRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, role) {
		logger.Warn("The user's access is not allowed to update this member")
		return handlerutil.ErrForbidden
	}

	_, err := s.queries.UpdateRole(ctx, UpdateRoleParams{
		GroupID: groupId,
		UserID:  userId,
		RoleID:  role,
	})
	if err != nil {
		span.RecordError(err)
		return databaseutil.WrapDBErrorWithKeyValue(
			err,
			"memberships",
			"group_id/user_id",
			fmt.Sprintf("%s/%s", groupId, userId),
			logger,
			"failed to update membership",
		)
	}

	return err
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

	membership, err := s.queries.GetByUser(traceCtx, GetByUserParams{
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

func (s *Service) HasGroupControlAccess(ctx context.Context, groupId uuid.UUID) bool {
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

func (s *Service) ListPendingWithPaged(ctx context.Context, groupId uuid.UUID, page int, size int, sort string, sortBy string) ([]PendingMemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListPendingWithPaged")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the user has access to the group (group owner or group admin)
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return nil, handlerutil.ErrForbidden
	}

	var pendingMembers []PendingMemberResponse
	if sort == "desc" {
		params := ListPendingMembersDescPagedParams{
			GroupID: groupId,
			//Sortby:  sortBy,	//TODO: Implement various query with corresponding sortBy
			Size: int32(size),
			Skip: int32(page) * int32(size),
		}
		res, err := s.queries.ListPendingMembersDescPaged(traceCtx, params)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to list pending group members")
			span.RecordError(err)
			return nil, err
		}
		pendingMembers = make([]PendingMemberResponse, len(res))
		for i, member := range res {
			pendingMembers[i] = PendingMemberResponse{
				ID:             member.ID,
				UserIdentifier: member.UserIdentifier,
				GroupID:        member.GroupID,
				Role: grouprole.RoleResponse{
					ID:          member.RoleID.String(),
					RoleName:    member.RoleName,
					AccessLevel: member.AccessLevel,
				},
			}
		}
	} else {
		params := ListPendingMembersAscPagedParams{
			GroupID: groupId,
			//Sortby:  sortBy,	//TODO: Implement various query with corresponding sortBy
			Size: int32(size),
			Skip: int32(page) * int32(size),
		}
		res, err := s.queries.ListPendingMembersAscPaged(traceCtx, params)
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "failed to list pending group members")
			span.RecordError(err)
			return nil, err
		}
		pendingMembers = make([]PendingMemberResponse, len(res))
		for i, member := range res {
			pendingMembers[i] = PendingMemberResponse{
				ID:             member.ID,
				UserIdentifier: member.UserIdentifier,
				GroupID:        member.GroupID,
				Role: grouprole.RoleResponse{
					ID:          member.RoleID.String(),
					RoleName:    member.RoleName,
					AccessLevel: member.AccessLevel,
				},
			}
		}
	}

	return pendingMembers, nil
}

func (s *Service) UpdatePending(ctx context.Context, groupId uuid.UUID, pendingId uuid.UUID, role uuid.UUID) (PendingMemberResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdatePending")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// check if the role is group owner (it should never be allowed to update to group owner)
	roleInfo, err := s.groupRoleStore.GetByID(traceCtx, role)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get group role")
		span.RecordError(err)
		return PendingMemberResponse{}, err
	}
	isOwner := s.isGroupOwner(roleInfo)
	if isOwner {
		logger.Warn("Group role is owner, you cannot update to group owner")
		return PendingMemberResponse{}, handlerutil.ErrForbidden
	}

	// check if the user has access to the group (group owner or group admin)
	if !s.HasGroupControlAccess(traceCtx, groupId) {
		logger.Warn("The user's access is not allowed to control this group")
		return PendingMemberResponse{}, handlerutil.ErrForbidden
	}

	// check if the user's access_level is bigger than the target access_level
	if !s.canAssignRole(traceCtx, groupId, role) {
		logger.Warn("The user's access is not allowed to update this pending member")
		return PendingMemberResponse{}, handlerutil.ErrForbidden
	}

	// Get the pending member to verify it belongs to the correct group
	pendingMember, err := s.queries.GetPendingByID(traceCtx, pendingId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "id", pendingId.String(), logger, "failed to get pending member")
		span.RecordError(err)
		return PendingMemberResponse{}, err
	}

	if pendingMember.GroupID != groupId {
		logger.Warn("Pending member does not belong to the specified group")
		return PendingMemberResponse{}, handlerutil.NewNotFoundError("pending_memberships", "group_id", groupId.String(), "pending member does not belong to group")
	}

	updatedPending, err := s.queries.UpdatePendingByID(ctx, UpdatePendingByIDParams{
		RoleID: role,
		ID:     pendingId,
	})
	if err != nil {
		span.RecordError(err)
		return PendingMemberResponse{}, databaseutil.WrapDBErrorWithKeyValue(
			err,
			"pending_memberships",
			"id",
			pendingId.String(),
			logger,
			"failed to update pending membership",
		)
	}

	return PendingMemberResponse{
		ID:             updatedPending.ID,
		UserIdentifier: updatedPending.UserIdentifier,
		GroupID:        updatedPending.GroupID,
		Role: grouprole.RoleResponse{
			ID:          roleInfo.ID.String(),
			RoleName:    roleInfo.RoleName,
			AccessLevel: roleInfo.AccessLevel,
		},
	}, nil
}

func (s *Service) RemovePending(ctx context.Context, groupId uuid.UUID, pendingId uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "RemovePending")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Get the pending member to verify it belongs to the correct group and check permissions
	pendingMember, err := s.queries.GetPendingByID(traceCtx, pendingId)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "id", pendingId.String(), logger, "failed to get pending member")
		span.RecordError(err)
		return err
	}

	if pendingMember.GroupID != groupId {
		logger.Warn("Pending member does not belong to the specified group")
		return handlerutil.NewNotFoundError("pending_memberships", "group_id", groupId.String(), "pending member does not belong to group")
	}

	// check if the user is the pending member (process pending membership after onboarding)
	jwtUser, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.Error("failed to get user from context", zap.Error(err))
		return err
	}

	// Check if the user is a pending member who is allowed to remove themselves after onboarding
	if jwtUser.Email != pendingMember.UserIdentifier && jwtUser.StudentID.String != pendingMember.UserIdentifier {
		// check if the user has access to the group (group owner or group admin)
		if !s.HasGroupControlAccess(traceCtx, groupId) {
			logger.Warn("The user's access is not allowed to control this group")
			return handlerutil.ErrForbidden
		}

		// check if the user's access_level is bigger than the target access_level
		if !s.canAssignRole(traceCtx, groupId, pendingMember.RoleID) {
			logger.Warn("The user's access is not allowed to remove this pending member")
			return handlerutil.ErrForbidden
		}
	}

	err = s.queries.DeletePendingByID(traceCtx, pendingId)
	if err != nil {
		span.RecordError(err)
		return databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "id", pendingId.String(), logger, "failed to remove pending member")
	}

	return nil
}

func (s *Service) CountPendingByGroupID(ctx context.Context, groupID uuid.UUID) (int64, error) {
	traceCtx, span := s.tracer.Start(ctx, "CountPendingByGroupID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	count, err := s.queries.CountPendingByGroupID(ctx, groupID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "pending_memberships", "group_id", groupID.String(), logger, "count pending memberships by group id")
		span.RecordError(err)
		return 0, err
	}

	return count, nil
}

func (s *Service) ProcessPendingMemberships(ctx context.Context, userID uuid.UUID, email string, studentID string) error {
	traceCtx, span := s.tracer.Start(ctx, "ProcessPendingMemberships")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// Get all pending memberships for this user identifier
	pendingMemberships, err := s.queries.GetPendingByUserIdentifier(traceCtx, GetPendingByUserIdentifierParams{
		Email:     email,
		StudentID: studentID,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		err = databaseutil.WrapDBError(err, logger, "failed to get pending memberships")
		span.RecordError(err)
		return err
	}

	// Process each pending membership
	for _, pending := range pendingMemberships {
		// Add user to group with the specified role
		_, err := s.Join(traceCtx, userID, pending.GroupID, pending.RoleID, pending.IsArchived.Bool)
		if err != nil {
			logger.Warn("failed to join user to group from pending membership",
				zap.String("email", email),
				zap.String("studentID", studentID),
				zap.String("groupID", pending.GroupID.String()),
				zap.Error(err))
			continue
		}

		// Remove the pending membership after successful join
		err = s.RemovePending(ctx, pending.GroupID, pending.ID)
		if err != nil {
			logger.Warn("failed to delete pending membership after join",
				zap.String("pendingID", pending.ID.String()),
				zap.Error(err))
		}

		logger.Info("successfully processed pending membership",
			zap.String("email", email),
			zap.String("studentID", studentID),
			zap.String("groupID", pending.GroupID.String()),
			zap.String("role", pending.RoleName))
	}

	return nil
}

func (s *Service) getLDAPMember(groupCN string) ([]*ldap.Entry, error) {
	entry, err := s.ldapClient.GetGroupInfo(groupCN)
	if err != nil || entry == nil {
		return nil, err
	}
	uids := entry.GetAttributeValues("memberUid")
	return s.ldapClient.GetAllUserByUIDList(uids)
}
