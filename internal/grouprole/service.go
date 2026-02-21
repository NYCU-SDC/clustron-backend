package grouprole

import (
	"clustron-backend/internal"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"fmt"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type LDAPGroupStore interface {
	GetLDAPAdminGroupCNByGroupID(ctx context.Context, groupID uuid.UUID) (string, error)
}

type LDAPClient interface {
	AddUserToGroup(groupName string, memberUid string) error
	RemoveUserFromGroup(groupName string, memberUid string) error
	GetUserInfoByUIDNumber(uidNumber int64) (*ldap.Entry, error)
}

type Service struct {
	logger         *zap.Logger
	tracer         trace.Tracer
	queries        *Queries
	db             *pgxpool.Pool
	ldapGroupStore LDAPGroupStore
	ldapClient     LDAPClient
}

func NewService(logger *zap.Logger, ldapGroupStore LDAPGroupStore, ldapClient LDAPClient, db *pgxpool.Pool) *Service {
	return &Service{
		logger:         logger,
		tracer:         otel.Tracer("group/service"),
		queries:        New(db),
		db:             db,
		ldapGroupStore: ldapGroupStore,
		ldapClient:     ldapClient,
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

func (s *Service) Create(ctx context.Context, roleName string, level AccessLevel) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByRoleName(ctx, roleName)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_name", roleName, logger, "check if group role exists")
		span.RecordError(err)
		return GroupRole{}, err
	}
	if exists {
		err = fmt.Errorf("role %s already exists, %w", roleName, internal.ErrDatabaseConflict)
		span.RecordError(err)
		return GroupRole{}, err
	}

	createdRole, err := s.queries.Create(ctx, CreateParams{
		RoleName:    roleName,
		AccessLevel: level.String(),
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_name", roleName, logger, "create group role")
		span.RecordError(err)
		return GroupRole{}, err
	}

	return createdRole, nil
}

func (s *Service) Update(ctx context.Context, roleID uuid.UUID, roleName string, level AccessLevel) (GroupRole, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateGroupRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groupRole, err := s.queries.GetByID(ctx, roleID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "get group role by id")
		span.RecordError(err)
		return GroupRole{}, err
	}

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "begin transaction for updating group role")
		span.RecordError(err)
		return GroupRole{}, err
	}
	defer func(tx pgx.Tx) {
		txErr := tx.Rollback(traceCtx)
		if txErr != nil && !errors.Is(txErr, pgx.ErrTxClosed) {
			logger.Error("failed to rollback transaction for updating group role", zap.String("role_id", roleID.String()), zap.Error(txErr))
		}
	}(tx)

	q := s.queries.WithTx(tx)

	updatedRole, err := q.Update(ctx, UpdateParams{
		ID:          roleID,
		RoleName:    roleName,
		AccessLevel: level.String(),
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "update group role")
		span.RecordError(err)
		return GroupRole{}, err
	}

	isChangeToAdminLevel := (groupRole.AccessLevel == AccessLevelUser.String() && level.String() == AccessLevelAdmin.String()) ||
		(groupRole.AccessLevel == AccessLevelUser.String() && level.String() == AccessLevelOwner.String())
	isChangeFromAdminLevel := (groupRole.AccessLevel == AccessLevelAdmin.String() && level.String() == AccessLevelUser.String()) ||
		(groupRole.AccessLevel == AccessLevelOwner.String() && level.String() == AccessLevelUser.String())

	if isChangeToAdminLevel || isChangeFromAdminLevel {
		saga := internal.NewSaga(logger)

		updatedMember, err := s.queries.GetUpdatedUser(ctx, roleID)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", "role_id", roleID.String(), logger, "get updated user for group role")
			span.RecordError(err)
			return GroupRole{}, err
		}

		for _, member := range updatedMember {
			saga.AddStep(internal.SagaStep{
				Name: "UpdateUserRole",
				Action: func(ctx context.Context) error {
					userInfo, err := s.ldapClient.GetUserInfoByUIDNumber(member.UidNumber)
					if err != nil {
						return fmt.Errorf("failed to get user info by UID number %d: %w", member.UidNumber, err)
					}

					memberUid := userInfo.GetAttributeValue("uid")
					if memberUid == "" {
						return fmt.Errorf("user with UID number %d does not have a uid attribute", member.UidNumber)
					}

					adminCN, err := s.ldapGroupStore.GetLDAPAdminGroupCNByGroupID(ctx, member.GroupID)
					if err != nil {
						return fmt.Errorf("failed to get LDAP base group CN by group ID %s: %w", member.GroupID.String(), err)
					}

					if level.String() == AccessLevelAdmin.String() || level.String() == AccessLevelOwner.String() {
						err = s.ldapClient.AddUserToGroup(adminCN, memberUid)
						if err != nil {
							return fmt.Errorf("failed to add user %s to admin group for group %s: %w", memberUid, adminCN, err)
						}
					} else {
						err = s.ldapClient.RemoveUserFromGroup(adminCN, memberUid)
						if err != nil {
							return fmt.Errorf("failed to remove user %s from admin group for group %s: %w", memberUid, adminCN, err)
						}
					}

					return nil
				},
				Compensate: func(ctx context.Context) error {
					userInfo, err := s.ldapClient.GetUserInfoByUIDNumber(member.UidNumber)
					if err != nil {
						return fmt.Errorf("failed to get user info by UID number %d: %w", member.UidNumber, err)
					}

					memberUid := userInfo.GetAttributeValue("uid")
					if memberUid == "" {
						return fmt.Errorf("user with UID number %d does not have a uid attribute", member.UidNumber)
					}

					adminCN, err := s.ldapGroupStore.GetLDAPAdminGroupCNByGroupID(ctx, member.GroupID)
					if err != nil {
						return fmt.Errorf("failed to get LDAP base group CN by group ID %s: %w", member.GroupID.String(), err)
					}

					if level.String() == AccessLevelAdmin.String() || level.String() == AccessLevelOwner.String() {
						err = s.ldapClient.RemoveUserFromGroup(adminCN, memberUid)
						if err != nil {
							return fmt.Errorf("failed to remove user %s from admin group for group %s: %w", memberUid, adminCN, err)
						}
					} else {
						err = s.ldapClient.AddUserToGroup(adminCN, memberUid)
						if err != nil {
							return fmt.Errorf("failed to add user %s to admin group for group %s: %w", memberUid, adminCN, err)
						}
					}

					return nil
				},
			})
		}

		err = saga.Execute(traceCtx)
		if err != nil {
			err = fmt.Errorf("failed to execute saga for updating user roles when updating group role with id %s: %w", roleID.String(), err)
			span.RecordError(err)
			return GroupRole{}, err
		}

		if err := tx.Commit(traceCtx); err != nil {
			err = databaseutil.WrapDBError(err, logger, "commit transaction for updating group role")
			span.RecordError(err)
			return GroupRole{}, err
		}

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

	roleType := "membership"
	if userRole == role.Admin.String() {
		roleType = "adminOverride"
		return GroupRole{}, roleType, nil
	}

	groupRole, err := s.GetByUser(traceCtx, userID, groupID)
	if err != nil {
		if errors.As(err, &handlerutil.NotFoundError{}) {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "group_role", fmt.Sprintf("(%s, %s)", "group_id", "user_id"), fmt.Sprintf("(%s, %s)", groupID.String(), userID.String()), logger, "get group role by user id and group id")
		}
		span.RecordError(err)
		return GroupRole{}, "", err
	}

	return groupRole, roleType, nil
}
