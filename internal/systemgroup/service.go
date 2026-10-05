package systemgroup

import (
	"context"
	"errors"

	"clustron-backend/internal"
	"clustron-backend/internal/ansible"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/setting"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//mockery:generate: true
type Querier interface {
	Create(ctx context.Context, arg CreateParams) (SystemGroup, error)
	GetByID(ctx context.Context, id uuid.UUID) (SystemGroup, error)
	ListAll(ctx context.Context) ([]SystemGroup, error)
	ListNames(ctx context.Context) ([]string, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AddMember(ctx context.Context, arg AddMemberParams) error
	RemoveMember(ctx context.Context, arg RemoveMemberParams) (int64, error)
	ListMembers(ctx context.Context, systemGroupID uuid.UUID) ([]ListMembersRow, error)
}

//mockery:generate: true
type LDAPClient interface {
	CreateGroup(groupName string, gidNumber string, memberUids []string) error
	DeleteGroup(groupName string) error
	AddUserToGroup(groupName string, memberUid string) error
	RemoveUserFromGroup(groupName string, memberUid string) error
}

//mockery:generate: true
type SettingStore interface {
	GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (setting.LDAPUserInfo, error)
}

//mockery:generate: true
type LocalGroupStore interface {
	ListLocalGroups(ctx context.Context) ([]ansible.LocalGroup, error)
	DiscoverLocalGroupsInBackground(ctx context.Context)
}

type Service struct {
	logger          *zap.Logger
	tracer          trace.Tracer
	query           Querier
	ldapClient      LDAPClient
	settingStore    SettingStore
	localGroupStore LocalGroupStore
	denylist        map[string]struct{}
}

func NewService(logger *zap.Logger, querier Querier, ldapClient LDAPClient, settingStore SettingStore, localGroupStore LocalGroupStore, denylist []string) *Service {
	return &Service{
		logger:          logger,
		tracer:          otel.Tracer("systemgroup/service"),
		query:           querier,
		ldapClient:      ldapClient,
		settingStore:    settingStore,
		localGroupStore: localGroupStore,
		denylist:        NewDenylist(denylist),
	}
}

func (s *Service) ListCandidates(ctx context.Context) ([]Candidate, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListCandidates")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groups, err := s.localGroupStore.ListLocalGroups(traceCtx)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	names, err := s.query.ListNames(traceCtx)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list system group names")
	}
	registered := make(map[string]struct{}, len(names))
	for _, name := range names {
		registered[name] = struct{}{}
	}
	return BuildCandidates(groups, s.denylist, registered), nil
}

func (s *Service) Discover(ctx context.Context) {
	s.localGroupStore.DiscoverLocalGroupsInBackground(ctx)
}

// Register creates the LDAP group first and inserts the row as the last saga
// step, so a failed insert deletes the LDAP group again.
func (s *Service) Register(ctx context.Context, name, description string) (SystemGroup, error) {
	traceCtx, span := s.tracer.Start(ctx, "Register")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if err := ValidateName(name); err != nil {
		return SystemGroup{}, err
	}
	groups, err := s.localGroupStore.ListLocalGroups(traceCtx)
	if err != nil {
		span.RecordError(err)
		return SystemGroup{}, err
	}
	gid, err := ResolveGID(groups, name, s.denylist)
	if err != nil {
		return SystemGroup{}, err
	}

	var created SystemGroup
	saga := internal.NewSaga(logger)
	saga.AddStep(CreateLDAPGroupStep(s.ldapClient, name, gid))
	saga.AddStep(internal.SagaStep{
		Name: "InsertSystemGroup",
		Action: func(ctx context.Context) error {
			created, err = s.query.Create(ctx, CreateParams{
				Name:        name,
				GidNumber:   gid,
				Description: pgtype.Text{String: description, Valid: description != ""},
			})
			if err != nil {
				return databaseutil.WrapDBError(err, logger, "create system group")
			}
			return nil
		},
	})
	if err = saga.Execute(traceCtx); err != nil {
		span.RecordError(err)
		return SystemGroup{}, err
	}
	return created, nil
}

func (s *Service) List(ctx context.Context) ([]SystemGroup, error) {
	traceCtx, span := s.tracer.Start(ctx, "List")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	groups, err := s.query.ListAll(traceCtx)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list system groups")
	}
	return groups, nil
}

// Delete removes the LDAP group first: if the DB delete then fails, a retry
// still works because a missing LDAP group counts as deleted.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Delete")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.query.GetByID(traceCtx, id)
	if err != nil {
		return databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	if err = s.ldapClient.DeleteGroup(group.Name); err != nil && !errors.Is(err, ldap.ErrGroupNotFound) {
		span.RecordError(err)
		return err
	}
	if err = s.query.Delete(traceCtx, id); err != nil {
		return databaseutil.WrapDBError(err, logger, "delete system group")
	}
	return nil
}

func (s *Service) ListMembers(ctx context.Context, id uuid.UUID) ([]Member, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListMembers")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if _, err := s.query.GetByID(traceCtx, id); err != nil {
		return nil, databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	rows, err := s.query.ListMembers(traceCtx, id)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list system group members")
	}
	members := make([]Member, len(rows))
	for i, row := range rows {
		members[i] = Member{UserID: row.ID, Email: row.Email, FullName: row.FullName.String, AddedAt: row.CreatedAt.Time}
	}
	return members, nil
}

// AddMember adds the LDAP memberUid first and inserts the row as the last saga
// step, so a failed insert removes a memberUid this call added.
func (s *Service) AddMember(ctx context.Context, id, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "AddMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.query.GetByID(traceCtx, id)
	if err != nil {
		return databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	uid, err := s.lookupUID(traceCtx, userID)
	if err != nil {
		return err
	}

	saga := internal.NewSaga(logger)
	saga.AddStep(AddLDAPMemberStep(s.ldapClient, group.Name, uid))
	saga.AddStep(internal.SagaStep{
		Name: "InsertSystemGroupMember",
		Action: func(ctx context.Context) error {
			if err := s.query.AddMember(ctx, AddMemberParams{SystemGroupID: id, UserID: userID}); err != nil {
				return databaseutil.WrapDBError(err, logger, "add system group member")
			}
			return nil
		},
	})
	if err = saga.Execute(traceCtx); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

// RemoveMember deletes the row first, so a non-member gets 404 before any LDAP
// lookup and a member without an LDAP account can still be removed. If the LDAP
// removal fails, the row is restored so DB and LDAP stay consistent.
func (s *Service) RemoveMember(ctx context.Context, id, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "RemoveMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, err := s.query.GetByID(traceCtx, id)
	if err != nil {
		return databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}

	params := RemoveMemberParams{SystemGroupID: id, UserID: userID}
	deleted, err := s.query.RemoveMember(traceCtx, params)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "remove system group member")
	}
	if deleted == 0 {
		return handlerutil.NewNotFoundError("system_group_members", "user_id", userID.String(), "user is not a member of this system group")
	}

	uid, err := s.lookupUID(traceCtx, userID)
	if errors.Is(err, internal.ErrUserHasNoLDAPAccount) {
		// Without an LDAP account there is no memberUid left to remove.
		logger.Warn("system group member has no LDAP account, removed membership row only", zap.String("user_id", userID.String()))
		return nil
	}
	if err == nil {
		err = RemoveLDAPMemberStep(s.ldapClient, group.Name, uid).Action(traceCtx)
	}
	if err != nil {
		s.restoreMember(traceCtx, params, logger)
		span.RecordError(err)
		return err
	}
	return nil
}

// restoreMember re-inserts a membership row deleted before a failed LDAP step.
func (s *Service) restoreMember(ctx context.Context, params RemoveMemberParams, logger *zap.Logger) {
	if err := s.query.AddMember(ctx, AddMemberParams(params)); err != nil {
		logger.Error("failed to restore system group member after LDAP failure", zap.String("user_id", params.UserID.String()), zap.Error(err))
	}
}

// lookupUID returns the user's LDAP uid. A user without an LDAP account (no
// ldap_user row, a missing LDAP entry, or an unknown user id) yields
// ErrUserHasNoLDAPAccount.
func (s *Service) lookupUID(ctx context.Context, userID uuid.UUID) (string, error) {
	info, err := s.settingStore.GetLDAPUserInfoByUserID(ctx, userID)
	if errors.Is(err, handlerutil.ErrNotFound) || errors.Is(err, ldap.ErrUserNotFound) {
		return "", internal.ErrUserHasNoLDAPAccount
	}
	if err != nil {
		return "", err
	}
	return info.Username, nil
}
