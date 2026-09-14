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
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//mockery:generate: true
type LDAPClient interface {
	CreateGroup(groupName string, gidNumber string, memberUids []string) error
	DeleteGroup(groupName string) error
	AddUserToGroup(groupName string, memberUid string) error
	RemoveUserFromGroup(groupName string, memberUid string) error
}

type SettingStore interface {
	GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (setting.LDAPUserInfo, error)
}

type LocalGroupStore interface {
	ListLocalGroups(ctx context.Context) ([]ansible.LocalGroup, error)
	DiscoverLocalGroupsInBackground(ctx context.Context)
}

type Service struct {
	logger          *zap.Logger
	tracer          trace.Tracer
	db              *pgxpool.Pool
	queries         *Queries
	ldapClient      LDAPClient
	settingStore    SettingStore
	localGroupStore LocalGroupStore
	denylist        map[string]struct{}
}

func NewService(logger *zap.Logger, db *pgxpool.Pool, ldapClient LDAPClient, settingStore SettingStore, localGroupStore LocalGroupStore, denylist []string) *Service {
	return &Service{
		logger:          logger,
		tracer:          otel.Tracer("systemgroup/service"),
		db:              db,
		queries:         New(db),
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
	names, err := s.queries.ListNames(traceCtx)
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

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return SystemGroup{}, databaseutil.WrapDBError(err, logger, "begin tx for register system group")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	created, err := s.queries.WithTx(tx).Create(traceCtx, CreateParams{
		Name:        name,
		GidNumber:   gid,
		Description: pgtype.Text{String: description, Valid: description != ""},
	})
	if err != nil {
		return SystemGroup{}, databaseutil.WrapDBError(err, logger, "create system group")
	}

	saga := internal.NewSaga(logger)
	saga.AddStep(CreateLDAPGroupStep(s.ldapClient, name, gid))
	saga.AddStep(commitStep(tx))
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

	groups, err := s.queries.ListAll(traceCtx)
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

	group, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		return databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	if err = s.ldapClient.DeleteGroup(group.Name); err != nil && !errors.Is(err, ldap.ErrGroupNotFound) {
		span.RecordError(err)
		return err
	}
	if err = s.queries.Delete(traceCtx, id); err != nil {
		return databaseutil.WrapDBError(err, logger, "delete system group")
	}
	return nil
}

func (s *Service) ListMembers(ctx context.Context, id uuid.UUID) ([]Member, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListMembers")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if _, err := s.queries.GetByID(traceCtx, id); err != nil {
		return nil, databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	rows, err := s.queries.ListMembers(traceCtx, id)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list system group members")
	}
	members := make([]Member, len(rows))
	for i, row := range rows {
		members[i] = Member{UserID: row.ID, Email: row.Email, FullName: row.FullName.String, AddedAt: row.CreatedAt.Time}
	}
	return members, nil
}

func (s *Service) AddMember(ctx context.Context, id, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "AddMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, uid, err := s.groupAndUID(traceCtx, id, userID)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "begin tx for add system group member")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	if err = s.queries.WithTx(tx).AddMember(traceCtx, AddMemberParams{SystemGroupID: id, UserID: userID}); err != nil {
		return databaseutil.WrapDBError(err, logger, "add system group member")
	}

	saga := internal.NewSaga(logger)
	saga.AddStep(AddLDAPMemberStep(s.ldapClient, group.Name, uid))
	saga.AddStep(commitStep(tx))
	if err = saga.Execute(traceCtx); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

func (s *Service) RemoveMember(ctx context.Context, id, userID uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "RemoveMember")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	group, uid, err := s.groupAndUID(traceCtx, id, userID)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "begin tx for remove system group member")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	deleted, err := s.queries.WithTx(tx).RemoveMember(traceCtx, RemoveMemberParams{SystemGroupID: id, UserID: userID})
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "remove system group member")
	}
	if deleted == 0 {
		return handlerutil.NewNotFoundError("system_group_members", "user_id", userID.String(), "user is not a member of this system group")
	}

	saga := internal.NewSaga(logger)
	saga.AddStep(RemoveLDAPMemberStep(s.ldapClient, group.Name, uid))
	saga.AddStep(commitStep(tx))
	if err = saga.Execute(traceCtx); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

// groupAndUID loads the system group and the user's LDAP uid. A user without an
// LDAP account (including an unknown user id) yields ErrUserHasNoLDAPAccount.
func (s *Service) groupAndUID(ctx context.Context, id, userID uuid.UUID) (SystemGroup, string, error) {
	logger := logutil.WithContext(ctx, s.logger)

	group, err := s.queries.GetByID(ctx, id)
	if err != nil {
		return SystemGroup{}, "", databaseutil.WrapDBErrorWithKeyValue(err, "system_groups", "id", id.String(), logger, "get system group")
	}
	info, err := s.settingStore.GetLDAPUserInfoByUserID(ctx, userID)
	if errors.Is(err, handlerutil.ErrNotFound) {
		return SystemGroup{}, "", internal.ErrUserHasNoLDAPAccount
	}
	if err != nil {
		return SystemGroup{}, "", err
	}
	return group, info.Username, nil
}
