package user

import (
	"clustron-backend/internal/config"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const StartUidNumber = 10000

type Service struct {
	queries   *Queries
	logger    *zap.Logger
	presetMap map[string]config.PresetUserInfo
	tracer    trace.Tracer
}

type ServiceInterface interface {
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
}

func NewService(logger *zap.Logger, presetMap map[string]config.PresetUserInfo, db DBTX) *Service {
	return &Service{
		queries:   New(db),
		logger:    logger,
		presetMap: presetMap,
		tracer:    otel.Tracer("user/service"),
	}
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	user, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by id")
		span.RecordError(err)
		return User{}, err
	}

	return user, nil
}

func (s *Service) Create(ctx context.Context, email, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "CreateInfo")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	param := CreateParams{
		Email:     email,
		StudentID: pgtype.Text{String: studentID, Valid: studentID != ""},
		Role:      role.NotSetup.String(),
	}

	user, err := s.queries.Create(traceCtx, param)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create user")
		span.RecordError(err)
		return User{}, err
	}
	return user, nil
}

func (s *Service) GetEmailByID(ctx context.Context, id uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetEmailByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	email, err := s.queries.GetEmailByID(traceCtx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", id.String(), logger, "get user email by id")
		span.RecordError(err)
		return "", err
	}

	return email, nil
}

func (s *Service) ExistsByIdentifier(ctx context.Context, email string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "ExistsByIdentifier")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.queries.ExistsByIdentifier(traceCtx, email)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "get user by email")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}

func (s *Service) GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetIdByEmail")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	id, err := s.queries.GetIdByEmail(traceCtx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil
		}
		err = databaseutil.WrapDBError(err, logger, "get user id by email")
		span.RecordError(err)
		return uuid.Nil, err
	}

	return id, nil
}

func (s *Service) GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetIdByStudentId")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	id, err := s.queries.GetIdByStudentId(traceCtx, pgtype.Text{String: studentID, Valid: studentID != ""})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil
		}
		err = databaseutil.WrapDBError(err, logger, "get user id by student id")
		span.RecordError(err)
		return uuid.Nil, err
	}

	return id, nil
}

func (s *Service) UpdateRoleByID(ctx context.Context, id uuid.UUID, globalRole string) error {
	traceCtx, span := s.tracer.Start(ctx, "UpdateRoleByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if !role.IsValidGlobalRole(globalRole) {
		err := errors.New("invalid role provided: " + globalRole)
		logger.Error("Invalid role provided", zap.String("role", globalRole))
		span.RecordError(err)
		return err
	}

	_, err := s.queries.UpdateRole(traceCtx, UpdateRoleParams{
		ID:   id,
		Role: globalRole,
	})

	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", id.String(), logger, "update user role")
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) UpdateStudentID(ctx context.Context, userID uuid.UUID, studentID string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateStudentID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	updatedUser, err := s.queries.UpdateStudentID(traceCtx, UpdateStudentIDParams{
		ID:        userID,
		StudentID: pgtype.Text{String: studentID, Valid: studentID != ""},
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", userID.String(), logger, "update user student id")
		span.RecordError(err)
		return User{}, err
	}

	return updatedUser, nil
}

func (s *Service) UpdateFullName(ctx context.Context, userID uuid.UUID, fullName string) (User, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateFullName")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	updatedUser, err := s.queries.UpdateFullName(traceCtx, UpdateFullNameParams{
		ID:       userID,
		FullName: pgtype.Text{String: fullName, Valid: fullName != ""},
	})
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", userID.String(), logger, "update user fullname")
		span.RecordError(err)
		return User{}, err
	}

	return updatedUser, nil
}

func (s *Service) SetupUserRole(ctx context.Context, userID uuid.UUID) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "SetupUserRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	userEmail, err := s.GetEmailByID(traceCtx, userID)
	if err != nil {
		span.RecordError(err)
		return "", err
	}

	var userRole string
	presetRole, exist := s.presetMap[userEmail]
	if exist {
		userRole = presetRole.Role
	} else {
		userRole = role.User.String()
	}
	err = s.UpdateRoleByID(traceCtx, userID, userRole)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", userID.String(), logger, "update user role")
		span.RecordError(err)
		return "", err
	}

	return userRole, nil
}

/*
To find the lowest unused uidNumber >= StartUidNumber for LDAP users.
It queries all used uidNumbers, builds a set, and returns the first available one.
*/
func (s *Service) GetAvailableUidNumber(ctx context.Context) (int, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAvailableUidNumber")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	usedUidNumbers, err := s.queries.ListUidNumbers(ctx)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "failed to get available uid number")
		span.RecordError(err)
		return 0, err
	}

	next := StartUidNumber
	usedSet := make(map[int32]struct{}, len(usedUidNumbers))
	for _, n := range usedUidNumbers {
		usedSet[int32(n.Int32)] = struct{}{}
	}

	for {
		if _, ok := usedSet[int32(next)]; !ok {
			return int(next), nil
		}
		next++
	}
}

func (s *Service) SetUidNumber(ctx context.Context, id uuid.UUID, uidNumber int) error {
	traceCtx, span := s.tracer.Start(ctx, "SetUidNumber")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if uidNumber == 0 {
		err := s.queries.SetUidNumber(traceCtx, SetUidNumberParams{
			ID:        id,
			UidNumber: pgtype.Int4{Int32: int32(uidNumber), Valid: false},
		})
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", id.String(), logger, "set uid number")
			span.RecordError(err)
			return err
		}
	} else {
		err := s.queries.SetUidNumber(traceCtx, SetUidNumberParams{
			ID:        id,
			UidNumber: pgtype.Int4{Int32: int32(uidNumber), Valid: true},
		})
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "users", "id", id.String(), logger, "set uid number")
			span.RecordError(err)
			return err
		}
	}

	return nil
}

func (s *Service) ListLoginMethodsByID(ctx context.Context, userID uuid.UUID) ([]ListLoginMethodsRow, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListLoginMethods")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	methods, err := s.queries.ListLoginMethods(traceCtx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "login_info", "user_id", userID.String(), logger, "list login methods")
		span.RecordError(err)
		return nil, err
	}

	return methods, nil
}

func (s *Service) SearchByIdentifier(ctx context.Context, query string, page, size int) ([]string, int, error) {
	traceCtx, span := s.tracer.Start(ctx, "SearchByIdentifier")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	totalCount, err := s.queries.CountSearchByIdentifier(traceCtx, pgtype.Text{String: query, Valid: true})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "count search user by identifier")
		span.RecordError(err)
		return nil, 0, err
	}

	identifiers, err := s.queries.SearchByIdentifier(traceCtx, SearchByIdentifierParams{
		Query: pgtype.Text{String: query, Valid: true},
		Size:  int32(size),
		Skip:  int32(page * size),
	})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "search user by identifier")
		span.RecordError(err)
		return nil, 0, err
	}

	return identifiers, int(totalCount), nil
}
