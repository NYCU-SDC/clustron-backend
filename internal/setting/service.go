package setting

import (
	"clustron-backend/internal"
	"clustron-backend/internal/ldap"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"errors"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:generate mockery --name UserStore
type UserStore interface {
	SetupUserRole(ctx context.Context, userID uuid.UUID) (string, error)
	ListLoginMethodsByID(ctx context.Context, userID uuid.UUID) ([]user.ListLoginMethodsRow, error)
}

type MembershipService interface {
	ProcessPendingMemberships(ctx context.Context, userID uuid.UUID, email string, studentID string) error
}

type Service struct {
	logger            *zap.Logger
	tracer            trace.Tracer
	query             *Queries
	userStore         UserStore
	membershipService MembershipService
	ldapClient        ldap.LDAPClient
}

func NewService(logger *zap.Logger, db DBTX, userStore UserStore, ldapClient ldap.LDAPClient) *Service {
	return &Service{
		logger: logger,
		tracer: otel.Tracer("setting/service"),
		query:  New(db),

		userStore:  userStore,
		ldapClient: ldapClient,
	}
}

func (s *Service) SetMembershipService(membershipService MembershipService) {
	s.membershipService = membershipService
}

func (s *Service) OnboardUser(ctx context.Context, userRole string, userID uuid.UUID, email string, studentID string, fullName pgtype.Text, linuxUsername pgtype.Text) error {
	traceCtx, span := s.tracer.Start(ctx, "OnboardUser")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// validate user role
	if userRole != role.NotSetup.String() {
		logger.Warn(internal.ErrAlreadyOnboarded.Error(), zap.String("userID", userID.String()), zap.String("userRole", userRole))
		span.RecordError(internal.ErrAlreadyOnboarded)
		return internal.ErrAlreadyOnboarded
	}

	// update user's setting
	_, err := s.UpdateSetting(traceCtx, userID, Setting{
		UserID:        userID,
		FullName:      fullName,
		LinuxUsername: linuxUsername,
	})
	if err != nil {
		span.RecordError(err)
		return err
	}

	// set up the user's role
	_, err = s.userStore.SetupUserRole(traceCtx, userID)
	if err != nil {
		span.RecordError(err)
		return err
	}

	// Process pending memberships after user onboarding
	err = s.membershipService.ProcessPendingMemberships(traceCtx, userID, email, studentID)
	if err != nil {
		logger.Warn("failed to process pending memberships for onboarded user",
			zap.String("userID", userID.String()),
			zap.String("email", email),
			zap.String("student_id", studentID),
			zap.Error(err))
	}

	return nil
}

func (s *Service) GetSettingByUserID(ctx context.Context, userID uuid.UUID) (Setting, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetSettingByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	setting, err := s.query.GetSetting(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return Setting{}, err
	}

	return setting, nil
}

func (s *Service) FindOrCreateSetting(ctx context.Context, userID uuid.UUID, fullName pgtype.Text) (Setting, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateSetting")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exist, err := s.query.ExistByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userID.String(), logger, "check setting exists")
		span.RecordError(err)
		return Setting{}, err
	}

	var setting Setting
	if !exist {
		setting, err = s.query.CreateSetting(ctx, CreateSettingParams{UserID: userID, FullName: fullName})
		if err != nil {
			err = databaseutil.WrapDBError(err, logger, "create setting")
			span.RecordError(err)
			return Setting{}, err
		}
	} else {
		setting, err = s.query.GetSetting(ctx, userID)
		if err != nil {
			err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userID.String(), logger, "get setting by user id")
			span.RecordError(err)
			return Setting{}, err
		}
	}

	return setting, nil
}

func (s *Service) UpdateSetting(ctx context.Context, userID uuid.UUID, setting Setting) (Setting, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateSetting")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	updatedSetting, err := s.query.UpdateSetting(ctx, UpdateSettingParams(setting))
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", userID.String(), logger, "update setting")
		span.RecordError(err)
		return Setting{}, err
	}

	return updatedSetting, nil
}

func (s *Service) GetPublicKeysByUserID(ctx context.Context, userID uuid.UUID) ([]PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeysByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	publicKeys, err := s.query.GetPublicKeys(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", userID.String(), logger, "get public keys by user id")
		span.RecordError(err)
		return nil, err
	}

	return publicKeys, err
}

func (s *Service) GetPublicKeyByID(ctx context.Context, id uuid.UUID) (PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeyByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	publicKey, err := s.query.GetPublicKey(ctx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", id.String(), logger, "get public key by id")
		span.RecordError(err)
		return PublicKey{}, err
	}

	return publicKey, nil
}

func (s *Service) AddPublicKey(ctx context.Context, publicKey CreatePublicKeyParams) (PublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddPublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.query.ExistPublicKey(ctx, publicKey.PublicKey)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "check public key exists")
		span.RecordError(err)
		return PublicKey{}, err
	}
	if exists {
		logger.Warn("public key already exists", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
		return PublicKey{}, internal.ErrDatabaseConflict
	}

	var (
		publicKeyLDAPExists bool
		addedPublicKey      PublicKey
		userSetting         Setting
	)

	saga := internal.NewSaga(s.logger)

	saga.AddStep(internal.SagaStep{
		Name: "AddPublicKey",
		Action: func(ctx context.Context) error {
			addedPublicKey, err = s.query.CreatePublicKey(ctx, publicKey)
			if err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", publicKey.UserID.String(), logger, "add public key")
				span.RecordError(err)
				return err
			}
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if err := s.query.DeletePublicKey(ctx, addedPublicKey.ID); err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "public_keys", "id", addedPublicKey.ID.String(), logger, "compensate delete public key")
				span.RecordError(err)
				return err
			}
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "GetSettingByUserID",
		Action: func(ctx context.Context) error {
			userSetting, err = s.GetSettingByUserID(ctx, publicKey.UserID)
			if err != nil {
				err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", publicKey.UserID.String(), logger, "get setting by user id")
				span.RecordError(err)
				return err
			}
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "GetUserInfo",
		Action: func(ctx context.Context) error {
			ldapUser, err := s.ldapClient.GetUserInfo(userSetting.LinuxUsername.String)
			if err != nil && !errors.Is(err, ldap.ErrUserNotFound) {
				logger.Warn("get user by id failed", zap.Error(err))
				return err
			}
			exists = ldapUser != nil
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "CheckSSHPublicKeyExists",
		Action: func(ctx context.Context) error {
			if exists {
				publicKeyLDAPExists, err = s.ldapClient.ExistSSHPublicKey(publicKey.PublicKey)
				if err != nil {
					err = internal.ErrLDAPPublicKeyConflict
					logger.Warn("check public key exists in LDAP failed", zap.Error(err))
					return err
				}
				return nil
			}
			logger.Info("LDAP user does not exist, skipping checking public key existence", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
			return nil
		},
	})

	saga.AddStep(internal.SagaStep{
		Name: "AddSSHPublicKey",
		Action: func(ctx context.Context) error {
			if exists && !publicKeyLDAPExists {
				err = s.ldapClient.AddSSHPublicKey(userSetting.LinuxUsername.String, publicKey.PublicKey)
				if err != nil {
					logger.Warn("add public key to LDAP user failed", zap.Error(err))
					return err
				}
				logger.Info("add public key to LDAP user successfully", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
				return nil
			}
			logger.Info("LDAP user does not exist, skipping adding public key", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
			return nil
		},
		Compensate: func(ctx context.Context) error {
			if exists && !publicKeyLDAPExists {
				err = s.ldapClient.DeleteSSHPublicKey(userSetting.LinuxUsername.String, publicKey.PublicKey)
				if err != nil {
					logger.Warn("delete public key from LDAP user failed", zap.Error(err))
					return err
				}
				logger.Info("delete public key from LDAP user successfully", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
				return nil
			}
			logger.Info("LDAP user does not exist, skipping deleting public key", zap.String("userID", publicKey.UserID.String()), zap.String("publicKey", publicKey.PublicKey))
			return nil
		},
	})

	err = saga.Execute(traceCtx)
	if err != nil {
		logger.Error("saga execution failed", zap.Error(err))
		span.RecordError(err)
		return PublicKey{}, err
	}

	return addedPublicKey, nil
}

func (s *Service) DeletePublicKey(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "DeletePublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	publicKey, err := s.GetPublicKeyByID(ctx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", id.String(), logger, "get public key by id")
		span.RecordError(err)
		return err
	}

	settings, err := s.GetSettingByUserID(ctx, publicKey.UserID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", publicKey.UserID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return err
	}

	// check if the user LDAP user exists, if exists, delete the public key to the user
	user, err := s.ldapClient.GetUserInfo(settings.LinuxUsername.String)
	if err != nil {
		logger.Warn("get user by id failed", zap.Error(err))
	} else if user != nil {
		err = s.ldapClient.DeleteSSHPublicKey(settings.LinuxUsername.String, publicKey.PublicKey)
		if err != nil {
			logger.Warn("delete the public key from LDAP user failed", zap.Error(err))
		}
	}

	err = s.query.DeletePublicKey(ctx, id)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "settings", "id", id.String(), logger, "delete public key")
		span.RecordError(err)
		return err
	}

	return nil
}

func (s *Service) IsLinuxUsernameExists(ctx context.Context, linuxUsername string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "IsLinuxUsernameExists")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.query.ExistByLinuxUsername(ctx, pgtype.Text{String: linuxUsername, Valid: true})
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "check linux username exists")
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}
