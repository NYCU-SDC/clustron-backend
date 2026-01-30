package setting

import (
	"clustron-backend/internal"
	ldaputil "clustron-backend/internal/ldap"
	"clustron-backend/internal/user"
	"clustron-backend/internal/user/role"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"

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
	GetByID(ctx context.Context, userID uuid.UUID) (user.User, error)
	SetupUserRole(ctx context.Context, userID uuid.UUID) (string, error)
	UpdateFullName(ctx context.Context, userID uuid.UUID, fullName string) (user.User, error)
	ListLoginMethodsByID(ctx context.Context, userID uuid.UUID) ([]user.ListLoginMethodsRow, error)
}

//go:generate mockery --name LDAPClient
type LDAPClient interface {
	CreateUser(uid string, cn string, sn string, sshPublicKey string, uidNumber string) error
	GetUserInfoByUIDNumber(uidNumber int64) (*ldap.Entry, error)
	GetAllUIDNumbers() ([]string, error)
	GetUserInfo(uid string) (*ldap.Entry, error)
	ExistSSHPublicKey(publicKey string) (bool, error)
	AddSSHPublicKey(uid string, publicKey string) error
	DeleteSSHPublicKey(uid string, publicKey string) error
	ExistUser(uid string) (bool, error)
	UpdateUserPassword(uid string, password string) error
}

//go:generate mockery --name Querier
type Querier interface {
	GetUIDByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	CreateLDAPUser(ctx context.Context, params CreateLDAPUserParams) error
	ExistByUserID(ctx context.Context, userID uuid.UUID) (bool, error)
	GetPublicKeys(ctx context.Context, userID uuid.UUID) ([]PublicKey, error)
	GetPublicKey(ctx context.Context, id uuid.UUID) (PublicKey, error)
	ExistPublicKey(ctx context.Context, publicKey string) (bool, error)
	CreatePublicKey(ctx context.Context, arg CreatePublicKeyParams) (PublicKey, error)
	DeletePublicKey(ctx context.Context, id uuid.UUID) error
	ExistByLinuxUsername(ctx context.Context, linuxUsername pgtype.Text) (bool, error)
	GetAllUserByUIDNumber(ctx context.Context, uidNumbers []int32) ([]uuid.UUID, error)
}

type MembershipService interface {
	ProcessPendingMemberships(ctx context.Context, userID uuid.UUID, email string, studentID string) error
}

type Service struct {
	logger            *zap.Logger
	tracer            trace.Tracer
	query             Querier
	userStore         UserStore
	membershipService MembershipService
	ldapClient        LDAPClient
}

func NewService(logger *zap.Logger, querier Querier, userStore UserStore, ldapClient LDAPClient) *Service {
	return &Service{
		logger: logger,
		tracer: otel.Tracer("setting/service"),
		query:  querier,

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

	// update User's FullName
	updatedUser, err := s.userStore.UpdateFullName(traceCtx, userID, fullName.String)
	if err != nil {
		span.RecordError(err)
		return err
	}
	logger.Info("updated user's full name", zap.String("userID", userID.String()), zap.String("fullName", updatedUser.FullName.String))

	// set up the user's role
	_, err = s.userStore.SetupUserRole(traceCtx, userID)
	if err != nil {
		span.RecordError(err)
		return err
	}

	uidNumber, err := s.GetAvailableUIDNumber(traceCtx)
	if err != nil {
		logger.Error("failed to get available uid number", zap.String("userID", userID.String()), zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("failed to get available uid number: %w", err)
	}

	// Create User Entry
	err = s.ldapClient.CreateUser(linuxUsername.String, fullName.String, "User", "", uidNumber)
	if err != nil {
		logger.Error("failed to create LDAP user", zap.String("userID", userID.String()), zap.String("linuxUsername", linuxUsername.String), zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("failed to create LDAP user: %w", err)
	}

	uidNumberInt, err := strconv.ParseInt(uidNumber, 10, 64)
	if err != nil {
		logger.Error("failed to parse uidNumber to int64", zap.String("uidNumber", uidNumber), zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("failed to parse uidNumber to int64: %w", err)
	}

	// Store ldap_user
	err = s.query.CreateLDAPUser(traceCtx, CreateLDAPUserParams{
		ID:        userID,
		UidNumber: uidNumberInt,
	})
	if err != nil {
		logger.Error("failed to create ldap_user record", zap.String("userID", userID.String()), zap.Int64("uidNumber", uidNumberInt), zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("failed to create ldap_user record: %w", err)
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

func (s *Service) GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (LDAPUserInfo, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetLDAPUserInfoByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUID, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return LDAPUserInfo{}, err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUID)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID))
			return LDAPUserInfo{}, err
		}
		err = fmt.Errorf("failed to get LDAP user info by UID: %w", err)
		logger.Error("failed to get LDAP user info", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID), zap.Error(err))
		span.RecordError(err)
		return LDAPUserInfo{}, err
	}

	username := ldapEntry.GetAttributeValue("uid")
	publicKeys := ldapEntry.GetAttributeValues("sshPublicKey")

	ldapUserInfo := LDAPUserInfo{
		Username:  username,
		PublicKey: publicKeys,
	}

	return ldapUserInfo, nil
}

func (s *Service) GetAllUserIDByUIDNumber(ctx context.Context, uidNumbers []int32) ([]uuid.UUID, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAllUserIDByUIDNumber")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	userIDs, err := s.query.GetAllUserByUIDNumber(ctx, uidNumbers)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "uid_number", fmt.Sprint(uidNumbers), logger, "get all user IDs by UID numbers")
		span.RecordError(err)
		return nil, err
	}

	return userIDs, nil
}

func (s *Service) GetPublicKeysByUserID(ctx context.Context, userID uuid.UUID) ([]LDAPPublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeysByUserID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUID, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return nil, err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUID)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID))
			return nil, err
		}
		err = fmt.Errorf("failed to get LDAP user info by UID: %w", err)
		logger.Error("failed to get LDAP user info", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID), zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	publicKeyStrs := ldapEntry.GetAttributeValues("sshPublicKey")

	publicKeys := make([]LDAPPublicKey, len(publicKeyStrs))
	for i, keyStr := range publicKeyStrs {
		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			logger.Warn("failed to parse SSH public key", zap.String("publicKey", keyStr), zap.Error(err))
			continue
		}

		hash := sha256.Sum256(pubKey.Marshal())
		fingerprint := base64.RawStdEncoding.EncodeToString(hash[:])

		publicKeys[i] = LDAPPublicKey{
			Fingerprint: fingerprint,
			PublicKey:   keyStr,
			Title:       comment,
		}
	}

	return publicKeys, err
}

func (s *Service) GetPublicKeyByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (LDAPPublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetPublicKeyByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUID, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return LDAPPublicKey{}, err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUID)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID))
			return LDAPPublicKey{}, err
		}
		err = fmt.Errorf("failed to get LDAP user info by UID: %w", err)
		logger.Error("failed to get LDAP user info", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID), zap.Error(err))
		span.RecordError(err)
		return LDAPPublicKey{}, err
	}

	publicKeyStrs := ldapEntry.GetAttributeValues("sshPublicKey")

	for _, keyStr := range publicKeyStrs {
		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			logger.Warn("failed to parse SSH public key", zap.String("publicKey", keyStr), zap.Error(err))
			continue
		}

		hash := sha256.Sum256(pubKey.Marshal())
		calculatedFingerprint := base64.RawStdEncoding.EncodeToString(hash[:])
		if strings.EqualFold(calculatedFingerprint, fingerprint) {
			return LDAPPublicKey{
				Fingerprint: calculatedFingerprint,
				PublicKey:   keyStr,
				Title:       comment,
			}, nil
		}
	}

	err = fmt.Errorf("public key with fingerprint %s not found for user %s", fingerprint, userID.String())
	logger.Warn("public key not found", zap.String("fingerprint", fingerprint), zap.String("userID", userID.String()))
	span.RecordError(err)
	return LDAPPublicKey{}, err
}

func (s *Service) AddPublicKey(ctx context.Context, userID uuid.UUID, publicKey string, title string) (LDAPPublicKey, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddPublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUID, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return LDAPPublicKey{}, err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUID)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID))
			return LDAPPublicKey{}, err
		}
		err = fmt.Errorf("failed to get LDAP user info by UID: %w", err)
		logger.Error("failed to get LDAP user info", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID), zap.Error(err))
		span.RecordError(err)
		return LDAPPublicKey{}, err
	}

	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		logger.Warn("failed to parse SSH public key", zap.String("publicKey", publicKey), zap.Error(err))
		span.RecordError(err)
		return LDAPPublicKey{}, fmt.Errorf("failed to parse SSH public key: %w", err)
	}
	hash := sha256.Sum256(pubKey.Marshal())
	fingerprint := base64.RawStdEncoding.EncodeToString(hash[:])

	// check if the public key already exists in LDAP
	publicKeyStrs := ldapEntry.GetAttributeValues("sshPublicKey")

	for _, keyStr := range publicKeyStrs {
		oldPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			logger.Warn("failed to parse SSH public key", zap.String("publicKey", keyStr), zap.Error(err))
			continue
		}
		oldHash := sha256.Sum256(oldPubKey.Marshal())
		oldFingerprint := base64.RawStdEncoding.EncodeToString(oldHash[:])

		if strings.EqualFold(fingerprint, oldFingerprint) {
			err = ldaputil.ErrPublicKeyExists
			logger.Debug("public key already exists in LDAP", zap.String("userID", userID.String()))
			return LDAPPublicKey{}, err
		}
	}

	// re-construct the public key with title
	if title != "" {
		publicKey = fmt.Sprintf("%s %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), title)
	} else {
		publicKey = fmt.Sprintf("%s %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), comment)
	}

	// add the public key to LDAP
	err = s.ldapClient.AddSSHPublicKey(ldapEntry.GetAttributeValue("uid"), publicKey)
	if err != nil {
		if errors.Is(err, ldaputil.ErrPublicKeyExists) {
			logger.Warn("public key already exists in LDAP", zap.String("userID", userID.String()))
			return LDAPPublicKey{}, err
		}
		logger.Error("failed to add SSH public key to LDAP", zap.String("userID", userID.String()), zap.Error(err))
		span.RecordError(err)
		return LDAPPublicKey{}, fmt.Errorf("failed to add SSH public key to LDAP: %w", err)
	}

	return LDAPPublicKey{
		Fingerprint: fingerprint,
		PublicKey:   publicKey,
		Title:       title,
	}, nil
}

func (s *Service) DeletePublicKey(ctx context.Context, userID uuid.UUID, fingerprint string) error {
	traceCtx, span := s.tracer.Start(ctx, "DeletePublicKey")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUID, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get setting by user id")
		span.RecordError(err)
		return err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUID)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID))
			return err
		}
		err = fmt.Errorf("failed to get LDAP user info by UID: %w", err)
		logger.Error("failed to get LDAP user info", zap.String("userID", userID.String()), zap.Int64("ldapUID", ldapUID), zap.Error(err))
		span.RecordError(err)
		return err
	}

	publicKeyStrs := ldapEntry.GetAttributeValues("sshPublicKey")

	for _, keyStr := range publicKeyStrs {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			logger.Warn("failed to parse SSH public key", zap.String("publicKey", keyStr), zap.Error(err))
			continue
		}
		hash := sha256.Sum256(pubKey.Marshal())
		calculatedFingerprint := base64.RawStdEncoding.EncodeToString(hash[:])
		if strings.EqualFold(calculatedFingerprint, fingerprint) {
			// delete the public key from LDAP
			err = s.ldapClient.DeleteSSHPublicKey(ldapEntry.GetAttributeValue("uid"), keyStr)
			if err != nil {
				logger.Error("failed to delete SSH public key from LDAP", zap.String("userID", userID.String()), zap.Error(err))
				span.RecordError(err)
				return fmt.Errorf("failed to delete SSH public key from LDAP: %w", err)
			}
			return nil
		}
	}

	err = ldaputil.ErrPublicKeyNotFound
	logger.Warn("public key not found", zap.String("fingerprint", fingerprint), zap.String("userID", userID.String()))
	span.RecordError(err)
	return err
}

func (s *Service) IsLinuxUsernameExists(ctx context.Context, linuxUsername string) (bool, error) {
	traceCtx, span := s.tracer.Start(ctx, "IsLinuxUsernameExists")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	exists, err := s.ldapClient.ExistUser(linuxUsername)
	if err != nil {
		logger.Error("failed to check linux username existence in LDAP", zap.String("linuxUsername", linuxUsername), zap.Error(err))
		span.RecordError(err)
		return false, err
	}

	return exists, nil
}

func (s *Service) GetAvailableUIDNumber(ctx context.Context) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetAvailableUidNumber")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	uidNumbers, err := s.ldapClient.GetAllUIDNumbers()
	if err != nil {
		logger.Error("failed to get all uid numbers from LDAP", zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	uidNumbersMap := make(map[int]bool)
	for _, uidStr := range uidNumbers {
		var uid int
		_, err := fmt.Sscanf(uidStr, "%d", &uid)
		if err != nil {
			logger.Warn("failed to parse uid number", zap.String("uidStr", uidStr), zap.Error(err))
			continue
		}
		uidNumbersMap[uid] = true
	}

	for uid := 10000; uid < 60000; uid++ {
		if !uidNumbersMap[uid] {
			return fmt.Sprintf("%d", uid), nil
		}
	}

	err = fmt.Errorf("no available uid number found")
	logger.Error("failed to find available uid number", zap.Error(err))
	span.RecordError(err)
	return "", err
}

func (s *Service) UpdatePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	traceCtx, span := s.tracer.Start(ctx, "UpdatePassword")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	ldapUIDNumber, err := s.query.GetUIDByUserID(ctx, userID)
	if err != nil {
		err = databaseutil.WrapDBErrorWithKeyValue(err, "ldap_user", "id", userID.String(), logger, "get ldap uid by user id")
		span.RecordError(err)
		return err
	}

	ldapEntry, err := s.ldapClient.GetUserInfoByUIDNumber(ldapUIDNumber)
	if err != nil {
		if errors.Is(err, ldaputil.ErrUserNotFound) {
			logger.Warn("LDAP user not found", zap.Int64("uidNumber", ldapUIDNumber))
			return err
		}
		logger.Error("failed to find ldap user", zap.Error(err))
		return err
	}

	uidString := ldapEntry.GetAttributeValue("uid")

	err = s.ldapClient.UpdateUserPassword(uidString, newPassword)
	if err != nil {
		logger.Error("failed to update ldap password", zap.String("uid", uidString), zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("failed to update ldap password: %w", err)
	}

	logger.Info("user password updated successfully", zap.String("userID", userID.String()), zap.String("uid", uidString))
	return nil
}
