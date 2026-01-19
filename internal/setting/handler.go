package setting

import (
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type OnboardingRequest struct {
	FullName      string `json:"fullName" validate:"required"`
	LinuxUsername string `json:"linuxUsername" validate:"required,excludesall= \t\r\n"`
}

type LoginMethod struct {
	Provider string `json:"provider"`
	Email    string `json:"email"`
}

type BasicSettingResponse struct {
	FullName          string        `json:"fullName"`
	LinuxUsername     string        `json:"linuxUsername"`
	BoundLoginMethods []LoginMethod `json:"boundLoginMethods"`
}

type AddPublicKeyRequest struct {
	Title     string `json:"title" validate:"required"`
	PublicKey string `json:"publicKey" validate:"required"`
}

type PublicKeyResponse struct {
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	PublicKey   string `json:"publicKey"`
}

type UpdatePasswordRequest struct {
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

//go:generate mockery --name Store
type Store interface {
	GetLDAPUserInfoByUserID(ctx context.Context, userID uuid.UUID) (LDAPUserInfo, error)
	GetPublicKeysByUserID(ctx context.Context, userID uuid.UUID) ([]LDAPPublicKey, error)
	GetPublicKeyByFingerprint(ctx context.Context, id uuid.UUID, fingerprint string) (LDAPPublicKey, error)
	AddPublicKey(ctx context.Context, user uuid.UUID, publicKey string, title string) (LDAPPublicKey, error)
	DeletePublicKey(ctx context.Context, user uuid.UUID, fingerprint string) error
	OnboardUser(ctx context.Context, userRole string, userID uuid.UUID, email string, studentID string, fullName pgtype.Text, linuxUsername pgtype.Text) error
	IsLinuxUsernameExists(ctx context.Context, linuxUsername string) (bool, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, newPassword string) error
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	tracer        trace.Tracer
	problemWriter *problem.HttpWriter

	settingStore Store
	userStore    UserStore
}

func validatePublicKey(key string) error {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}
	return nil
}

func NewHandler(logger *zap.Logger, v *validator.Validate, problemWriter *problem.HttpWriter, store Store, userStore UserStore) Handler {
	return Handler{
		logger:        logger,
		validator:     v,
		tracer:        otel.Tracer("setting/handler"),
		problemWriter: problemWriter,
		settingStore:  store,
		userStore:     userStore,
	}
}

func (h *Handler) OnboardingHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "OnboardingHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request OnboardingRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	if strings.TrimSpace(request.FullName) == "" {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidSetting{Reason: "Full Name cannot be empty"}, logger)
		return
	}
	if strings.TrimSpace(request.LinuxUsername) == "" {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidSetting{Reason: "Linux Username cannot be empty"}, logger)
		return
	}

	// check if the linux username is valid first
	err = h.IsLinuxUsernameValid(traceCtx, request.LinuxUsername)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.settingStore.OnboardUser(traceCtx, user.Role, user.ID, user.Email, user.StudentID.String, pgtype.Text{String: request.FullName, Valid: true}, pgtype.Text{String: request.LinuxUsername, Valid: true})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}

func (h *Handler) GetUserSettingHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetUserSettingHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userID := user.ID

	ldapUserInfo, err := h.settingStore.GetLDAPUserInfoByUserID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	loginMethods, err := h.userStore.ListLoginMethodsByID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userInfo, err := h.userStore.GetByID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := BasicSettingResponse{
		FullName:      userInfo.FullName.String,
		LinuxUsername: ldapUserInfo.Username,
	}
	response.BoundLoginMethods = make([]LoginMethod, len(loginMethods))
	for i, method := range loginMethods {
		response.BoundLoginMethods[i] = LoginMethod{
			Provider: method.Providertype,
			Email:    method.Email.String,
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) GetUserPublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetUserPublicKeysHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userID := user.ID

	publicKeys, err := h.settingStore.GetPublicKeysByUserID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	q := r.URL.Query()
	var length int64
	length = 20 // default 20: frontend usually only needs short public key
	if q.Has("length") {
		length, err = strconv.ParseInt(q.Get("length"), 10, 64)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
	}

	response := make([]PublicKeyResponse, len(publicKeys))

	for i, publicKey := range publicKeys {
		response[i] = PublicKeyResponse{
			Fingerprint: publicKey.Fingerprint,
			PublicKey:   publicKey.PublicKey[:min(length, int64(len(publicKey.PublicKey)))],
			Title:       publicKey.Title,
		}
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) AddUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddUserPublicKeyHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userID := user.ID

	var request AddPublicKeyRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	err = validatePublicKey(request.PublicKey)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidPublicKey, logger)
		return
	}

	addedPublicKey, err := h.settingStore.AddPublicKey(traceCtx, userID, request.PublicKey, request.Title)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := PublicKeyResponse{
		Fingerprint: addedPublicKey.Fingerprint,
		Title:       addedPublicKey.Title,
		PublicKey:   addedPublicKey.PublicKey,
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) DeletePublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DeletePublicKeyHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userID := user.ID

	fingerprint := r.PathValue("fingerprint")
	if fingerprint == "" {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidFingerprint, logger)
		return
	}

	err = h.settingStore.DeletePublicKey(traceCtx, userID, fingerprint)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}

func (h *Handler) IsLinuxUsernameValid(ctx context.Context, linuxUsername string) error {
	if len(linuxUsername) == 0 {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username cannot be empty",
		}
	}

	if len(linuxUsername) > 32 {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username cannot be longer than 32 characters",
		}
	}

	if linuxUsername[0] == '-' {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username cannot start with a hyphen",
		}
	}

	if strings.ContainsAny(linuxUsername, " :/") {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username cannot contain colon or slash",
		}
	}

	// check if the linux username matches the pattern. source: https://www.unix.com/man_page/linux/8/useradd/
	pattern := `^[a-z_][a-z0-9_-]*[$]?$`
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(linuxUsername) {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username must start with a lowercase letter or underscore, followed by lowercase letters, numbers, underscores, or hyphens, and can end with a dollar sign",
		}
	}

	if linuxUsername == "root" || linuxUsername == "admin" || linuxUsername == "administrator" {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username contain reserved keywords",
		}
	}

	isLinuxUsernameExists, err := h.settingStore.IsLinuxUsernameExists(ctx, linuxUsername)
	if err != nil {
		h.logger.Error("Failed to check if linux username exists", zap.Error(err))
		return err
	}

	if isLinuxUsernameExists {
		return internal.ErrInvalidLinuxUsername{
			Reason: "Linux username already exists",
		}
	}
	return nil
}

func (h *Handler) UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdatePasswordHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request UpdatePasswordRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if !isValidPassword(request.NewPassword) {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidPassword, logger)
		return
	}

	err = h.settingStore.UpdatePassword(traceCtx, user.ID, request.NewPassword)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}

func isValidPassword(pass string) bool {
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(pass)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(pass)
	return hasLetter && hasNumber
}
