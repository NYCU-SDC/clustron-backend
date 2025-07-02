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
	Username      string `json:"username" validate:"required"`
	LinuxUsername string `json:"linuxUsername" validate:"required,excludesall= \t\r\n"`
}

type UpdateSettingRequest struct {
	Username      string `json:"username" validate:"required"`
	LinuxUsername string `json:"linuxUsername" validate:"excludesall= \t\r\n"`
}

type BasicSettingResponse struct {
	Username      string `json:"username"`
	LinuxUsername string `json:"linuxUsername"`
}

type AddPublicKeyRequest struct {
	Title     string `json:"title" validate:"required"`
	PublicKey string `json:"publicKey" validate:"required"`
}

type DeletePublicKeyRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

type PublicKeyResponse struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	PublicKey string `json:"publicKey"`
}

//go:generate mockery --name Store
type Store interface {
	GetSettingByUserID(ctx context.Context, userID uuid.UUID) (Setting, error)
	UpdateSetting(ctx context.Context, userID uuid.UUID, setting Setting) (Setting, error)
	GetPublicKeysByUserID(ctx context.Context, userID uuid.UUID) ([]PublicKey, error)
	GetPublicKeyByID(ctx context.Context, id uuid.UUID) (PublicKey, error)
	AddPublicKey(ctx context.Context, publicKey CreatePublicKeyParams) (PublicKey, error)
	DeletePublicKey(ctx context.Context, id uuid.UUID) error
	OnboardUser(ctx context.Context, userRole string, userID uuid.UUID, email string, studentID string, username pgtype.Text, linuxUsername pgtype.Text) error
	IsLinuxUsernameExists(ctx context.Context, linuxUsername string) (bool, error)
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	tracer        trace.Tracer
	problemWriter *problem.HttpWriter

	settingStore Store
}

func validatePublicKey(key string) error {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}
	return nil
}

func NewHandler(logger *zap.Logger, v *validator.Validate, problemWriter *problem.HttpWriter, store Store) Handler {
	return Handler{
		logger:        logger,
		validator:     v,
		tracer:        otel.Tracer("setting/handler"),
		problemWriter: problemWriter,
		settingStore:  store,
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

	// check if the linux username is valid first
	err = h.IsLinuxUsernameValid(traceCtx, request.LinuxUsername)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.settingStore.OnboardUser(traceCtx, user.Role, user.ID, user.Email, user.StudentID.String, pgtype.Text{String: request.Username, Valid: true}, pgtype.Text{String: request.LinuxUsername, Valid: true})
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

	setting, err := h.settingStore.GetSettingByUserID(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := BasicSettingResponse{
		Username:      setting.Username.String,
		LinuxUsername: setting.LinuxUsername.String,
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) UpdateUserSettingHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateUserSettingHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	oldSetting, err := h.settingStore.GetSettingByUserID(traceCtx, user.ID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request UpdateSettingRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// TODO: allow updating linux username (after we have a solution to manage ldap users and the home directory in remote lab)
	var setting Setting
	// if the linux username is already set, we keep it
	if oldSetting.LinuxUsername.String != "" {
		setting = Setting{
			UserID:        user.ID,
			Username:      pgtype.Text{String: request.Username, Valid: true},
			LinuxUsername: oldSetting.LinuxUsername,
		}
	} else {
		// else we update the linux username as well
		// check if the linux username is valid first
		err = h.IsLinuxUsernameValid(traceCtx, request.LinuxUsername)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		setting = Setting{
			UserID:        user.ID,
			Username:      pgtype.Text{String: request.Username, Valid: true},
			LinuxUsername: pgtype.Text{String: request.LinuxUsername, Valid: true},
		}
	}

	updatedSetting, err := h.settingStore.UpdateSetting(traceCtx, user.ID, setting)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := BasicSettingResponse{
		Username:      updatedSetting.Username.String,
		LinuxUsername: updatedSetting.LinuxUsername.String,
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
			ID:        publicKey.ID.String(),
			Title:     publicKey.Title,
			PublicKey: publicKey.PublicKey[:min(length, int64(len(publicKey.PublicKey)))],
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
		handlerutil.WriteJSONResponse(w, http.StatusBadRequest, err)
		return
	}

	publicKey := CreatePublicKeyParams{
		UserID:    userID,
		Title:     request.Title,
		PublicKey: request.PublicKey,
	}

	addedPublicKey, err := h.settingStore.AddPublicKey(traceCtx, publicKey)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := PublicKeyResponse{
		Title:     addedPublicKey.Title,
		PublicKey: addedPublicKey.PublicKey,
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

	var request DeletePublicKeyRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	publicKeyID, err := uuid.Parse(request.ID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Check if the public key belongs to the user
	publicKey, err := h.settingStore.GetPublicKeyByID(traceCtx, publicKeyID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	if publicKey.UserID != userID {
		logger.Warn("Public key id does not match user id", zap.String("userID", userID.String()), zap.String("publicKeyID", request.ID))
		handlerutil.WriteJSONResponse(w, http.StatusNotFound, nil)
		return
	}

	err = h.settingStore.DeletePublicKey(traceCtx, publicKeyID)
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
