package setting

import (
	"clustron-backend/internal/jwt"
	"context"
	"fmt"
	"github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"net/http"
	"strconv"
)

type OnboardingRequest struct {
	Username string `json:"username" validate:"required"`
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
	AddPublicKey(ctx context.Context, publicKey AddPublicKeyParams) (PublicKey, error)
	DeletePublicKey(ctx context.Context, id uuid.UUID) error
	OnboardUser(ctx context.Context, userRole string, userID uuid.UUID, username pgtype.Text) error
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

	err = h.settingStore.OnboardUser(traceCtx, user.Role, user.ID, pgtype.Text{String: request.Username, Valid: true})
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

	var request UpdateSettingRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	setting := Setting{
		UserID:        user.ID,
		Username:      pgtype.Text{String: request.Username, Valid: true},
		LinuxUsername: pgtype.Text{String: request.LinuxUsername, Valid: true},
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
	short := true // default true: frontend usually only needs short public key
	if q.Has("short") {
		short, err = strconv.ParseBool(q.Get("short"))
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
	}

	response := make([]PublicKeyResponse, len(publicKeys))
	if short {
		for i, publicKey := range publicKeys {
			response[i] = PublicKeyResponse{
				ID:        publicKey.ID.String(),
				Title:     publicKey.Title,
				PublicKey: publicKey.PublicKey[:10],
			}
		}
		handlerutil.WriteJSONResponse(w, http.StatusOK, response)
		return
	} else {
		for i, publicKey := range publicKeys {
			response[i] = PublicKeyResponse{
				Title:     publicKey.Title,
				PublicKey: publicKey.PublicKey,
			}
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

	publicKey := AddPublicKeyParams{
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
