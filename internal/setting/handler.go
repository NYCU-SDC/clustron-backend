package setting

import (
	"context"
	"errors"
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
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

type UpdateSettingRequest struct {
	Username      string `json:"username" validate:"required"`
	LinuxUsername string `json:"linux_username"`
}

type SettingResponse struct {
	Username      string `json:"username"`
	LinuxUsername string `json:"linux_username"`
}

type PublicKeyRequest struct {
	KeyName   string `json:"key_name"`
	PublicKey string `json:"public_key"`
}
type PublicKeyResponse struct {
	KeyName   string `json:"key_name"`
	PublicKey string `json:"public_key"`
}

type Store interface {
	GetSettingByUserId(ctx context.Context, userId uuid.UUID) (Setting, error)
	UpdateSetting(ctx context.Context, userId uuid.UUID, setting Setting) (Setting, error)
	GetPublicKeysByUserId(ctx context.Context, userId uuid.UUID) ([]PublicKey, error)
	AddPublicKey(ctx context.Context, publicKey PublicKey) (PublicKey, error)
	DeletePublicKey(ctx context.Context, publicKey PublicKey) error
}

type Handler struct {
	validator    *validator.Validate
	logger       *zap.Logger
	tracer       trace.Tracer
	settingStore Store
}

func validatePublicKey(key string) error {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return errors.New("invalid public key format")
	}
	return nil
}

func NewHandler(v *validator.Validate, logger *zap.Logger, store Store) Handler {
	return Handler{
		validator:    v,
		logger:       logger,
		tracer:       otel.Tracer("setting/handler"),
		settingStore: store,
	}
}

func (h *Handler) GetUserSettingHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetUserSettingHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	userId, err := uuid.Parse(user.ID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	setting, err := h.settingStore.GetSettingByUserId(traceCtx, userId)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	response := SettingResponse{
		Username:      setting.Username,
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
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	userId, err := uuid.Parse(user.ID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	var request UpdateSettingRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	setting := Setting{
		UserID:        userId,
		Username:      request.Username,
		LinuxUsername: pgtype.Text{String: request.LinuxUsername, Valid: true},
	}

	updatedSetting, err := h.settingStore.UpdateSetting(traceCtx, userId, setting)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	response := SettingResponse{
		Username:      updatedSetting.Username,
		LinuxUsername: updatedSetting.LinuxUsername.String,
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) GetUserPublicKeysHandler( (w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetUserPublicKeysHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	userId, err := uuid.Parse(user.ID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	publicKeys, err := h.settingStore.GetPublicKeysByUserId(traceCtx, userId)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	q := r.URL.Query()
	raw := q.Get("short")
	var short bool
	if raw != "" {
		short = true
	} else {
		short, err = strconv.ParseBool(raw)
		if err != nil {
			problem.WriteError(traceCtx, w, err, logger)
			return
		}
	}

	response := make([]PublicKeyResponse, len(publicKeys))
	if short {
		for i, publicKey := range publicKeys {
			response[i] = PublicKeyResponse{
				KeyName:   publicKey.Keyname,
				PublicKey: publicKey.PublicKey[:10],
			}
		}
		handlerutil.WriteJSONResponse(w, http.StatusOK, response)
		return
	} else {
		for i, publicKey := range publicKeys {
			response[i] = PublicKeyResponse{
				KeyName:   publicKey.Keyname,
				PublicKey: publicKey.PublicKey,
			}
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
	return
}

func (h *Handler) AddUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddUserPublicKeyHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	userId, err := uuid.Parse(user.ID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	var request PublicKeyRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, request)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}
	err = validatePublicKey(request.PublicKey)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	publicKey := PublicKey{
		UserID:    userId,
		Keyname:   request.KeyName,
		PublicKey: request.PublicKey,
	}

	addedPublicKey, err := h.settingStore.AddPublicKey(traceCtx, publicKey)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	response := PublicKeyResponse{
		KeyName:   addedPublicKey.Keyname,
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
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	userId, err := uuid.Parse(user.ID)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	var request PublicKeyRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, request)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	publicKey := PublicKey{
		UserID:  userId,
		Keyname: request.KeyName,
	}

	err = h.settingStore.DeletePublicKey(traceCtx, publicKey)
	if err != nil {
		problem.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}
