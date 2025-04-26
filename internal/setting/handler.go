package setting

import (
	"context"
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
	"github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type UpdateSettingRequest struct {
	Username      string `json:"username" validate:"required"`
	LinuxUsername string `json:"linux_username"`
}

type SettingResponse struct {
	Username      string `json:"username"`
	LinuxUsername string `json:"linux_username"`
}
type PublicKeyResponse struct {
	PublicKeys []struct {
		KeyName   string `json:"key_name"`
		PublicKey string `json:"public_key"`
	}
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

func NewHandler(validator *validator.Validate, logger *zap.Logger, store Store) Handler {
	return Handler{
		validator:    validator,
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
