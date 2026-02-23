package module

import (
	"context"
	"encoding/json"
	"net/http"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"

	"clustron-backend/internal"
	"clustron-backend/internal/jwt"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type EnvironmentItem struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}
type CreateRequest struct {
	Title       string            `json:"title" validate:"required,max=100"`
	Description string            `json:"description"`
	Environment []EnvironmentItem `json:"environment" validate:"dive"`
}

type UpdateRequest struct {
	Title       string            `json:"title" validate:"required,max=100"`
	Description string            `json:"description"`
	Environment []EnvironmentItem `json:"environment" validate:"dive"`
}

type Response struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Environment []EnvironmentItem `json:"environment"`
}

type Store interface {
	Create(ctx context.Context, userID uuid.UUID, title string, description string, environment []byte) (Module, error)
	Get(ctx context.Context, id uuid.UUID) (Module, error)
	List(ctx context.Context, userID uuid.UUID) ([]Module, error)
	Update(ctx context.Context, id uuid.UUID, userID uuid.UUID, title string, description string, environment []byte) (Module, error)
	Delete(ctx context.Context, id uuid.UUID, userID uuid.UUID) error
}

type Handler struct {
	store         Store
	validator     *validator.Validate
	logger        *zap.Logger
	tracer        trace.Tracer
	problemWriter *problem.HttpWriter
}

func NewHandler(store Store, validator *validator.Validate, logger *zap.Logger, problemWriter *problem.HttpWriter) *Handler {
	return &Handler{
		store:         store,
		validator:     validator,
		logger:        logger,
		tracer:        otel.Tracer("module/handler"),
		problemWriter: problemWriter,
	}
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Create")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	userID, ok := h.getUserID(traceCtx, w, logger) // ✨ 使用輔助方法
	if !ok {
		return
	}

	var req CreateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	envBytes, err := json.Marshal(req.Environment)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Create(traceCtx, userID, req.Title, req.Description, envBytes)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusCreated, toResponse(module))
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Get")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.getModuleID(traceCtx, w, r, logger) // ✨ 使用輔助方法
	if !ok {
		return
	}

	module, err := h.store.Get(traceCtx, id)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(module))
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "List")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	userID, ok := h.getUserID(traceCtx, w, logger) // ✨ 使用輔助方法
	if !ok {
		return
	}

	modules, err := h.store.List(traceCtx, userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]Response, len(modules))
	for i, m := range modules {
		responses[i] = toResponse(m)
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Update")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	userID, ok := h.getUserID(traceCtx, w, logger)
	if !ok {
		return
	}

	id, ok := h.getModuleID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	var req UpdateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	envBytes, err := json.Marshal(req.Environment)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Update(traceCtx, id, userID, req.Title, req.Description, envBytes)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(module))
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Delete")
	defer span.End()

	logger := logutil.WithContext(traceCtx, h.logger)

	userID, ok := h.getUserID(traceCtx, w, logger)
	if !ok {
		return
	}

	id, ok := h.getModuleID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	if err := h.store.Delete(traceCtx, id, userID); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toResponse(m Module) Response {

	var envItems []EnvironmentItem
	if len(m.Environment) > 0 {
		_ = json.Unmarshal(m.Environment, &envItems)
	}
	return Response{
		ID:          m.ID.String(),
		Title:       m.Title,
		Environment: envItems,
	}
}

func (h *Handler) getUserID(ctx context.Context, w http.ResponseWriter, logger *zap.Logger) (uuid.UUID, bool) {
	user, err := jwt.GetUserFromContext(ctx)
	if err != nil {
		h.problemWriter.WriteError(ctx, w, err, logger)
		return uuid.Nil, false
	}
	return user.ID, true
}

func (h *Handler) getModuleID(ctx context.Context, w http.ResponseWriter, r *http.Request, logger *zap.Logger) (uuid.UUID, bool) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(ctx, w, internal.ErrInvalidUUID, logger)
		return uuid.Nil, false
	}
	return id, true
}
