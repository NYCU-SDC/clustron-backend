package module

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type CreateRequest struct {
	Title       string          `json:"title" validate:"required,max=100"`
	Description string          `json:"description"`
	Environment json.RawMessage `json:"environment"`
}

type UpdateRequest struct {
	Title       string          `json:"title" validate:"required,max=100"`
	Description string          `json:"description"`
	Environment json.RawMessage `json:"environment"`
}

type Response struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Environment json.RawMessage `json:"environment"`
}

type Store interface {
	Create(ctx context.Context, title string, description string, environment []byte) (Module, error)
	Get(ctx context.Context, id uuid.UUID) (Module, error)
	ListPaged(ctx context.Context, page int, size int) ([]Module, error)
	Update(ctx context.Context, id uuid.UUID, title string, description string, environment []byte) (Module, error)
	Delete(ctx context.Context, id uuid.UUID) error
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

	var req CreateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Create(traceCtx, req.Title, req.Description, req.Environment)
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

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
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

	pageStr := r.URL.Query().Get("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		page = 0
	}

	sizeStr := r.URL.Query().Get("size")
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size <= 0 {
		size = 10
	}

	modules, err := h.store.ListPaged(traceCtx, page, size)
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

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	module, err := h.store.Update(traceCtx, id, req.Title, req.Description, req.Environment)
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

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if err := h.store.Delete(traceCtx, id); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func toResponse(m Module) Response {
	return Response{
		ID:          m.ID.String(),
		Title:       m.Title,
		Environment: m.Environment,
	}
}
