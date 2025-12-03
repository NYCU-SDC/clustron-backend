package user

import (
	"clustron-backend/internal/jwt"
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type Store interface {
	UpdateFullName(ctx context.Context, userID uuid.UUID, fullName string) (User, error)
	SearchByIdentifier(ctx context.Context, query string, page, size int) ([]string, int, error)
}

type Response struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
}

type UpdateFullNameRequest struct {
	FullName string `json:"full_name" validate:"required,min=1,max=255"`
}

type SearchingResponse struct {
	Identifier string `json:"identifier"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store             Store
	paginationFactory pagination.Factory[SearchingResponse]
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	store Store,
) *Handler {
	return &Handler{
		logger:            logger,
		validator:         validator,
		problemWriter:     problemWriter,
		tracer:            otel.Tracer("user/handler"),
		store:             store,
		paginationFactory: pagination.NewFactory[SearchingResponse](200, []string{"created_at"}),
	}
}

func (h *Handler) GetMeHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetMeHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "GetMeHandler"))

	user, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.Error("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, Response{
		ID:       user.ID,
		Email:    user.Email,
		FullName: user.FullName.String,
	})
}

func (h *Handler) UpdateFullNameHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateFullnameHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdateFullnameHandler"))

	user, err := jwt.GetUserFromContext(traceCtx)
	if err != nil {
		logger.Error("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateFullNameRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	updatedUser, err := h.store.UpdateFullName(traceCtx, user.ID, req.FullName)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, Response{
		ID:       updatedUser.ID,
		Email:    updatedUser.Email,
		FullName: updatedUser.FullName.String,
	})
}

func (h *Handler) SearchByIdentifierHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "SearchByIdentifierHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "SearchByIdentifierHandler"))

	pageRequest, err := h.paginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	query := r.URL.Query().Get("query")

	identifiers, totalCount, err := h.store.SearchByIdentifier(traceCtx, query, pageRequest.Page, pageRequest.Size)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := make([]SearchingResponse, len(identifiers))
	for i, identifier := range identifiers {
		response[i] = SearchingResponse{Identifier: identifier}
	}

	pageResponse := h.paginationFactory.NewResponse(response, totalCount, pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}
