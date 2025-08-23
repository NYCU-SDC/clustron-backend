package user

import (
	"context"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

type Store interface {
	SearchByIdentifier(ctx context.Context, query string, page, size int) ([]string, int, error)
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
