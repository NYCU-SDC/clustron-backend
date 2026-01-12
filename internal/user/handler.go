package user

import (
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"math"
	"net/http"
	"strings"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:generate mockery --name=Store
type Store interface {
	UpdateFullName(ctx context.Context, userID uuid.UUID, fullName string) (User, error)
	SearchByIdentifier(ctx context.Context, query string, page, size int) ([]string, int, error)
	ListUsers(ctx context.Context, params ListUsersServiceParams) ([]ListUsersRow, int, error)
	UpdateRoleByID(ctx context.Context, id uuid.UUID, globalRole string) (User, error)
}

type Response struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	StudentID string    `json:"studentId"`
	Role      string    `json:"role"`
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
		ID:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName.String,
		StudentID: user.StudentID.String,
		Role:      strings.ToUpper(user.Role),
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
	req.FullName = strings.TrimSpace(req.FullName)
	if err := h.validator.Struct(req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidFullName, logger)
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

type ListUserItem struct {
	ID        uuid.UUID `json:"id"`
	FullName  string    `json:"fullName"`
	Email     string    `json:"email"`
	StudentID string    `json:"studentId"`
	Role      string    `json:"role"`
}

type ListUserResponse struct {
	Items       []ListUserItem `json:"items"`
	TotalPages  int            `json:"totalPages"`
	TotalItems  int            `json:"totalItems"`
	CurrentPage int            `json:"currentPage"`
	PageSize    int            `json:"pageSize"`
	HasNextPage bool           `json:"hasNextPage"`
}

func (h *Handler) ListUserHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListUserHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ListUserHandler"))

	pageRequest, err := h.paginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	query := r.URL.Query()
	search := query.Get("search")
	roleFilter := query.Get("role")
	sort := query.Get("sort")
	sortBy := query.Get("sortBy")

	if sortBy != "fullName" && sortBy != "studentID" && sortBy != "email" {
		h.problemWriter.WriteError(traceCtx, w, errors.New("not supported sortBy string"), logger)
		return
	}

	items, totalCount, err := h.store.ListUsers(traceCtx, ListUsersServiceParams{
		Page:   pageRequest.Page,
		Size:   pageRequest.Size,
		Search: search,
		Role:   roleFilter,
		Sort:   sort,
		SortBy: sortBy,
	})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responseItems := make([]ListUserItem, len(items))
	for i, item := range items {
		responseItems[i] = ListUserItem{
			ID:        item.ID,
			FullName:  item.FullName.String,
			Email:     item.Email,
			StudentID: item.StudentID.String,
			Role:      strings.ToUpper(item.Role),
		}
	}

	totalPages := 0
	if pageRequest.Size > 0 {
		totalPages = int(math.Ceil(float64(totalCount) / float64(pageRequest.Size)))
	}

	response := ListUserResponse{
		Items:       responseItems,
		TotalPages:  totalPages,
		TotalItems:  totalCount,
		CurrentPage: pageRequest.Page,
		PageSize:    pageRequest.Size,
		HasNextPage: pageRequest.Page+1 < totalPages,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

type UpdateUserRoleRequest struct {
	Role string `json:"role" validate:"required"`
}

func (h *Handler) UpdateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateUserRoleHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdateUserRoleHandler"))

	idStr := r.PathValue("user_id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, internal.ErrInvalidUUIDFormat, logger)
		return
	}

	var req UpdateUserRoleRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	req.Role = strings.ToLower(req.Role)
	if !role.IsValidGlobalRole(req.Role) {
		h.problemWriter.WriteError(traceCtx, w, errors.New("unknown role type"), logger)
	}

	updatedUser, err := h.store.UpdateRoleByID(traceCtx, id, req.Role)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, Response{
		ID:        updatedUser.ID,
		Email:     updatedUser.Email,
		FullName:  updatedUser.FullName.String,
		StudentID: updatedUser.StudentID.String,
		Role:      strings.ToUpper(updatedUser.Role),
	})
}
