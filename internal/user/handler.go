package user

import (
	"clustron-backend/internal"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
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
	FullName  string    `json:"fullName"`
	StudentID string    `json:"studentId"`
	Role      string    `json:"role"`
}

type UpdateFullNameRequest struct {
	FullName string `json:"fullName" validate:"required,min=1,max=255"`
}

type SearchingResponse struct {
	Identifier string `json:"identifier"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store                       Store
	identifierPaginationFactory pagination.Factory[SearchingResponse]
	userInfoPaginationFactory   pagination.Factory[Response]
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	store Store,
) *Handler {
	return &Handler{
		logger:                      logger,
		validator:                   validator,
		problemWriter:               problemWriter,
		tracer:                      otel.Tracer("user/handler"),
		store:                       store,
		identifierPaginationFactory: pagination.NewFactory[SearchingResponse](200, []string{"created_at"}),
		userInfoPaginationFactory:   pagination.NewFactory[Response](200, []string{"studentId", "fullName", "email"}),
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
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateFullNameHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdateFullNameHandler"))

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

	pageRequest, err := h.identifierPaginationFactory.GetRequest(r)
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

	pageResponse := h.identifierPaginationFactory.NewResponse(response, totalCount, pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}

func (h *Handler) ListUserHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListUserHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ListUserHandler"))

	pageRequest, err := h.userInfoPaginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	query := r.URL.Query()
	search := query.Get("search")
	roleFilter := query.Get("role")

	roleFilter = strings.ToLower(roleFilter)

	if !role.IsValidGlobalRole(roleFilter) && roleFilter != "" {
		h.problemWriter.WriteError(traceCtx, w, errors.New("unknown role type"), logger)
		return
	}

	items, totalCount, err := h.store.ListUsers(traceCtx, ListUsersServiceParams{
		Search: search,
		Role:   roleFilter,
		SortBy: pageRequest.SortBy,
		Page:   pageRequest.Page,
		Size:   pageRequest.Size,
	})

	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responseItems := make([]Response, len(items))
	for i, item := range items {
		responseItems[i] = Response{
			ID:        item.ID,
			FullName:  item.FullName.String,
			Email:     item.Email,
			StudentID: item.StudentID.String,
			Role:      strings.ToUpper(item.Role),
		}
	}

	pageResponse := h.userInfoPaginationFactory.NewResponse(responseItems, totalCount, pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
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
		h.problemWriter.WriteError(traceCtx, w, handlerutil.ErrInvalidUUID, logger)
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
		return
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
