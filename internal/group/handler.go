package group

import (
	"clustron-backend/internal/jwt"
	"context"
	"errors"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

//go:generate mockery --name=Auth
type Auth interface {
	GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error)
	GetUserGroupRole(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (GroupRole, error)
}

//go:generate mockery --name=Store
type Store interface {
	GetAllWithUserScope(ctx context.Context, user jwt.User, page int, size int, sort string, sortBy string) ([]UserScope, int /* totalCount */, error)
	GetByIDWithUserScope(ctx context.Context, user jwt.User, groupID uuid.UUID) (UserScope, error)
	GetUserGroupRoleType(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (RoleResponse, string, error)
	CreateGroup(ctx context.Context, group CreateParams) (Group, error)
	ArchiveGroup(ctx context.Context, groupID uuid.UUID) (Group, error)
	UnarchiveGroup(ctx context.Context, groupID uuid.UUID) (Group, error)
	GetGroupRoleByID(ctx context.Context, roleID uuid.UUID) (GroupRole, error)
}

type RoleResponse struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	AccessLevel string `json:"accessLevel"`
}

type Response struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsArchived  bool   `json:"isArchived"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	Me          struct {
		Type string       `json:"type"` // will be "membership" or "adminOverride"
		Role RoleResponse `json:"role"`
	} `json:"me"`
}

type AddMemberRequest struct {
	Member string `json:"member"` // email or student id
	Role   string `json:"role"`
}

type CreateRequest struct {
	Title       string             `json:"title" validate:"required"`
	Description string             `json:"description" validate:"required"`
	Members     []AddMemberRequest `json:"members"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store             Store
	auth              Auth
	paginationFactory pagination.Factory[Response]
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, store Store, auth Auth) *Handler {
	return &Handler{
		validator:         validator,
		logger:            logger,
		tracer:            otel.Tracer("group/handler"),
		problemWriter:     problemWriter,
		store:             store,
		auth:              auth,
		paginationFactory: pagination.NewFactory[Response](200, []string{"created_at"}),
	}
}

// GetAllHandler handles the request to get all groups with pagination and sorting
func (h *Handler) GetAllHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetAllGroupHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "GetAllGroupHandler"))

	pageRequest, err := h.paginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
	}

	// verify the role to determine how much data to return
	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userScopeResponse, totalCount, err := h.store.GetAllWithUserScope(traceCtx, user, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)

	groupResponse := make([]Response, len(userScopeResponse))
	for i, group := range userScopeResponse {
		groupResponse[i] = Response{
			ID:          group.ID.String(),
			Title:       group.Title,
			Description: group.Description.String,
			IsArchived:  group.IsArchived.Bool,
			CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		}
		groupResponse[i].Me.Type = group.Me.Type
		groupResponse[i].Me.Role = group.Me.Role
	}

	pageResponse := h.paginationFactory.NewResponse(groupResponse, totalCount, pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}

// GetByIDHandler handles the request to get a group by ID
func (h *Handler) GetByIDHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetByIDHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "GetByIDHandler"))

	// get group id from url
	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userScopeResponse, err := h.store.GetByIDWithUserScope(traceCtx, user, groupUUID)
	if err != nil {
		if errors.As(err, &handlerutil.NotFoundError{}) {
			handlerutil.WriteJSONResponse(w, http.StatusNotFound, nil)
			return
		}
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		ID:          userScopeResponse.ID.String(),
		Title:       userScopeResponse.Title,
		Description: userScopeResponse.Description.String,
		IsArchived:  userScopeResponse.IsArchived.Bool,
		CreatedAt:   userScopeResponse.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   userScopeResponse.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	groupResponse.Me.Type = userScopeResponse.Me.Type
	groupResponse.Me.Role = userScopeResponse.Me.Role

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}

func (h *Handler) CreateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "CreateHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "CreateHandler"))

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" && user.Role.String != "organizer" { // TODO: the string comparison should be replaced with a enum.
		handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
		return
	}

	var request CreateRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	group, err := h.store.CreateGroup(traceCtx, CreateParams{
		Title:       request.Title,
		Description: pgtype.Text{String: request.Description, Valid: true},
	})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// TODO: Add members to the group and set the creator as the group-owner

	roleOwner, err := h.store.GetGroupRoleByID(traceCtx, uuid.MustParse(string(RoleOwner)))
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		ID:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	groupResponse.Me.Type = "membership"
	groupResponse.Me.Role = RoleResponse{
		ID:          roleOwner.ID.String(),
		Role:        roleOwner.Role.String,
		AccessLevel: roleOwner.AccessLevel,
	}

	handlerutil.WriteJSONResponse(w, http.StatusCreated, groupResponse)
}

func (h *Handler) ArchiveHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ArchiveHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ArchiveHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" { // TODO: the string comparison should be replaced with a enum.
		accessLevel, err := h.auth.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != string(AccessLevelOwner) {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.store.ArchiveGroup(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	roleResponse, roleType, err := h.store.GetUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		ID:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	groupResponse.Me.Type = roleType
	if roleType == "membership" {
		groupResponse.Me.Role = roleResponse
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}

func (h *Handler) UnarchiveHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ArchiveHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ArchiveHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" { // TODO: the string comparison should be replaced with a enum.
		accessLevel, err := h.auth.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != string(AccessLevelOwner) {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.store.UnarchiveGroup(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	roleResponse, roleType, err := h.store.GetUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		ID:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	groupResponse.Me.Type = roleType
	if roleType == "membership" {
		groupResponse.Me.Role = roleResponse
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}
