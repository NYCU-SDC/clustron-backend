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
	GetAllGroupCount(ctx context.Context) (int, error)
	GetUserGroupsCount(ctx context.Context, userID uuid.UUID) (int, error)
	GetAll(ctx context.Context, page int, size int, sort string, sortBy string) ([]Group, error)
	GetAllByUserID(ctx context.Context, userID uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, []GroupRole, error)
	GetByID(ctx context.Context, groupID uuid.UUID) (Group, error)
	CreateGroup(ctx context.Context, group CreateParams) (Group, error)
	ArchiveGroup(ctx context.Context, groupID uuid.UUID) (Group, error)
	UnarchiveGroup(ctx context.Context, groupID uuid.UUID) (Group, error)
	FindUserGroupByID(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (Group, error)
	GetUserAllMembership(ctx context.Context, userID uuid.UUID) ([]GetUserAllMembershipRow, error)
	GetUserGroupRole(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (GroupRole, error)
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
		Type string       `json:"type"` // will be "mambership" or "adminOverride"
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

	var groupResponse []Response
	var totalCount int
	if user.Role.String == "admin" { // TODO: the string comparison should be replaced with a enum.
		groups, err := h.store.GetAll(traceCtx, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		roles, err := h.store.GetUserAllMembership(traceCtx, user.ID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		totalCount, err = h.store.GetAllGroupCount(traceCtx)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// map the roles to group ids
		groupRoleMap := make(map[uuid.UUID]RoleResponse)
		for _, role := range roles {
			groupRoleMap[role.GroupID] = RoleResponse{
				ID:          role.RoleID.String(),
				Role:        role.Role.String,
				AccessLevel: role.AccessLevel,
			}
		}
		// join the groups and roles
		groupResponse = make([]Response, len(groups))
		for i, group := range groups {
			groupResponse[i] = Response{
				ID:          group.ID.String(),
				Title:       group.Title,
				Description: group.Description.String,
				IsArchived:  group.IsArchived.Bool,
				CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			}
			role, ok := groupRoleMap[group.ID]
			if ok {
				groupResponse[i].Me.Type = "membership"
				groupResponse[i].Me.Role = role
			} else {
				groupResponse[i].Me.Type = "adminOverride"
			}
		}
	} else {
		groups, roles, err := h.store.GetAllByUserID(traceCtx, user.ID, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		totalCount, err = h.store.GetUserGroupsCount(traceCtx, user.ID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// join the groups and roles
		groupResponse = make([]Response, len(groups))
		for i, group := range groups {
			groupResponse[i] = Response{
				ID:          group.ID.String(),
				Title:       group.Title,
				Description: group.Description.String,
				IsArchived:  group.IsArchived.Bool,
				CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			}
			role := roles[i]
			groupResponse[i].Me.Type = "membership"
			groupResponse[i].Me.Role = RoleResponse{
				ID:          role.ID.String(),
				Role:        role.Role.String,
				AccessLevel: role.AccessLevel,
			}
		}
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

	var group Group
	if user.Role.String != "admin" { // TODO: the string comparison should be replaced with a enum.
		group, err = h.store.FindUserGroupByID(traceCtx, user.ID, groupUUID)
	} else {
		group, err = h.store.GetByID(traceCtx, groupUUID)
	}
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	roleResponse, roleType, err := h.getUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupUUID)
	if err != nil {
		if errors.As(err, &handlerutil.NotFoundError{}) {
			handlerutil.WriteJSONResponse(w, http.StatusNotFound, nil)
			return
		}
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

	roleResponse, roleType, err := h.getUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupUUID)
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

	roleResponse, roleType, err := h.getUserGroupRoleType(traceCtx, user.Role.String, user.ID, groupUUID)
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

func (h *Handler) getUserGroupRoleType(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (RoleResponse, string, error) {
	role, err := h.store.GetUserGroupRole(ctx, userID, groupID)
	roleType := "membership"
	roleResponse := RoleResponse{}
	if err != nil {
		// if the user is not a member of the group, check if the user is an admin
		if errors.As(err, &handlerutil.NotFoundError{}) {
			// if the user is an admin, return the group with admin override
			if userRole == "admin" { // TODO: the string comparison should be replaced with a enum.
				roleType = "adminOverride"
			} else {
				// if the user is not a member of the group and not an admin, return 404
				return RoleResponse{}, "", err
			}
		} else {
			// other errors
			return RoleResponse{}, "", err
		}
	}
	// if roleResponse hasn't been set, it means the user is a member of the group
	if roleResponse == (RoleResponse{}) && roleType != "adminOverride" {
		roleResponse = RoleResponse{
			ID:          role.ID.String(),
			Role:        role.Role.String,
			AccessLevel: role.AccessLevel,
		}
	}

	return roleResponse, roleType, nil
}
