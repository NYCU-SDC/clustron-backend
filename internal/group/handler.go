package group

import (
	"context"
	"errors"
	"github.com/NYCU-SDC/clustron-backend/internal/jwt"
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
	GetUserGroupAccessLevel(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (string, error)
	GetUserGroupRole(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (GroupRole, error)
}

//go:generate mockery --name=Store
type Store interface {
	GetAllGroupCount(ctx context.Context) (int, error)
	GetUserGroupsCount(ctx context.Context, userId uuid.UUID) (int, error)
	GetAll(ctx context.Context, page int, size int, sort string, sortBy string) ([]Group, error)
	GetByUserId(ctx context.Context, userId uuid.UUID, page int, size int, sort string, sortBy string) ([]Group, []GroupRole, error)
	GetById(ctx context.Context, groupId uuid.UUID) (Group, error)
	CreateGroup(ctx context.Context, group CreateParams) (Group, error)
	ArchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error)
	UnarchiveGroup(ctx context.Context, groupId uuid.UUID) (Group, error)
	FindUserGroupById(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (Group, error)
	GetUserAllMembership(ctx context.Context, userId uuid.UUID) ([]GetUserAllMembershipRow, error)
	GetUserGroupRole(ctx context.Context, userId uuid.UUID, groupId uuid.UUID) (GroupRole, error)
}

type RoleResponse struct {
	Id          string `json:"id"`
	Role        string `json:"role"`
	AccessLevel string `json:"accessLevel"`
}
type Response struct {
	Id          string `json:"id"`
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
	Validator         *validator.Validate
	Logger            *zap.Logger
	Tracer            trace.Tracer
	ProblemWriter     *problem.HttpWriter
	Store             Store
	Auth              Auth
	PaginationFactory pagination.Factory[Response]
}

func NewHandler(validator *validator.Validate, logger *zap.Logger, store Store, auth Auth) *Handler {
	return &Handler{
		Validator:         validator,
		Logger:            logger,
		Tracer:            otel.Tracer("group/handler"),
		ProblemWriter:     problem.New(),
		Store:             store,
		Auth:              auth,
		PaginationFactory: pagination.NewFactory[Response](200, []string{"created_at"}),
	}
}

// GetAllHandler handles the request to get all groups with pagination and sorting
func (h *Handler) GetAllHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "GetAllGroupHandler")
	defer span.End()
	logger := h.Logger.With(zap.String("handler", "GetAllGroupHandler"))

	pageRequest, err := h.PaginationFactory.GetRequest(r)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
	}

	// verify the role to determine how much data to return
	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var groupResponse []Response
	var totalCount int
	if user.Role.String == "admin" {
		groups, err := h.Store.GetAll(traceCtx, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		roles, err := h.Store.GetUserAllMembership(traceCtx, user.ID)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		totalCount, err = h.Store.GetAllGroupCount(traceCtx)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// map the roles to group ids
		groupRoleMap := make(map[uuid.UUID]RoleResponse)
		for _, role := range roles {
			groupRoleMap[role.GroupID] = RoleResponse{
				Id:          role.RoleID.String(),
				Role:        role.Role.String,
				AccessLevel: role.AccessLevel,
			}
		}
		// join the groups and roles
		groupResponse = make([]Response, len(groups))
		for i, group := range groups {
			groupResponse[i] = Response{
				Id:          group.ID.String(),
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
		groups, roles, err := h.Store.GetByUserId(traceCtx, user.ID, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		totalCount, err = h.Store.GetUserGroupsCount(traceCtx, user.ID)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// join the groups and roles
		groupResponse = make([]Response, len(groups))
		for i, group := range groups {
			groupResponse[i] = Response{
				Id:          group.ID.String(),
				Title:       group.Title,
				Description: group.Description.String,
				IsArchived:  group.IsArchived.Bool,
				CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			}
			role := roles[i]
			groupResponse[i].Me.Type = "membership"
			groupResponse[i].Me.Role = RoleResponse{
				Id:          role.ID.String(),
				Role:        role.Role.String,
				AccessLevel: role.AccessLevel,
			}
		}
	}

	pageResponse := h.PaginationFactory.NewResponse(groupResponse, totalCount, pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}

// GetByIdHandler handles the request to get a group by ID
func (h *Handler) GetByIdHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "GetByIdHandler")
	defer span.End()
	logger := h.Logger.With(zap.String("handler", "GetByIdHandler"))

	// get group id from url
	groupId := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupId)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var group Group
	if user.Role.String != "admin" {
		group, err = h.Store.FindUserGroupById(traceCtx, user.ID, groupUUID)
	} else {
		group, err = h.Store.GetById(traceCtx, groupUUID)
	}
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	role, err := h.Store.GetUserGroupRole(traceCtx, user.ID, groupUUID)
	roleType := "membership"
	roleResponse := RoleResponse{}
	if err != nil {
		// if the user is not a member of the group, check if the user is an admin
		if errors.As(err, &handlerutil.NotFoundError{}) {
			// if the user is an admin, return the group with admin override
			if user.Role.String == "admin" {
				roleType = "adminOverride"
			} else {
				// if the user is not a member of the group and not an admin, return 404
				h.ProblemWriter.WriteError(traceCtx, w, err, logger)
				return
			}
		} else {
			// other errors
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
	}
	// if roleResponse hasn't been set, it means the user is a member of the group
	if roleResponse == (RoleResponse{}) && roleType != "adminOverride" {
		roleResponse = RoleResponse{
			Id:          role.ID.String(),
			Role:        role.Role.String,
			AccessLevel: role.AccessLevel,
		}
	}

	groupResponse := Response{
		Id:          group.ID.String(),
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
	traceCtx, span := h.Tracer.Start(r.Context(), "CreateHandler")
	defer span.End()
	logger := h.Logger.With(zap.String("handler", "CreateHandler"))

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" && user.Role.String != "organizer" {
		handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
		return
	}

	var request CreateRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.Validator, r, &request)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	group, err := h.Store.CreateGroup(traceCtx, CreateParams{
		Title:       request.Title,
		Description: pgtype.Text{String: request.Description, Valid: true},
	})
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// TODO: Add members to the group

	groupResponse := Response{
		Id:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}

	handlerutil.WriteJSONResponse(w, http.StatusCreated, groupResponse)
}

func (h *Handler) ArchiveHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "ArchiveHandler")
	defer span.End()
	logger := h.Logger.With(zap.String("handler", "ArchiveHandler"))

	groupId := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupId)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" {
		accessLevel, err := h.Auth.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != "organizer" {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.Store.ArchiveGroup(traceCtx, groupUUID)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		Id:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}

func (h *Handler) UnarchiveHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.Tracer.Start(r.Context(), "ArchiveHandler")
	defer span.End()
	logger := h.Logger.With(zap.String("handler", "ArchiveHandler"))

	groupId := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupId)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if user.Role.String != "admin" {
		accessLevel, err := h.Auth.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.ProblemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != "organizer" {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.Store.UnarchiveGroup(traceCtx, groupUUID)
	if err != nil {
		h.ProblemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := Response{
		Id:          group.ID.String(),
		Title:       group.Title,
		Description: group.Description.String,
		IsArchived:  group.IsArchived.Bool,
		CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}
