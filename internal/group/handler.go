package group

import (
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/membership"
	"clustron-backend/internal/user/role"
	"context"
	"errors"
	"net/http"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/pagination"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:generate mockery --name=MemberStore
type MemberStore interface {
	Add(ctx context.Context, groupId uuid.UUID, memberIdentifier string, role uuid.UUID) (membership.JoinResult, error)
	Join(ctx context.Context, userId uuid.UUID, groupId uuid.UUID, role uuid.UUID, isArchived bool) (membership.MemberResponse, error)
	Remove(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
	Update(ctx context.Context, groupID uuid.UUID, userID uuid.UUID, role uuid.UUID) (membership.MemberResponse, error)
}

//go:generate mockery --name=Store
type Store interface {
	ListWithUserScope(ctx context.Context, user jwt.User, page int, size int, sort string, sortBy string) ([]grouprole.UserScope, int /* totalCount */, error)
	ListByIDWithLinks(ctx context.Context, user jwt.User, groupID uuid.UUID) (ResponseWithLinks, error)
	Create(ctx context.Context, userID uuid.UUID, title, description string) (Group, error)
	Archive(ctx context.Context, groupID uuid.UUID) (Group, error)
	Unarchive(ctx context.Context, groupID uuid.UUID) (Group, error)
	GetTypeByUser(ctx context.Context, userRole string, userID uuid.UUID, groupID uuid.UUID) (grouprole.GroupRole, string, error)
	GetUserGroupAccessLevel(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) (string, error)
	GetByID(ctx context.Context, roleID uuid.UUID) (grouprole.GroupRole, error)
	TransferOwner(ctx context.Context, groupID uuid.UUID, newOwnerIdentifier string, user jwt.User) (grouprole.UserScope, error)
	CreateLink(ctx context.Context, groupID uuid.UUID, title string, Url string) (Link, error)
	UpdateLink(ctx context.Context, groupID uuid.UUID, linkID uuid.UUID, title string, Url string) (Link, error)
	DeleteLink(ctx context.Context, groupID uuid.UUID, linkID uuid.UUID) error
}

type LinkResponse struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Url   string `json:"url"`
}

type CreateLinkRequest struct {
	Title string `json:"title" validate:"required"`
	Url   string `json:"url" validate:"required"`
}

type Response struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsArchived  bool   `json:"isArchived"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	Me          struct {
		Type string                 `json:"type"` // will be "membership" or "adminOverride"
		Role grouprole.RoleResponse `json:"role"`
	} `json:"me"`
}

type WithLinksResponse struct {
	Response
	Links []LinkResponse `json:"links"`
}

type CreateResponse struct {
	Response
	AddedResult membership.JoinMemberResponse `json:"addedResult"` // contains the result of adding members
}

type CreateRequest struct {
	Title       string                        `json:"title" validate:"required,regexp=^[a-zA-Z]([a-zA-Z0-9- ]*[a-zA-Z0-9])?$"`
	Description string                        `json:"description" validate:"required"`
	Members     []membership.AddMemberRequest `json:"members"`
	Links       []CreateLinkRequest
}

type TransferOwnerRequest struct {
	Identifier string `json:"identifier"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store             Store
	memberStore       MemberStore
	paginationFactory pagination.Factory[Response]
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	store Store,
	memberStore MemberStore) *Handler {
	return &Handler{
		validator:         validator,
		logger:            logger,
		tracer:            otel.Tracer("group/handler"),
		problemWriter:     problemWriter,
		store:             store,
		memberStore:       memberStore,
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
		return
	}

	// verify the role to determine how much data to return
	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		logger.DPanic("Can't find user in context, this should never happen")
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	userScopeResponse, totalCount, err := h.store.ListWithUserScope(traceCtx, user, pageRequest.Page, pageRequest.Size, pageRequest.Sort, pageRequest.SortBy)
	if err != nil {
		if errors.As(err, &handlerutil.NotFoundError{}) {
			handlerutil.WriteJSONResponse(w, http.StatusNotFound, nil)
			return
		}
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

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
		groupResponse[i].Me.Role = group.Me.Role.ToResponse()
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

	userScopeResponse, err := h.store.ListByIDWithLinks(traceCtx, user, groupUUID)
	if err != nil {
		if errors.As(err, &handlerutil.NotFoundError{}) {
			handlerutil.WriteJSONResponse(w, http.StatusNotFound, nil)
			return
		}
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupResponse := WithLinksResponse{
		// Basic group information
		Response: Response{
			ID:          userScopeResponse.ID.String(),
			Title:       userScopeResponse.Title,
			Description: userScopeResponse.Description.String,
			IsArchived:  userScopeResponse.IsArchived.Bool,
			CreatedAt:   userScopeResponse.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   userScopeResponse.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		},
	}

	// User-specific information
	groupResponse.Me.Type = userScopeResponse.Me.Type
	groupResponse.Me.Role = userScopeResponse.Me.Role.ToResponse()

	// Links resources of the group
	groupResponse.Links = make([]LinkResponse, len(userScopeResponse.Links))
	for i, link := range userScopeResponse.Links {
		groupResponse.Links[i] = LinkResponse{
			ID:    link.ID.String(),
			Title: link.Title,
			Url:   link.Url,
		}
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

	if user.Role != role.Admin.String() && user.Role != role.Organizer.String() {
		handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
		return
	}

	var request CreateRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	group, err := h.store.Create(traceCtx, user.ID, request.Title, request.Description)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	roleOwner, err := h.store.GetByID(traceCtx, uuid.MustParse(string(grouprole.RoleOwner)))
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 1. Set creator as a group-owner
	_, err = h.memberStore.Join(traceCtx, user.ID, group.ID, roleOwner.ID, false)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// 2. Add other members
	results := membership.JoinMemberResponse{
		AddedSuccessNumber: 0,
		AddedFailureNumber: 0,
		Errors:             []membership.JoinMemberErrorResponse{},
	}
	for _, m := range request.Members {
		if m.Member == user.Email || m.Member == user.StudentID.String {
			continue
		}

		_, err = h.memberStore.Add(traceCtx, group.ID, m.Member, m.Role)
		if err != nil {
			results.AddedFailureNumber++
			results.Errors = append(results.Errors, membership.JoinMemberErrorResponse{
				Member:  m.Member,
				Role:    m.Role.String(),
				Message: err.Error(),
			})
			continue
		}
		// If adding member is successful, increase the success count
		results.AddedSuccessNumber++
	}

	// 3. Add links
	for _, link := range request.Links {
		_, err = h.store.CreateLink(traceCtx, group.ID, link.Title, link.Url)
		if err != nil {
			continue
		}
	}

	groupResponse := CreateResponse{
		Response: Response{
			ID:          group.ID.String(),
			Title:       group.Title,
			Description: group.Description.String,
			IsArchived:  group.IsArchived.Bool,
			CreatedAt:   group.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   group.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		},
		AddedResult: results,
	}
	groupResponse.Me.Type = "membership"
	groupResponse.Me.Role = grouprole.RoleResponse{
		ID:          roleOwner.ID.String(),
		RoleName:    roleOwner.RoleName,
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

	if user.Role != grouprole.AccessLevelAdmin.String() {
		accessLevel, err := h.store.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != string(grouprole.AccessLevelOwner) {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.store.Archive(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	role, roleType, err := h.store.GetTypeByUser(traceCtx, user.Role, user.ID, groupUUID)
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
		groupResponse.Me.Role = grouprole.RoleResponse{
			ID:          role.ID.String(),
			RoleName:    role.RoleName,
			AccessLevel: role.AccessLevel,
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}

func (h *Handler) UnarchiveHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UnarchiveHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UnarchiveHandler"))

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

	if user.Role != grouprole.AccessLevelAdmin.String() {
		accessLevel, err := h.store.GetUserGroupAccessLevel(traceCtx, user.ID, groupUUID)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		if accessLevel != string(grouprole.AccessLevelOwner) {
			handlerutil.WriteJSONResponse(w, http.StatusForbidden, nil)
			return
		}
	}

	group, err := h.store.Unarchive(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	role, roleType, err := h.store.GetTypeByUser(traceCtx, user.Role, user.ID, groupUUID)
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
		groupResponse.Me.Role = grouprole.RoleResponse{
			ID:          role.ID.String(),
			RoleName:    role.RoleName,
			AccessLevel: role.AccessLevel,
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}

func (h *Handler) CreateLinkHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "CreateLinkHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "CreateLinkHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request CreateLinkRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	link, err := h.store.CreateLink(traceCtx, groupUUID, request.Title, request.Url)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := LinkResponse{
		ID:    link.ID.String(),
		Title: link.Title,
		Url:   link.Url,
	}

	handlerutil.WriteJSONResponse(w, http.StatusCreated, response)
}

func (h *Handler) UpdateLinkHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateLinkHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdateLinkHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	linkID := r.PathValue("link_id")
	linkUUID, err := uuid.Parse(linkID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request CreateLinkRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	link, err := h.store.UpdateLink(traceCtx, groupUUID, linkUUID, request.Title, request.Url)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	response := LinkResponse{
		ID:    link.ID.String(),
		Title: link.Title,
		Url:   link.Url,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

func (h *Handler) DeleteLinkHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DeleteLinkHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "DeleteLinkHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	linkID := r.PathValue("link_id")
	linkUUID, err := uuid.Parse(linkID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.store.DeleteLink(traceCtx, groupUUID, linkUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusNoContent, nil)
}

func (h *Handler) TransferGroupOwnerHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "TransferGroupOwnerHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "TransferGroupOwnerHandler"))

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

	var request TransferOwnerRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Change role of old owner of the group
	userScopeResponse, err := h.store.TransferOwner(traceCtx, groupUUID, request.Identifier, user)
	if err != nil {
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
	groupResponse.Me.Role = userScopeResponse.Me.Role.ToResponse()

	handlerutil.WriteJSONResponse(w, http.StatusOK, groupResponse)
}
