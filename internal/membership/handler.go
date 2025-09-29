package membership

import (
	"clustron-backend/internal/grouprole"
	"clustron-backend/internal/jwt"
	"clustron-backend/internal/user/role"
	"context"
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

//go:generate mockery --name=Store
type Store interface {
	Add(ctx context.Context, groupId uuid.UUID, memberIdentifier string, role uuid.UUID) (JoinResult, error)
	Remove(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
	Update(ctx context.Context, groupID uuid.UUID, userID uuid.UUID, role uuid.UUID) (MemberResponse, error)
	CountByGroupID(ctx context.Context, groupID uuid.UUID) (int64, error)
	ListWithPaged(ctx context.Context, groupID uuid.UUID, page int, size int, sort string, sortBy string) ([]Response, error)
	ListPendingWithPaged(ctx context.Context, groupID uuid.UUID, page int, size int, sort string, sortBy string) ([]PendingMemberResponse, error)
	UpdatePending(ctx context.Context, groupID uuid.UUID, pendingID uuid.UUID, role uuid.UUID) (PendingMemberResponse, error)
	RemovePending(ctx context.Context, groupID uuid.UUID, pendingID uuid.UUID) error
	CountPendingByGroupID(ctx context.Context, groupID uuid.UUID) (int64, error)
}

//go:generate mockery --name=UserService
type UserService interface {
	GetIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	GetIdByStudentId(ctx context.Context, studentID string) (uuid.UUID, error)
}

type Response struct {
	ID        uuid.UUID              `json:"id"`
	FullName  string                 `json:"fullName"`
	Email     string                 `json:"email"`
	StudentID string                 `json:"studentId"`
	Role      grouprole.RoleResponse `json:"role"`
}

type AddMembersRequest struct {
	Members []AddMemberRequest `json:"members"`
}

type AddMemberRequest struct {
	Member string    `json:"member"` // email or student id
	Role   uuid.UUID `json:"roleId"`
}

type UpdateMemberRequest struct {
	Role uuid.UUID `json:"roleId"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store                    Store
	userService              UserService
	paginationFactory        pagination.Factory[Response]
	pendingPaginationFactory pagination.Factory[PendingMemberResponse]
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	store Store,
	userService UserService,
) *Handler {
	return &Handler{
		logger:                   logger,
		validator:                validator,
		problemWriter:            problemWriter,
		tracer:                   otel.Tracer("member/handler"),
		store:                    store,
		userService:              userService,
		paginationFactory:        pagination.NewFactory[Response](200, []string{"id"}),
		pendingPaginationFactory: pagination.NewFactory[PendingMemberResponse](200, []string{"id"}),
	}
}

func (h *Handler) AddGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddGroupMemberHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "AddGroupMemberHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	user, err := jwt.GetUserFromContext(r.Context())
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var request AddMembersRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	results := JoinMemberResponse{
		AddedSuccessNumber: 0,
		AddedFailureNumber: 0,
		Errors:             []JoinMemberErrorResponse{},
	}
	for _, m := range request.Members {
		if (m.Member == user.Email || m.Member == user.StudentID.String) && !user.HasRole(role.Admin.String()) {
			continue
		}

		_, err = h.store.Add(traceCtx, groupUUID, m.Member, m.Role)
		// Errors happened during adding members, add it the error list
		if err != nil {
			results.AddedFailureNumber++
			results.Errors = append(results.Errors, JoinMemberErrorResponse{
				Member:  m.Member,
				Role:    m.Role.String(),
				Message: err.Error(),
			})
			continue
		}
		// If adding member is successful, increase the success count
		results.AddedSuccessNumber++
	}

	if results.AddedSuccessNumber > 0 {
		handlerutil.WriteJSONResponse(w, http.StatusCreated, results)
		return
	}
	if results.AddedFailureNumber > 0 {
		handlerutil.WriteJSONResponse(w, http.StatusInternalServerError, results)
		return
	}
}

func (h *Handler) RemoveGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RemoveGroupMemberHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "RemoveGroupMemberHandler"))

	groupID := r.PathValue("group_id")
	removedUserID := r.PathValue("user_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	removedUserUUID, err := uuid.Parse(removedUserID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.store.Remove(traceCtx, groupUUID, removedUserUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}

func (h *Handler) UpdateGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateGroupMemberHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdateGroupMemberHandler"))

	groupID := r.PathValue("group_id")
	userID := r.PathValue("user_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateMemberRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	member, err := h.store.Update(traceCtx, groupUUID, userUUID, req.Role)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, member)
}

func (h *Handler) ListGroupMembersPagedHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListGroupMembersPagedHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ListGroupMembersPagedHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pageRequest, err := h.paginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	members, err := h.store.ListWithPaged(
		traceCtx,
		groupUUID,
		pageRequest.Page,
		pageRequest.Size,
		pageRequest.Sort,
		pageRequest.SortBy,
	)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	totalCount, err := h.store.CountByGroupID(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pageResponse := h.paginationFactory.NewResponse(members, int(totalCount), pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}

func (h *Handler) ListPendingMembersPagedHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListPendingMembersPagedHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "ListPendingMembersPagedHandler"))

	groupID := r.PathValue("group_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pageRequest, err := h.pendingPaginationFactory.GetRequest(r)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pendingMembers, err := h.store.ListPendingWithPaged(
		traceCtx,
		groupUUID,
		pageRequest.Page,
		pageRequest.Size,
		pageRequest.Sort,
		pageRequest.SortBy,
	)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	totalCount, err := h.store.CountPendingByGroupID(traceCtx, groupUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pageResponse := h.pendingPaginationFactory.NewResponse(pendingMembers, int(totalCount), pageRequest.Page, pageRequest.Size)
	handlerutil.WriteJSONResponse(w, http.StatusOK, pageResponse)
}

func (h *Handler) UpdatePendingMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdatePendingMemberHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "UpdatePendingMemberHandler"))

	groupID := r.PathValue("group_id")
	pendingID := r.PathValue("pending_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	pendingUUID, err := uuid.Parse(pendingID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateMemberRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	pendingMember, err := h.store.UpdatePending(traceCtx, groupUUID, pendingUUID, req.Role)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, pendingMember)
}

func (h *Handler) RemovePendingMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RemovePendingMemberHandler")
	defer span.End()
	logger := h.logger.With(zap.String("handler", "RemovePendingMemberHandler"))

	groupID := r.PathValue("group_id")
	pendingID := r.PathValue("pending_id")
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	pendingUUID, err := uuid.Parse(pendingID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.store.RemovePending(traceCtx, groupUUID, pendingUUID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}
