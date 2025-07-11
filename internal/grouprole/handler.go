package grouprole

import (
	"context"
	"net/http"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:generate mockery --name=Store
type Store interface {
	GetAll(ctx context.Context) ([]GroupRole, error)
	Create(ctx context.Context, params CreateParams) (GroupRole, error)
	Update(ctx context.Context, params UpdateParams) (GroupRole, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer

	store Store
}

func NewHandler(
	logger *zap.Logger,
	validator *validator.Validate,
	problemWriter *problem.HttpWriter,
	store Store,
) *Handler {
	return &Handler{
		logger:        logger,
		validator:     validator,
		problemWriter: problemWriter,
		tracer:        otel.Tracer("grouprole/handler"),
		store:         store,
	}
}

type CreateRequest struct {
	RoleName    string `json:"role" validate:"required"`
	AccessLevel string `json:"accessLevel" validate:"required,oneof=GROUP_OWNER GROUP_ADMIN USER"`
}

type UpdateRequest struct {
	RoleName    string `json:"role" validate:"required"`
	AccessLevel string `json:"accessLevel" validate:"required,oneof=GROUP_OWNER GROUP_ADMIN USER"`
}

func (h *Handler) GetAllHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListGroupRolesHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	roles, err := h.store.GetAll(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	rolesResponse := make([]RoleResponse, len(roles))
	for i, role := range roles {
		rolesResponse[i] = RoleResponse{
			ID:          role.ID.String(),
			RoleName:    role.RoleName,
			AccessLevel: role.AccessLevel,
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, rolesResponse)
}

func (h *Handler) CreateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "CreateGroupRoleHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var req CreateRequest
	err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	createdRole, err := h.store.Create(traceCtx, CreateParams{
		RoleName:    req.RoleName,
		AccessLevel: req.AccessLevel,
	})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	createdRoleResponse := RoleResponse{
		ID:          createdRole.ID.String(),
		RoleName:    createdRole.RoleName,
		AccessLevel: createdRole.AccessLevel,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, createdRoleResponse)
}

func (h *Handler) UpdateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateGroupRoleHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	roleIDStr := r.PathValue("role_id")
	if roleIDStr == "" {
		h.problemWriter.WriteError(traceCtx, w, handlerutil.NewNotFoundError("group_role", "id", roleIDStr, "missing group role ID"), logger)
		return
	}
	roleID, err := handlerutil.ParseUUID(roleIDStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	var req UpdateRequest
	err = handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	updatedRole, err := h.store.Update(traceCtx, UpdateParams{
		ID:          roleID,
		RoleName:    req.RoleName,
		AccessLevel: req.AccessLevel,
	})
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, updatedRole)
}

func (h *Handler) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DeleteGroupRoleHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	roleIDStr := r.PathValue("role_id")
	if roleIDStr == "" {
		h.problemWriter.WriteError(traceCtx, w, handlerutil.NewNotFoundError("group_role", "id", roleIDStr, "missing group role ID"), logger)
		return
	}
	roleID, err := handlerutil.ParseUUID(roleIDStr)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	err = h.store.Delete(traceCtx, roleID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusNoContent, nil)
}
