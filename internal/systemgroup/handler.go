package systemgroup

import (
	"context"
	"net/http"
	"time"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//mockery:generate: true
type Store interface {
	ListCandidates(ctx context.Context) ([]Candidate, error)
	Discover(ctx context.Context)
	Register(ctx context.Context, name, description string) (SystemGroup, error)
	List(ctx context.Context) ([]SystemGroup, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListMembers(ctx context.Context, id uuid.UUID) ([]Member, error)
	AddMember(ctx context.Context, id, userID uuid.UUID) error
	RemoveMember(ctx context.Context, id, userID uuid.UUID) error
}

type RegisterRequest struct {
	Name        string `json:"name" validate:"required,max=32"`
	Description string `json:"description" validate:"max=1024"`
}

type AddMemberRequest struct {
	UserID string `json:"userId" validate:"required,uuid"`
}

type GIDServersResponse struct {
	GIDNumber int64    `json:"gidNumber"`
	Servers   []string `json:"servers"`
}

type CandidateResponse struct {
	Name           string               `json:"name"`
	Consistent     bool                 `json:"consistent"`
	GIDNumber      *int64               `json:"gidNumber,omitempty"`
	GIDs           []GIDServersResponse `json:"gids"`
	MissingServers []string             `json:"missingServers"`
	Registered     bool                 `json:"registered"`
}

type SystemGroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	GIDNumber   int64     `json:"gidNumber"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

type MemberResponse struct {
	UserID   string    `json:"userId"`
	Email    string    `json:"email"`
	FullName string    `json:"fullName"`
	AddedAt  time.Time `json:"addedAt"`
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	tracer        trace.Tracer
	store         Store
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, store Store) *Handler {
	return &Handler{
		logger:        logger,
		validator:     validator,
		problemWriter: problemWriter,
		tracer:        otel.Tracer("systemgroup/handler"),
		store:         store,
	}
}

func (h *Handler) ListCandidatesHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListSystemGroupCandidatesHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	candidates, err := h.store.ListCandidates(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]CandidateResponse, len(candidates))
	for i, c := range candidates {
		gids := make([]GIDServersResponse, len(c.GIDs))
		for j, g := range c.GIDs {
			gids[j] = GIDServersResponse(g)
		}
		responses[i] = CandidateResponse{
			Name:           c.Name,
			Consistent:     c.Consistent,
			GIDs:           gids,
			MissingServers: c.MissingServers,
			Registered:     c.Registered,
		}
		if c.Consistent {
			gid := c.GIDNumber
			responses[i].GIDNumber = &gid
		}
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) DiscoverHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DiscoverSystemGroupsHandler")
	defer span.End()

	h.store.Discover(traceCtx)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RegisterSystemGroupHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var req RegisterRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	group, err := h.store.Register(traceCtx, req.Name, req.Description)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusCreated, toSystemGroupResponse(group))
}

func (h *Handler) ListHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListSystemGroupsHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	groups, err := h.store.List(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	responses := make([]SystemGroupResponse, len(groups))
	for i, group := range groups {
		responses[i] = toSystemGroupResponse(group)
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "DeleteSystemGroupHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parsePathUUID(traceCtx, w, r, "id", logger)
	if !ok {
		return
	}
	if err := h.store.Delete(traceCtx, id); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListMembersHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ListSystemGroupMembersHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parsePathUUID(traceCtx, w, r, "id", logger)
	if !ok {
		return
	}
	members, err := h.store.ListMembers(traceCtx, id)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	responses := make([]MemberResponse, len(members))
	for i, m := range members {
		responses[i] = MemberResponse{UserID: m.UserID.String(), Email: m.Email, FullName: m.FullName, AddedAt: m.AddedAt}
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) AddMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddSystemGroupMemberHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parsePathUUID(traceCtx, w, r, "id", logger)
	if !ok {
		return
	}
	var req AddMemberRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	userID, err := handlerutil.ParseUUID(req.UserID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	if err = h.store.AddMember(traceCtx, id, userID); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveMemberHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RemoveSystemGroupMemberHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parsePathUUID(traceCtx, w, r, "id", logger)
	if !ok {
		return
	}
	userID, ok := h.parsePathUUID(traceCtx, w, r, "user_id", logger)
	if !ok {
		return
	}
	if err := h.store.RemoveMember(traceCtx, id, userID); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) parsePathUUID(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, logger *zap.Logger) (uuid.UUID, bool) {
	id, err := handlerutil.ParseUUID(r.PathValue(name))
	if err != nil {
		h.problemWriter.WriteError(ctx, w, err, logger)
		return uuid.Nil, false
	}
	return id, true
}

func toSystemGroupResponse(group SystemGroup) SystemGroupResponse {
	return SystemGroupResponse{
		ID:          group.ID.String(),
		Name:        group.Name,
		GIDNumber:   group.GidNumber,
		Description: group.Description.String,
		CreatedAt:   group.CreatedAt.Time,
	}
}
