package ansible

import (
	"context"
	"net/http"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type AddNodeRequest struct {
	AnsibleName    string `json:"ansible_name"     validate:"required"`
	IpAddress      string `json:"ip_address"       validate:"required_without=SshConfigHost"`
	SshConfigHost  string `json:"ssh_config_host"  validate:"required_without=IpAddress"`
	PrivateIp      string `json:"private_ip"`
	SshUser        string `json:"ssh_user"         validate:"required"`
	SshKeyName     string `json:"ssh_key_name"`
	AnsibleRole    string `json:"ansible_role"     validate:"required"`
	SlurmPartition string `json:"slurm_partition"`
	CpuCores       *int32 `json:"cpu_cores"`
	MemoryMb       *int32 `json:"memory_mb"`
}

type ServerResponse struct {
	ID              string  `json:"id"`
	AnsibleName     string  `json:"ansible_name"`
	IpAddress       string  `json:"ip_address,omitempty"`
	SshConfigHost   string  `json:"ssh_config_host,omitempty"`
	PrivateIp       string  `json:"private_ip,omitempty"`
	SshUser         string  `json:"ssh_user"`
	SshKeyName      string  `json:"ssh_key_name,omitempty"`
	AnsibleRole     string  `json:"ansible_role"`
	SlurmPartition  string  `json:"slurm_partition,omitempty"`
	Status          string  `json:"status"`
	ProvisionDetail *string `json:"provision_detail,omitempty"`
	CpuCores        *int32  `json:"cpu_cores,omitempty"`
	MemoryMb        *int32  `json:"memory_mb,omitempty"`
}

type UpdateRoleRequest struct {
	AnsibleRole string `json:"ansible_role" validate:"required"`
}

type Store interface {
	ListAll(ctx context.Context) ([]Server, error)
	AddNode(ctx context.Context, params CreateParams) (Server, error)
	GetByID(ctx context.Context, id uuid.UUID) (Server, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SetupAllNodes(ctx context.Context) error
	ResetNode(ctx context.Context, id uuid.UUID) (Server, error)
	UpdateRole(ctx context.Context, id uuid.UUID, role string) (Server, error)
}

type Handler struct {
	store         Store
	validator     *validator.Validate
	logger        *zap.Logger
	tracer        trace.Tracer
	problemWriter *problem.HttpWriter
}

func NewHandler(store Store, validator *validator.Validate, logger *zap.Logger, problemWriter *problem.HttpWriter) *Handler {
	return &Handler{
		store:         store,
		validator:     validator,
		logger:        logger,
		tracer:        otel.Tracer("ansible/handler"),
		problemWriter: problemWriter,
	}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "List")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	servers, err := h.store.ListAll(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]ServerResponse, len(servers))
	for i, s := range servers {
		responses[i] = toResponse(s)
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) AddNode(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var req AddNodeRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	params := CreateParams{
		AnsibleName:   req.AnsibleName,
		IpAddress:     pgtype.Text{String: req.IpAddress, Valid: req.IpAddress != ""},
		SshConfigHost: pgtype.Text{String: req.SshConfigHost, Valid: req.SshConfigHost != ""},
		PrivateIp:     pgtype.Text{String: req.PrivateIp, Valid: req.PrivateIp != ""},
		SshUser:       req.SshUser,
		SshKeyName:    pgtype.Text{String: req.SshKeyName, Valid: req.SshKeyName != ""},
		AnsibleRole:   req.AnsibleRole,
	}
	if req.SlurmPartition != "" {
		params.SlurmPartition = pgtype.Text{String: req.SlurmPartition, Valid: true}
	}
	if req.CpuCores != nil {
		params.CpuCores = pgtype.Int4{Int32: *req.CpuCores, Valid: true}
	}
	if req.MemoryMb != nil {
		params.MemoryMb = pgtype.Int4{Int32: *req.MemoryMb, Valid: true}
	}

	server, err := h.store.AddNode(traceCtx, params)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusCreated, toResponse(server))
}

func (h *Handler) GetByID(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	server, err := h.store.GetByID(traceCtx, id)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(server))
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "Delete")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	if err := h.store.Delete(traceCtx, id); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ResetNode(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ResetNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	server, err := h.store.ResetNode(traceCtx, id)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(server))
}

func (h *Handler) SetupAll(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "SetupAll")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	if err := h.store.SetupAllNodes(traceCtx); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	id, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	var req UpdateRoleRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	server, err := h.store.UpdateRole(traceCtx, id, req.AnsibleRole)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, toResponse(server))
}

func (h *Handler) parseServerID(ctx context.Context, w http.ResponseWriter, r *http.Request, logger *zap.Logger) (uuid.UUID, bool) {
	id, err := handlerutil.ParseUUID(r.PathValue("server_id"))
	if err != nil {
		h.problemWriter.WriteError(ctx, w, err, logger)
		return uuid.Nil, false
	}
	return id, true
}

func toResponse(s Server) ServerResponse {
	resp := ServerResponse{
		ID:          s.ID.String(),
		AnsibleName: s.AnsibleName,
		SshUser:     s.SshUser,
		AnsibleRole: s.AnsibleRole,
		Status:      s.Status,
	}
	if s.IpAddress.Valid {
		resp.IpAddress = s.IpAddress.String
	}
	if s.SshConfigHost.Valid {
		resp.SshConfigHost = s.SshConfigHost.String
	}
	if s.PrivateIp.Valid {
		resp.PrivateIp = s.PrivateIp.String
	}
	if s.SshKeyName.Valid {
		resp.SshKeyName = s.SshKeyName.String
	}
	if s.SlurmPartition.Valid {
		resp.SlurmPartition = s.SlurmPartition.String
	}
	if s.ProvisionDetail.Valid {
		v := s.ProvisionDetail.String
		resp.ProvisionDetail = &v
	}
	if s.CpuCores.Valid {
		v := s.CpuCores.Int32
		resp.CpuCores = &v
	}
	if s.MemoryMb.Valid {
		v := s.MemoryMb.Int32
		resp.MemoryMb = &v
	}
	return resp
}
