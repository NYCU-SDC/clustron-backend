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
	AnsibleName    string `json:"ansible_name"     validate:"required,max=253,hostname_rfc1123"`
	IpAddress      string `json:"ip_address"       validate:"required_without=SshConfigHost,omitempty,ip"`
	SshConfigHost  string `json:"ssh_config_host"  validate:"required_without=IpAddress,max=255"`
	PrivateIp      string `json:"private_ip"       validate:"required_without=IpAddress,omitempty,ip"`
	SshUser        string `json:"ssh_user"         validate:"required_with=IpAddress,max=255"`
	SshKeyName     string `json:"ssh_key_name"     validate:"max=255"`
	AnsibleRole    string `json:"ansible_role"     validate:"required,oneof=head_nodes compute_nodes"`
	SlurmPartition string `json:"slurm_partition"  validate:"max=255"`
	CpuCores       *int32 `json:"cpu_cores"       validate:"omitempty,min=1"`
	MemoryMb       *int32 `json:"memory_mb"       validate:"omitempty,min=1"`
}

type AddNodesRequest struct {
	Servers []AddNodeRequest `json:"servers" validate:"required,min=1,max=50,dive"`
}

type AddNodesResponse struct {
	Servers []ServerResponse `json:"servers"`
}

type ServerResponse struct {
	ID              string  `json:"id"`
	AnsibleName     string  `json:"ansible_name"`
	IpAddress       string  `json:"ip_address,omitempty"`
	SshConfigHost   string  `json:"ssh_config_host,omitempty"`
	PrivateIp       string  `json:"private_ip,omitempty"`
	SshUser         string  `json:"ssh_user,omitempty"`
	SshKeyName      string  `json:"ssh_key_name,omitempty"`
	AnsibleRole     string  `json:"ansible_role"`
	SlurmPartition  string  `json:"slurm_partition,omitempty"`
	Status          string  `json:"status"`
	ProvisionDetail *string `json:"provision_detail,omitempty"`
	CpuCores        *int32  `json:"cpu_cores,omitempty"`
	MemoryMb        *int32  `json:"memory_mb,omitempty"`
}

type UpdateRoleRequest struct {
	AnsibleRole string `json:"ansible_role" validate:"required,oneof=head_nodes compute_nodes"`
}

//mockery:generate: true
type Store interface {
	ListAll(ctx context.Context) ([]Server, error)
	AddNode(ctx context.Context, params CreateParams) (Server, error)
	AddNodes(ctx context.Context, params []CreateParams) ([]Server, error)
	GetByID(ctx context.Context, id uuid.UUID) (Server, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SetupAllNodes(ctx context.Context) error
	ResetNode(ctx context.Context, id uuid.UUID) (Server, error)
	UpdateRole(ctx context.Context, id uuid.UUID, role string) (Server, error)
	ListAllowedLoginGroups(ctx context.Context, serverID uuid.UUID) ([]AllowedLoginGroupDetail, error)
	SetAllowedLoginGroups(ctx context.Context, serverID uuid.UUID, groupIDs []uuid.UUID) error
	ListPartitionAllowedGroups(ctx context.Context, partitionName string) ([]PartitionAllowedGroupDetail, error)
	SetPartitionAllowedGroups(ctx context.Context, partitionName string, groupIDs []uuid.UUID) error
}

type UpdateAllowedLoginGroupsRequest struct {
	GroupIDs []string `json:"groupIds" validate:"required,dive,uuid"`
}

// UpdatePartitionAllowedGroupsRequest omits `required` so that an empty list is a valid way to
// re-open a partition to every group.
type UpdatePartitionAllowedGroupsRequest struct {
	GroupIDs []string `json:"groupIds" validate:"dive,uuid"`
}

type AllowedLoginGroupResponse struct {
	GroupID string `json:"groupId"`
	Title   string `json:"title"`
	LdapCN  string `json:"ldapCn"`
}

type PartitionAllowedGroupResponse struct {
	GroupID string `json:"groupId"`
	Title   string `json:"title"`
	LdapCN  string `json:"ldapCn"`
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

	server, err := h.store.AddNode(traceCtx, toCreateParams(req))
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	handlerutil.WriteJSONResponse(w, http.StatusCreated, toResponse(server))
}

func (h *Handler) AddNodes(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AddNodes")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var req AddNodesRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	params := make([]CreateParams, len(req.Servers))
	for i, server := range req.Servers {
		params[i] = toCreateParams(server)
	}

	servers, err := h.store.AddNodes(traceCtx, params)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]ServerResponse, len(servers))
	for i, server := range servers {
		responses[i] = toResponse(server)
	}
	handlerutil.WriteJSONResponse(w, http.StatusCreated, AddNodesResponse{Servers: responses})
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

func (h *Handler) GetAllowedLoginGroups(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetAllowedLoginGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	serverID, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	groups, err := h.store.ListAllowedLoginGroups(traceCtx, serverID)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]AllowedLoginGroupResponse, len(groups))
	for i, g := range groups {
		responses[i] = AllowedLoginGroupResponse{
			GroupID: g.GroupID.String(),
			Title:   g.Title,
			LdapCN:  g.LdapCN,
		}
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) UpdateAllowedLoginGroups(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdateAllowedLoginGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	serverID, ok := h.parseServerID(traceCtx, w, r, logger)
	if !ok {
		return
	}

	var req UpdateAllowedLoginGroupsRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupIDs := make([]uuid.UUID, len(req.GroupIDs))
	for i, raw := range req.GroupIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		groupIDs[i] = id
	}

	if err := h.store.SetAllowedLoginGroups(traceCtx, serverID, groupIDs); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetPartitionAllowedGroups(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "GetPartitionAllowedGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	partitionName := r.PathValue("partition_name")

	groups, err := h.store.ListPartitionAllowedGroups(traceCtx, partitionName)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	responses := make([]PartitionAllowedGroupResponse, len(groups))
	for i, g := range groups {
		responses[i] = PartitionAllowedGroupResponse{
			GroupID: g.GroupID.String(),
			Title:   g.Title,
			LdapCN:  g.LdapCN,
		}
	}
	handlerutil.WriteJSONResponse(w, http.StatusOK, responses)
}

func (h *Handler) UpdatePartitionAllowedGroups(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "UpdatePartitionAllowedGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	partitionName := r.PathValue("partition_name")

	var req UpdatePartitionAllowedGroupsRequest
	if err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req); err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	groupIDs := make([]uuid.UUID, len(req.GroupIDs))
	for i, raw := range req.GroupIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
		groupIDs[i] = id
	}

	if err := h.store.SetPartitionAllowedGroups(traceCtx, partitionName, groupIDs); err != nil {
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
		SshUser:     s.SshUser.String,
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

func toCreateParams(req AddNodeRequest) CreateParams {
	params := CreateParams{
		AnsibleName:   req.AnsibleName,
		IpAddress:     pgtype.Text{String: req.IpAddress, Valid: req.IpAddress != ""},
		SshConfigHost: pgtype.Text{String: req.SshConfigHost, Valid: req.SshConfigHost != ""},
		PrivateIp:     pgtype.Text{String: req.PrivateIp, Valid: req.PrivateIp != ""},
		SshUser:       pgtype.Text{String: req.SshUser, Valid: req.SshUser != ""},
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
	return params
}
