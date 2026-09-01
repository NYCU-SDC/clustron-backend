package ansible

import (
	"bytes"
	"clustron-backend/internal"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"clustron-backend/internal/ldap"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

const (
	ExecuteFolder       = "internal/ansible/ansible"
	InventoryFile       = "hosts.yaml"
	MainPlaybook        = "playbooks/nodes.yaml"
	UpdateRolesPlaybook = "playbooks/update_roles.yaml"
	LogFilePath         = "ansible-deploy.log"

	headNodeRole            = "head_nodes"
	computeNodeRole         = "compute_nodes"
	sssdTag                 = "sssd"
	computePrerequisiteTags = "nfs_exports,slurm_config"
)

type Service struct {
	db         *pgxpool.Pool
	queries    *Queries
	logger     *zap.Logger
	tracer     trace.Tracer
	ldapConfig ldap.Config
	ansibleMu  sync.Mutex
}

type ServiceInterface interface {
	SetupAllNodes(ctx context.Context) error
	AddNode(ctx context.Context, params CreateParams) (Server, error)
	AddNodes(ctx context.Context, params []CreateParams) ([]Server, error)
}

func NewService(logger *zap.Logger, db *pgxpool.Pool, ldapConfig ldap.Config) *Service {
	return &Service{
		db:         db,
		queries:    New(db),
		logger:     logger,
		tracer:     otel.Tracer("ansible/service"),
		ldapConfig: ldapConfig,
	}
}

func (s *Service) ListAll(ctx context.Context) ([]Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListAll")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	servers, err := s.queries.ListAll(traceCtx)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list all servers")
	}
	return servers, nil
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "GetByID")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	server, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "get server by id")
	}
	return server, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "Delete")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	rows, err := s.queries.Delete(traceCtx, id)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "delete server")
	}
	if rows == 0 {
		return handlerutil.NewNotFoundError("servers", "id", id.String(), "")
	}
	return nil
}

func (s *Service) AddNode(ctx context.Context, params CreateParams) (Server, error) {
	servers, err := s.AddNodes(ctx, []CreateParams{params})
	if err != nil {
		return Server{}, err
	}
	return servers[0], nil
}

func (s *Service) AddNodes(ctx context.Context, params []CreateParams) ([]Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddNodes")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)
	if len(params) == 0 {
		return []Server{}, nil
	}

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "begin tx for adding servers")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	qtx := s.queries.WithTx(tx)
	servers := make([]Server, len(params))
	for i := range params {
		params[i].Status = "provisioning"
		server, err := qtx.Create(traceCtx, params[i])
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == databaseutil.PGErrUniqueViolation {
				field, value := duplicateServerField(pgErr.ConstraintName, params[i])
				logger.Warn("Server already exists", zap.String("field", field), zap.String("value", value))
				err = fmt.Errorf("%w: %s %q", internal.ErrServerAlreadyExists, field, value)
			} else {
				err = databaseutil.WrapDBError(err, logger, fmt.Sprintf("create server %q in db", params[i].AnsibleName))
			}
			span.RecordError(err)
			return nil, err
		}
		servers[i] = server
	}

	if err = tx.Commit(traceCtx); err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "commit added servers")
	}

	bgCtx := context.WithoutCancel(traceCtx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)
	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, servers, "")
	}()

	return servers, nil
}

func duplicateServerField(constraint string, params CreateParams) (string, string) {
	switch constraint {
	case "servers_ip_address_key":
		return "ip_address", params.IpAddress.String
	case "servers_ssh_config_host_key":
		return "ssh_config_host", params.SshConfigHost.String
	case "servers_private_ip_key":
		return "private_ip", params.PrivateIp.String
	default:
		return "ansible_name", params.AnsibleName
	}
}

type stageTrackingWriter struct {
	lineBuffer strings.Builder
	AllOutput  bytes.Buffer
	delegate   io.Writer
	onTaskLine func(taskName string)
}

func (w *stageTrackingWriter) Write(p []byte) (n int, err error) {
	n, err = w.delegate.Write(p)
	if err != nil {
		return
	}
	w.AllOutput.Write(p[:n])
	for _, b := range p[:n] {
		if b == '\n' {
			line := w.lineBuffer.String()
			w.lineBuffer.Reset()
			if strings.HasPrefix(line, "TASK [") {
				w.onTaskLine(extractTaskName(line))
			}
		} else {
			w.lineBuffer.WriteByte(b)
		}
	}
	return
}

func extractTaskName(line string) string {
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start == -1 || end == -1 || start >= end {
		return line
	}
	return line[start+1 : end]
}

const maxAnsibleErrorOutputLines = 20

func parseAnsibleError(output string) string {
	lines := strings.Split(output, "\n")

	var currentTask, failedTask string
	var errorLines, recapLines, outputLines []string
	inRecap := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			outputLines = append(outputLines, trimmedLine)
		}
		if strings.HasPrefix(line, "TASK [") {
			currentTask = extractTaskName(line)
		}
		if strings.HasPrefix(line, "PLAY RECAP") {
			inRecap = true
			continue
		}
		if strings.HasPrefix(line, "TASKS RECAP") {
			inRecap = false
			continue
		}
		if inRecap && strings.TrimSpace(line) != "" {
			recapLines = append(recapLines, line)
		}
		if strings.Contains(line, "fatal:") || strings.Contains(line, "FAILED!") || strings.Contains(line, "[ERROR]:") {
			if failedTask == "" {
				failedTask = currentTask
			}
			errorLines = append(errorLines, trimmedLine)
		}
	}

	var sb strings.Builder
	if failedTask != "" {
		sb.WriteString("Stage: ")
		sb.WriteString(failedTask)
		sb.WriteString("\n\n")
	}
	if len(errorLines) > 0 {
		sb.WriteString("Error:\n")
		for i, l := range errorLines {
			if i >= 5 {
				break
			}
			sb.WriteString("  ")
			sb.WriteString(l)
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}
	if len(recapLines) > 0 {
		sb.WriteString("PLAY RECAP:\n")
		for _, l := range recapLines {
			sb.WriteString("  ")
			sb.WriteString(l)
			sb.WriteByte('\n')
		}
	}
	if len(errorLines) == 0 && len(outputLines) > 0 {
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), "\n\n") {
			sb.WriteByte('\n')
		}
		sb.WriteString("Output tail:\n")
		start := max(0, len(outputLines)-maxAnsibleErrorOutputLines)
		for _, line := range outputLines[start:] {
			sb.WriteString("  ")
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func (s *Service) runAnsibleInBackground(ctx context.Context, servers []Server, tags string) {
	s.ansibleMu.Lock()
	defer s.ansibleMu.Unlock()
	if len(servers) == 0 {
		return
	}

	logger := logutil.WithContext(ctx, s.logger)
	serverNames := make([]string, len(servers))
	serverIDs := make([]uuid.UUID, len(servers))
	hasComputeNode := false
	hasHeadNode := false
	for i, server := range servers {
		serverNames[i] = server.AnsibleName
		serverIDs[i] = server.ID
		hasComputeNode = hasComputeNode || server.AnsibleRole == computeNodeRole
		hasHeadNode = hasHeadNode || server.AnsibleRole == headNodeRole
	}

	if err := s.generateInventory(ctx); err != nil {
		detail := fmt.Sprintf("failed to generate inventory: %v", err)
		logger.Error("fail to generate inventory", zap.Error(err), zap.Strings("nodes", serverNames))
		if tags != sssdTag {
			s.failServers(ctx, serverIDs, detail)
		}
		return
	}
	if tags == sssdTag {
		logger.Info("[background] re-rendering sssd.conf", zap.Strings("nodes", serverNames))
		if err := s.executeNodesPlaybook(ctx, serverNames, tags, os.Stdout, os.Stderr); err != nil {
			logger.Error("fail to re-render sssd.conf", zap.Error(err), zap.Strings("nodes", serverNames))
			return
		}
		logger.Info("sssd.conf re-rendered", zap.Strings("nodes", serverNames))
		return
	}

	tracker := &stageTrackingWriter{
		delegate: os.Stderr,
		onTaskLine: func(taskName string) {
			s.updateServersProvisionDetail(ctx, serverIDs, taskName)
		},
	}

	// A new head node configures its shared services before the compute-node play runs.
	// Existing head nodes need their NFS exports and Slurm config refreshed before
	// new compute nodes mount the shares and start slurmd.
	if hasComputeNode && !hasHeadNode {
		if err := s.runUpdateRoles(ctx, tracker, computePrerequisiteTags); err != nil {
			detail := parseAnsibleError(tracker.AllOutput.String())
			logger.Error("fail to prepare cluster configuration for compute nodes", zap.Error(err))
			s.failServers(ctx, serverIDs, detail)
			return
		}
		tracker.AllOutput.Reset()
		tracker.lineBuffer.Reset()
	}

	logger.Info("[background] start setup nodes", zap.Strings("nodes", serverNames))
	deployErr := s.executeNodesPlaybook(ctx, serverNames, tags, tracker, tracker)
	deployOutput := tracker.AllOutput.String()
	successful := make(map[uuid.UUID]bool, len(servers))
	failureDetails := make(map[uuid.UUID]string, len(servers))
	if deployErr == nil {
		for _, id := range serverIDs {
			successful[id] = true
		}
	} else {
		recap := parseAnsibleRecap(deployOutput)
		for _, server := range servers {
			successful[server.ID] = recap[server.AnsibleName]
			if !successful[server.ID] {
				failureDetails[server.ID] = parseAnsibleError(deployOutput)
			}
		}
		logger.Error("some servers failed to deploy", zap.Error(deployErr), zap.Strings("nodes", serverNames))
	}

	hasSuccessfulServer := false
	for _, ok := range successful {
		hasSuccessfulServer = hasSuccessfulServer || ok
	}
	if hasSuccessfulServer {
		tracker.AllOutput.Reset()
		tracker.lineBuffer.Reset()
		if err := s.runUpdateRoles(ctx, tracker, ""); err != nil {
			detail := parseAnsibleError(tracker.AllOutput.String())
			logger.Error("fail to update cluster configuration after adding server batch", zap.Error(err))
			for id, ok := range successful {
				if ok {
					successful[id] = false
					failureDetails[id] = detail
				}
			}
		}
	}

	for _, server := range servers {
		if successful[server.ID] {
			s.updateServerProvisionResult(ctx, server.ID, "active", pgtype.Text{Valid: false})
			continue
		}
		detail := failureDetails[server.ID]
		s.updateServerProvisionResult(ctx, server.ID, "failed", pgtype.Text{String: detail, Valid: detail != ""})
	}
}

func (s *Service) executeNodesPlaybook(
	ctx context.Context,
	serverNames []string,
	tags string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	options := &playbook.AnsiblePlaybookOptions{
		Inventory: InventoryFile,
		Tags:      tags,
	}
	if len(serverNames) > 0 {
		options.Limit = strings.Join(serverNames, ",")
	}
	playbookCmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(MainPlaybook),
		playbook.WithPlaybookOptions(options),
	)
	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(stdout),
		execute.WithWriteError(stderr),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(ExecuteFolder),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks",
		}),
	)
	return exec.Execute(ctx)
}

func parseAnsibleRecap(output string) map[string]bool {
	result := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != ":" {
			continue
		}
		unreachable, failed, foundUnreachable, foundFailed := 0, 0, false, false
		for _, field := range fields[2:] {
			key, raw, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			value, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			switch key {
			case "unreachable":
				unreachable, foundUnreachable = value, true
			case "failed":
				failed, foundFailed = value, true
			}
		}
		if foundUnreachable && foundFailed {
			result[fields[0]] = unreachable == 0 && failed == 0
		}
	}
	return result
}

func (s *Service) failServers(ctx context.Context, ids []uuid.UUID, detail string) {
	for _, id := range ids {
		s.updateServerProvisionResult(ctx, id, "failed", pgtype.Text{String: detail, Valid: detail != ""})
	}
}

func (s *Service) updateServersProvisionDetail(ctx context.Context, ids []uuid.UUID, detail string) {
	for _, id := range ids {
		_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
			ID:              id,
			ProvisionDetail: pgtype.Text{String: detail, Valid: detail != ""},
		})
	}
}

func (s *Service) updateServerProvisionResult(ctx context.Context, id uuid.UUID, status string, detail pgtype.Text) {
	_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{ID: id, ProvisionDetail: detail})
	_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{ID: id, Status: status})
}

func (s *Service) runUpdateRoles(ctx context.Context, output io.Writer, tags string) error {
	logger := logutil.WithContext(ctx, s.logger)
	logger.Info("[background] updating cluster configuration")

	playbookCmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(UpdateRolesPlaybook),
		playbook.WithPlaybookOptions(&playbook.AnsiblePlaybookOptions{
			Inventory: InventoryFile,
			Tags:      tags,
		}),
	)

	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(output),
		execute.WithWriteError(output),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(ExecuteFolder),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks",
		}),
	)

	if err := exec.Execute(ctx); err != nil {
		return err
	}
	logger.Info("cluster configuration updated")
	return nil
}

func (s *Service) UpdateRole(ctx context.Context, id uuid.UUID, role string) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "begin tx for updating server role")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	qtx := s.queries.WithTx(tx)
	if role == headNodeRole {
		hasAllowedLoginGroups, err := qtx.ExistServerAllowedLoginGroup(traceCtx, id)
		if err != nil {
			return Server{}, databaseutil.WrapDBError(err, logger, "check server allowed login groups")
		}
		if err = validateAllowedLoginGroupRoleChange(role, hasAllowedLoginGroups); err != nil {
			return Server{}, err
		}
	}

	server, err := qtx.UpdateRole(traceCtx, UpdateRoleParams{ID: id, AnsibleRole: role})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "update server role")
	}

	updated, err := qtx.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "provisioning"})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "set server status to provisioning")
	}
	if err = qtx.UpdateProvisionDetail(traceCtx, UpdateProvisionDetailParams{
		ID:              id,
		ProvisionDetail: pgtype.Text{Valid: false},
	}); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "clear provision detail")
	}
	updated.ProvisionDetail = pgtype.Text{Valid: false}
	if err = tx.Commit(traceCtx); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "commit server role update")
	}

	bgCtx := context.WithoutCancel(traceCtx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, []Server{server}, "")
	}()

	return updated, nil
}

func (s *Service) ResetNode(ctx context.Context, id uuid.UUID) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "ResetNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "begin tx for resetting server")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	qtx := s.queries.WithTx(tx)
	server, err := qtx.GetByID(traceCtx, id)
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "get server by id")
	}

	updated, err := qtx.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "provisioning"})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "reset server status")
	}
	if err = qtx.UpdateProvisionDetail(traceCtx, UpdateProvisionDetailParams{
		ID:              id,
		ProvisionDetail: pgtype.Text{Valid: false},
	}); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "clear provision detail")
	}
	updated.ProvisionDetail = pgtype.Text{Valid: false}
	if err = tx.Commit(traceCtx); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "commit server reset")
	}

	bgCtx := context.WithoutCancel(traceCtx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, []Server{server}, "")
	}()

	return updated, nil
}

func (s *Service) SetupAllNodes(ctx context.Context) error {
	traceCtx, span := s.tracer.Start(ctx, "SetupAllNodes")
	defer span.End()

	servers, err := s.ListAll(traceCtx)
	if err != nil {
		span.RecordError(err)
		return err
	}

	bgCtx := context.WithoutCancel(traceCtx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, servers, "")
	}()

	return nil
}

// ListAllowedLoginGroups returns the Clustron groups whose members are allowed to log in
// to a server (rendered into that server's SSSD simple_allow_groups).
func (s *Service) ListAllowedLoginGroups(ctx context.Context, serverID uuid.UUID) ([]AllowedLoginGroupDetail, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListAllowedLoginGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if _, err := s.queries.GetByID(traceCtx, serverID); err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "get server by id")
	}

	rows, err := s.queries.ListServerAllowedLoginGroups(traceCtx, serverID)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list allowed login groups")
	}

	result := make([]AllowedLoginGroupDetail, 0, len(rows))
	for _, row := range rows {
		result = append(result, AllowedLoginGroupDetail{
			GroupID: row.GroupID,
			Title:   row.Title,
			LdapCN:  row.LdapCn.String,
		})
	}
	return result, nil
}

// SetAllowedLoginGroups replaces a server's allowed-login-group list with the given groups,
// then re-renders that server's sssd.conf in the background. Each group must already have a
// BASE LDAP group (i.e. a usable ldap_cn), otherwise the update is rejected.
func (s *Service) SetAllowedLoginGroups(ctx context.Context, serverID uuid.UUID, groupIDs []uuid.UUID) error {
	traceCtx, span := s.tracer.Start(ctx, "SetAllowedLoginGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	server, err := s.queries.GetByID(traceCtx, serverID)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "get server by id")
	}
	if err = validateAllowedLoginGroupTarget(server.AnsibleRole, groupIDs); err != nil {
		return err
	}

	for _, id := range groupIDs {
		exist, err := s.queries.ExistBaseLdapGroup(traceCtx, id)
		if err != nil {
			return databaseutil.WrapDBError(err, logger, "check base ldap group exists")
		}
		if !exist {
			return databaseutil.WrapDBErrorWithKeyValue(pgx.ErrNoRows, "ldap_groups", "group_id", id.String(), logger, "find base ldap group for allowed login group")
		}
	}

	tx, err := s.db.Begin(traceCtx)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "begin tx for set allowed login groups")
	}
	defer func() { _ = tx.Rollback(traceCtx) }()

	qtx := s.queries.WithTx(tx)
	if err = qtx.ClearServerAllowedLoginGroups(traceCtx, serverID); err != nil {
		return databaseutil.WrapDBError(err, logger, "clear allowed login groups")
	}
	for _, id := range groupIDs {
		if err = qtx.AddServerAllowedLoginGroup(traceCtx, AddServerAllowedLoginGroupParams{
			ServerID: serverID,
			GroupID:  id,
		}); err != nil {
			return mapAllowedLoginGroupError(err, serverID, id, logger)
		}
	}
	if err = tx.Commit(traceCtx); err != nil {
		return databaseutil.WrapDBError(err, logger, "commit allowed login groups")
	}

	if server.AnsibleRole == computeNodeRole {
		bgCtx := context.WithoutCancel(traceCtx)
		bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

		go func() {
			defer cancel()
			s.runAnsibleInBackground(bgCtx, []Server{server}, sssdTag)
		}()
	}

	return nil
}

func mapAllowedLoginGroupError(err error, serverID, groupID uuid.UUID, logger *zap.Logger) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == databaseutil.PGErrForeignKeyViolation {
		if pgErr.ConstraintName == "allowed_login_groups_server_id_fkey" {
			return handlerutil.NewNotFoundError("servers", "id", serverID.String(), "")
		}
		return handlerutil.NewNotFoundError("groups", "id", groupID.String(), "")
	}
	return databaseutil.WrapDBError(err, logger, "add allowed login group")
}

func validateAllowedLoginGroupTarget(role string, groupIDs []uuid.UUID) error {
	if role != computeNodeRole && len(groupIDs) > 0 {
		return internal.ErrAllowedLoginGroupsUnsupported
	}
	return nil
}

func validateAllowedLoginGroupRoleChange(role string, hasAllowedLoginGroups bool) error {
	if role == headNodeRole && hasAllowedLoginGroups {
		return internal.ErrAllowedLoginGroupsRoleConflict
	}
	return nil
}

func (s *Service) generateInventory(ctx context.Context) error {
	servers, err := s.queries.ListAll(ctx)
	if err != nil {
		return databaseutil.WrapDBError(err, s.logger, "list all servers from db")
	}

	ldapServerHost, ldapServerPort := s.ldapConfig.LDAPExternalHost, s.ldapConfig.LDAPExternalPort
	if ldapServerHost == "" {
		ldapServerHost = s.ldapConfig.LDAPHost
	}

	if ldapServerPort == "" {
		ldapServerPort = s.ldapConfig.LDAPPort
	}

	inventory := InventoryFiles{
		All: ServerGroup{
			Vars: map[string]interface{}{
				"slurm_version":      "25.11.4-1",
				"ldap_external_host": ldapServerHost,
				"ldap_external_port": ldapServerPort,
				"ldap_base_dn":       s.ldapConfig.LDAPBaseDN,
				"ldap_bind_dn":       s.ldapConfig.LDAPBindDN,
				"ldap_bind_pwd":      s.ldapConfig.LDAPBindPwd,
			},
			Children: make(map[string]ChildNode),
		},
	}

	for _, srv := range servers {
		if srv.AnsibleRole == "head_nodes" {
			if srv.PrivateIp.Valid {
				inventory.All.Vars["head_node_ip"] = srv.PrivateIp.String
			} else if srv.IpAddress.Valid {
				inventory.All.Vars["head_node_ip"] = srv.IpAddress.String
			} else if srv.SshConfigHost.Valid {
				inventory.All.Vars["head_node_ip"] = srv.SshConfigHost.String
			}
			break
		}
	}

	for _, srv := range servers {
		roleGroup := srv.AnsibleRole

		if _, exists := inventory.All.Children[roleGroup]; !exists {
			inventory.All.Children[roleGroup] = ChildNode{
				Hosts: make(map[string]HostVars),
			}
		}

		hostVars := HostVars{
			UserName: srv.SshUser.String,
			CPUCores: srv.CpuCores.Int32,
			MemoryMB: srv.MemoryMb.Int32,
		}

		if srv.IpAddress.Valid {
			hostVars.HostName = srv.IpAddress.String
			if srv.SshKeyName.Valid && srv.SshKeyName.String != "" {
				hostVars.SSHKeyPath = fmt.Sprintf("~/.ssh/%s", srv.SshKeyName.String)
			}
		} else if srv.SshConfigHost.Valid {
			hostVars.HostName = srv.SshConfigHost.String
		}

		if srv.PrivateIp.Valid {
			hostVars.PrivateIP = srv.PrivateIp.String
		}

		if srv.SlurmPartition.Valid {
			hostVars.SlurmPartition = srv.SlurmPartition.String
		}

		allowedCNs, err := s.queries.ListAllowedLoginGroupCNsByServerID(ctx, srv.ID)
		if err != nil {
			return databaseutil.WrapDBError(err, s.logger, "list allowed login group cns")
		}
		cns := make([]string, 0, len(allowedCNs))
		for _, cn := range allowedCNs {
			if cn.Valid && cn.String != "" {
				cns = append(cns, cn.String)
			}
		}
		hostVars.LDAPSimpleAllowGroups = strings.Join(cns, ", ")

		inventory.All.Children[roleGroup].Hosts[srv.AnsibleName] = hostVars
	}

	yamlData, err := yaml.Marshal(&inventory)
	if err != nil {
		return fmt.Errorf("YAML marshal failed: %w", err)
	}

	filePath := filepath.Join(ExecuteFolder, InventoryFile)
	tempFile, err := os.CreateTemp(ExecuteFolder, ".hosts-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temporary inventory: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err = tempFile.Write(yamlData); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to write temporary inventory: %w", err)
	}
	if err = tempFile.Chmod(0644); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to set inventory permissions: %w", err)
	}
	if err = tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary inventory: %w", err)
	}
	if err = os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to replace hosts.yaml: %w", err)
	}

	return nil
}
