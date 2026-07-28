package ansible

import (
	"bytes"
	"clustron-backend/internal"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clustron-backend/internal/ldap"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	AnsibleDir          = "internal/ansible/ansible"
	InventoryFile       = "hosts.yaml"
	MainPlaybook        = "playbooks/nodes.yaml"
	UpdateRolesPlaybook = "playbooks/update_roles.yaml"
	LogFilePath         = "ansible-deploy.log"

	headNodeRole    = "head_nodes"
	computeNodeRole = "compute_nodes"
	sssdTag         = "sssd"
	nfsExportsTag   = "nfs_exports"
)

type Service struct {
	db         *pgxpool.Pool
	queries    *Queries
	logger     *zap.Logger
	tracer     trace.Tracer
	ldapConfig ldap.Config
}

type ServiceInterface interface {
	SetupAllNodes(ctx context.Context) error
	AddNode(ctx context.Context, params CreateParams) (Server, error)
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
		return databaseutil.WrapDBError(err, logger, "server not found")
	}
	return nil
}

func (s *Service) AddNode(ctx context.Context, params CreateParams) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	params.Status = "provisioning"
	server, err := s.queries.Create(traceCtx, params)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create new server in db")
		span.RecordError(err)
		return Server{}, err
	}

	err = s.generateInventory(traceCtx)
	if err != nil {
		_, _ = s.queries.UpdateStatus(traceCtx, UpdateStatusParams{
			server.ID,
			"failed",
		})
		return server, fmt.Errorf("fail to generate inventory: %w", err)
	}

	bgCtx := context.WithoutCancel(ctx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, server, "")
	}()

	return server, nil
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

func (s *Service) runAnsibleInBackground(ctx context.Context, server Server, tags string) {
	logger := logutil.WithContext(ctx, s.logger)
	sssdOnly := tags == sssdTag
	if sssdOnly {
		logger.Info("[background] re-rendering sssd.conf via --tags sssd", zap.String("node", server.AnsibleName))
		if err := s.generateInventory(ctx); err != nil {
			logger.Error("fail to generate inventory for sssd re-render", zap.Error(err))
			return
		}
	} else {
		logger.Info("[background] start setup node", zap.String("node", server.AnsibleName))
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: InventoryFile,
		Limit:     server.AnsibleName,
		Tags:      tags,
	}

	playbookCmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(MainPlaybook),
		playbook.WithPlaybookOptions(ansiblePlaybookOptions),
	)

	tracker := &stageTrackingWriter{
		delegate: os.Stderr,
		onTaskLine: func(taskName string) {
			_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
				ID:              server.ID,
				ProvisionDetail: pgtype.Text{String: taskName, Valid: true},
			})
		},
	}
	stdoutWriter := io.Writer(tracker)
	stderrWriter := io.Writer(tracker)
	if sssdOnly {
		stdoutWriter = os.Stdout
		stderrWriter = os.Stderr
	}
	if !sssdOnly && server.AnsibleRole == computeNodeRole {
		if err := s.runUpdateRoles(ctx, tracker, nfsExportsTag); err != nil {
			logger.Error("fail to authorize compute node in NFS exports", zap.Error(err), zap.String("node", server.AnsibleName))
			errSummary := parseAnsibleError(tracker.AllOutput.String())
			_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
				ID:              server.ID,
				ProvisionDetail: pgtype.Text{String: errSummary, Valid: true},
			})
			_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
				ID:     server.ID,
				Status: "failed",
			})
			return
		}
	}
	tracker.AllOutput.Reset()
	tracker.lineBuffer.Reset()

	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(stdoutWriter),
		execute.WithWriteError(stderrWriter),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(AnsibleDir),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks",
		}),
	)

	err := exec.Execute(ctx)
	if err != nil {
		if sssdOnly {
			logger.Error("fail to re-render sssd.conf", zap.Error(err), zap.String("node", server.AnsibleName))
			return
		}
		logger.Error("fail to deploy node", zap.Error(err), zap.String("node", server.AnsibleName))
		errSummary := parseAnsibleError(tracker.AllOutput.String())
		_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
			ID:              server.ID,
			ProvisionDetail: pgtype.Text{String: errSummary, Valid: true},
		})
		_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
			ID:     server.ID,
			Status: "failed",
		})
		return
	}

	if sssdOnly {
		logger.Info("sssd.conf re-rendered", zap.String("node", server.AnsibleName))
		return
	}

	tracker.AllOutput.Reset()
	tracker.lineBuffer.Reset()
	if err = s.runUpdateRoles(ctx, tracker, ""); err != nil {
		logger.Error("fail to update cluster configuration after node change", zap.Error(err), zap.String("node", server.AnsibleName))
		errSummary := parseAnsibleError(tracker.AllOutput.String())
		_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
			ID:              server.ID,
			ProvisionDetail: pgtype.Text{String: errSummary, Valid: true},
		})
		_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
			ID:     server.ID,
			Status: "failed",
		})
		return
	}

	logger.Info("deploy successfully!", zap.String("node", server.AnsibleName))
	_ = s.queries.UpdateProvisionDetail(ctx, UpdateProvisionDetailParams{
		ID:              server.ID,
		ProvisionDetail: pgtype.Text{Valid: false},
	})
	_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
		ID:     server.ID,
		Status: "active",
	})
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
		execute.WithCmdRunDir(AnsibleDir),
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

	if err = s.generateInventory(traceCtx); err != nil {
		_, _ = s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "failed"})
		return Server{}, fmt.Errorf("fail to generate inventory: %w", err)
	}

	bgCtx := context.WithoutCancel(ctx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, server, "")
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

	if err = s.generateInventory(traceCtx); err != nil {
		_, _ = s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "failed"})
		return Server{}, fmt.Errorf("failed to generate inventory: %w", err)
	}

	bgCtx := context.WithoutCancel(ctx)
	bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

	go func() {
		defer cancel()
		s.runAnsibleInBackground(bgCtx, server, "")
	}()

	return updated, nil
}

func (s *Service) SetupAllNodes(ctx context.Context) error {
	traceCtx, span := s.tracer.Start(ctx, "SetupAllNodes")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if err := s.generateInventory(traceCtx); err != nil {
		span.RecordError(err)
		return err
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: InventoryFile,
	}

	playbookCmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(MainPlaybook),
		playbook.WithPlaybookOptions(ansiblePlaybookOptions),
	)

	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(os.Stdout),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(AnsibleDir),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks",
		}),
	)

	logger.Info("deploying all nodes...")
	if err := exec.Execute(traceCtx); err != nil {
		logger.Error("failed to deploy all nodes", zap.Error(err))
		span.RecordError(err)
		return err
	}

	logger.Info("all cluster deploy successfully")
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
			return databaseutil.WrapDBError(err, logger, "add allowed login group")
		}
	}
	if err = tx.Commit(traceCtx); err != nil {
		return databaseutil.WrapDBError(err, logger, "commit allowed login groups")
	}

	if server.AnsibleRole == computeNodeRole {
		bgCtx := context.WithoutCancel(ctx)
		bgCtx, cancel := context.WithTimeout(bgCtx, time.Hour)

		go func() {
			defer cancel()
			s.runAnsibleInBackground(bgCtx, server, sssdTag)
		}()
	}

	return nil
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

	inventory := AnsibleInventory{
		All: AnsibleGroup{
			Vars: map[string]interface{}{
				"slurm_version": "25.11.4-1",
				"ldap_base_dn":  s.ldapConfig.LDAPBaseDN,
				"ldap_bind_dn":  s.ldapConfig.LDAPBindDN,
				"ldap_bind_pwd": s.ldapConfig.LDAPBindPwd,
			},
			Children: make(map[string]AnsibleChild),
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
			inventory.All.Children[roleGroup] = AnsibleChild{
				Hosts: make(map[string]HostVars),
			}
		}

		hostVars := HostVars{
			AnsibleUser: srv.SshUser.String,
			CPUCores:    srv.CpuCores.Int32,
			MemoryMB:    srv.MemoryMb.Int32,
		}

		if srv.IpAddress.Valid {
			hostVars.AnsibleHost = srv.IpAddress.String
			if srv.SshKeyName.Valid && srv.SshKeyName.String != "" {
				hostVars.AnsibleSSHPrivate = fmt.Sprintf("~/.ssh/%s", srv.SshKeyName.String)
			}
		} else if srv.SshConfigHost.Valid {
			hostVars.AnsibleHost = srv.SshConfigHost.String
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

	filePath := filepath.Join(AnsibleDir, InventoryFile)
	err = os.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write hosts.yaml: %w", err)
	}

	return nil
}
