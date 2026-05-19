package ansible

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

const (
	AnsibleDir    = "internal/ansible/ansible"
	InventoryFile = "hosts.yaml"
	MainPlaybook  = "playbooks/nodes.yaml"
	LogFilePath   = "ansible-deploy.log"
)

type Service struct {
	queries *Queries
	logger  *zap.Logger
	tracer  trace.Tracer
}

type ServiceInterface interface {
	SetupAllNodes(ctx context.Context) error
	AddNode(ctx context.Context, params CreateParams) (Server, error)
}

func NewService(logger *zap.Logger, db DBTX) *Service {
	return &Service{
		queries: New(db),
		logger:  logger,
		tracer:  otel.Tracer("ansible/service"),
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

	bgCtx := context.Background()
	bgCtx = trace.ContextWithSpanContext(bgCtx, span.SpanContext())

	go s.runAnsibleInBackground(bgCtx, server)

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

func parseAnsibleError(output string) string {
	lines := strings.Split(output, "\n")

	var currentTask, failedTask string
	var errorLines, recapLines []string
	inRecap := false

	for _, line := range lines {
		if strings.HasPrefix(line, "TASK [") {
			currentTask = extractTaskName(line)
		}
		if strings.HasPrefix(line, "PLAY RECAP") {
			inRecap = true
			continue
		}
		if inRecap && strings.TrimSpace(line) != "" {
			recapLines = append(recapLines, line)
		}
		if strings.Contains(line, "fatal:") || strings.Contains(line, "FAILED!") {
			if failedTask == "" {
				failedTask = currentTask
			}
			errorLines = append(errorLines, strings.TrimSpace(line))
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
	return sb.String()
}

func (s *Service) runAnsibleInBackground(ctx context.Context, server Server) {
	logger := logutil.WithContext(ctx, s.logger)
	logger.Info("[background] start setup node", zap.String("node", server.AnsibleName))

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: InventoryFile,
		Limit:     server.AnsibleName,
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

	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(tracker),
		execute.WithWriteError(tracker),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(AnsibleDir),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks",
		}),
	)

	err := exec.Execute(ctx)
	if err != nil {
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

func (s *Service) UpdateRole(ctx context.Context, id uuid.UUID, role string) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "UpdateRole")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	server, err := s.queries.UpdateRole(traceCtx, UpdateRoleParams{ID: id, AnsibleRole: role})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "update server role")
	}

	updated, err := s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "provisioning"})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "set server status to provisioning")
	}
	if err = s.queries.UpdateProvisionDetail(traceCtx, UpdateProvisionDetailParams{
		ID:              id,
		ProvisionDetail: pgtype.Text{Valid: false},
	}); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "clear provision detail")
	}
	updated.ProvisionDetail = pgtype.Text{Valid: false}

	if err = s.generateInventory(traceCtx); err != nil {
		_, _ = s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "failed"})
		return Server{}, fmt.Errorf("fail to generate inventory: %w", err)
	}

	bgCtx := trace.ContextWithSpanContext(context.Background(), span.SpanContext())
	go s.runAnsibleInBackground(bgCtx, server)

	return updated, nil
}

func (s *Service) ResetNode(ctx context.Context, id uuid.UUID) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "ResetNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	server, err := s.queries.GetByID(traceCtx, id)
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "get server by id")
	}

	updated, err := s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "provisioning"})
	if err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "reset server status")
	}
	if err = s.queries.UpdateProvisionDetail(traceCtx, UpdateProvisionDetailParams{
		ID:              id,
		ProvisionDetail: pgtype.Text{Valid: false},
	}); err != nil {
		return Server{}, databaseutil.WrapDBError(err, logger, "clear provision detail")
	}
	updated.ProvisionDetail = pgtype.Text{Valid: false}

	if err = s.generateInventory(traceCtx); err != nil {
		_, _ = s.queries.UpdateStatus(traceCtx, UpdateStatusParams{ID: id, Status: "failed"})
		return Server{}, fmt.Errorf("產生 inventory 失敗: %w", err)
	}

	bgCtx := trace.ContextWithSpanContext(context.Background(), span.SpanContext())
	go s.runAnsibleInBackground(bgCtx, server)

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
		logger.Error("全叢集 Ansible 執行失敗", zap.Error(err))
		span.RecordError(err)
		return err
	}

	logger.Info("all cluster deploy successfully")
	return nil
}

type AnsibleInventory struct {
	All AnsibleGroup `yaml:"all"`
}
type AnsibleGroup struct {
	Vars     map[string]interface{}  `yaml:"vars,omitempty"`
	Children map[string]AnsibleChild `yaml:"children,omitempty"`
}
type AnsibleChild struct {
	Hosts map[string]HostVars `yaml:"hosts,omitempty"`
}
type HostVars struct {
	AnsibleHost       string `yaml:"ansible_host,omitempty"`
	AnsibleUser       string `yaml:"ansible_user"`
	AnsibleSSHPrivate string `yaml:"ansible_ssh_private_key_file,omitempty"`
	CPUCores          int32  `yaml:"cpu_cores,omitempty"`
	MemoryMB          int32  `yaml:"memory_mb,omitempty"`
	SlurmPartition    string `yaml:"slurm_partition,omitempty"`
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
			},
			Children: make(map[string]AnsibleChild),
		},
	}

	for _, srv := range servers {
		if srv.AnsibleRole == "head_nodes" {
			if srv.IpAddress.Valid {
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
			AnsibleUser: srv.SshUser,
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

		if srv.SlurmPartition.Valid {
			hostVars.SlurmPartition = srv.SlurmPartition.String
		}

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
