package ansible

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

// =====================================================================
// 常數與結構定義
// =====================================================================
const (
	AnsibleDir    = "./ansible"
	InventoryFile = "hosts.yaml"
	MainPlaybook  = "playbooks/nodes.yaml"
	LogFilePath   = "ansible-deploy.log" // Ansible 詳細日誌存放路徑
)

type Service struct {
	queries *Queries
	logger  *zap.Logger
	tracer  trace.Tracer
}

// 介面定義 (視你的架構需求保留)
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

// =====================================================================
// 1. 新增節點 (非同步架構：寫入 DB -> 更新 Inventory -> 背景跑 Ansible)
// =====================================================================
func (s *Service) AddNode(ctx context.Context, params CreateParams) (Server, error) {
	traceCtx, span := s.tracer.Start(ctx, "AddNode")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// 1. 強制設定初始狀態為 provisioning，寫入資料庫
	params.Status = "provisioning"
	server, err := s.queries.Create(traceCtx, params)
	if err != nil {
		err = databaseutil.WrapDBError(err, logger, "create new server in db")
		span.RecordError(err)
		return Server{}, err
	}
	logger.Info("節點已寫入資料庫，狀態為 provisioning", zap.String("node_name", server.AnsibleName))

	// 2. 重新產生包含新節點的 hosts.yaml
	err = s.generateInventory(traceCtx)
	if err != nil {
		// 如果產生失敗，立刻把 DB 狀態標記為 failed
		_, err := s.queries.UpdateStatus(traceCtx, UpdateStatusParams{
			server.ID,
			"failed",
		})
		return server, fmt.Errorf("產生 inventory 失敗: %w", err)
	}

	// 3. 開啟 Goroutine 在背景執行 Ansible
	// ⚠️ 關鍵：必須使用 context.Background()，避免 HTTP 回應後 ctx 被取消導致 Ansible 終止
	bgCtx := context.Background()
	
	// (進階) 傳遞 Trace ID 給背景任務，方便日誌追蹤
	bgCtx = trace.ContextWithSpanContext(bgCtx, span.SpanContext())

	go s.runAnsibleInBackground(bgCtx, server)

	// 4. 立刻回傳成功，不等待 Ansible 跑完
	return server, nil
}

// =====================================================================
// 2. 背景工作任務 (執行 Ansible 並更新 DB 狀態)
// =====================================================================
func (s *Service) runAnsibleInBackground(ctx context.Context, server Server) {
	logger := logutil.WithContext(ctx, s.logger)
	logger.Info("背景任務啟動：開始佈署節點", zap.String("node", server.AnsibleName))

	// 設定只對這台新機器跑 Ansible
	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions {
		Inventory: filepath.Join(AnsibleDir, InventoryFile),
		Limit:     server.AnsibleName,
	}

	playbookCmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(MainPlaybook),
		playbook.WithPlaybookOptions(ansiblePlaybookOptions),
	)

	// 開啟日誌檔案 (Append 模式)
	logFile, err := os.OpenFile(filepath.Join(AnsibleDir, LogFilePath), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logger.Error("無法開啟 Ansible log 檔案，改為僅輸出至終端機", zap.Error(err))
	} else {
		defer logFile.Close()
	}

	// 設定輸出導向：同時寫入螢幕 (os.Stdout) 與檔案 (logFile)
	var writer io.Writer = os.Stdout
	if logFile != nil {
		writer = io.MultiWriter(os.Stdout, logFile)
	}

	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithWrite(writer),
		execute.WithWriteError(writer),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
		execute.WithCmdRunDir(AnsibleDir),
		execute.WithEnvVars(map[string]string{
			"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks", // 開啟計時外掛
		}),
	)

	// 執行 Ansible
	err = exec.Execute(ctx)
	if err != nil {
		logger.Error("背景佈署失敗", zap.Error(err), zap.String("node", server.AnsibleName))
		_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
			server.ID,
			"failed",
		})
		return
	}

	// 佈署成功：更新狀態為 active
	logger.Info("背景佈署成功！", zap.String("node", server.AnsibleName))
			_, _ = s.queries.UpdateStatus(ctx, UpdateStatusParams{
			server.ID,
			"active",
		})
}

// =====================================================================
// 3. 手動觸發全叢集佈署 (通常用於初期建置)
// =====================================================================
func (s *Service) SetupAllNodes(ctx context.Context) error {
	traceCtx, span := s.tracer.Start(ctx, "SetupAllNodes")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if err := s.generateInventory(traceCtx); err != nil {
		span.RecordError(err)
		return err
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: filepath.Join(AnsibleDir, InventoryFile),
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

	logger.Info("開始執行全叢集 Ansible Playbook...")
	if err := exec.Execute(traceCtx); err != nil {
		logger.Error("全叢集 Ansible 執行失敗", zap.Error(err))
		span.RecordError(err)
		return err
	}

	logger.Info("全叢集設定完成！")
	return nil
}

// =====================================================================
// 4. 核心工具：從 DB 動態產生 hosts.yaml
// =====================================================================
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
	AnsibleHost       string `yaml:"ansible_host"`
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

	// 抓取 Head Node IP
	for _, srv := range servers {
		if srv.AnsibleRole == "head_nodes" {
			inventory.All.Vars["head_node_ip"] = srv.IpAddress
			break
		}
	}

	// 分群寫入
	for _, srv := range servers {
		roleGroup := srv.AnsibleRole

		if _, exists := inventory.All.Children[roleGroup]; !exists {
			inventory.All.Children[roleGroup] = AnsibleChild{
				Hosts: make(map[string]HostVars),
			}
		}

		hostVars := HostVars{
			AnsibleHost: srv.IpAddress,
			AnsibleUser: srv.SshUser,
			CPUCores:    srv.CpuCores.Int32,
			MemoryMB:    srv.MemoryMb.Int32,
		}

		if srv.SshKeyName != "" {
			hostVars.AnsibleSSHPrivate = fmt.Sprintf("~/.ssh/%s", srv.SshKeyName)
		}
		if srv.SlurmPartition.Valid {
			hostVars.SlurmPartition = srv.SlurmPartition.String
		}

		inventory.All.Children[roleGroup].Hosts[srv.AnsibleName] = hostVars
	}

	yamlData, err := yaml.Marshal(&inventory)
	if err != nil {
		return fmt.Errorf("轉換 YAML 失敗: %w", err)
	}

	filePath := filepath.Join(AnsibleDir, InventoryFile)
	err = os.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("寫入 hosts.yaml 失敗: %w", err)
	}

	return nil
}
