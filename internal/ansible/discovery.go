package ansible

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	databaseutil "github.com/NYCU-SDC/summer/pkg/database"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/apenella/go-ansible/v2/pkg/execute"
	results "github.com/apenella/go-ansible/v2/pkg/execute/result/json"
	"github.com/apenella/go-ansible/v2/pkg/execute/stdoutcallback"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	DiscoverGroupsPlaybook = "playbooks/discover_groups.yaml"
	discoverGroupsTaskName = "Read local groups"
)

// LocalGroup is a group found in a server's local /etc/group.
type LocalGroup struct {
	ServerName string
	Name       string
	GIDNumber  int64
}

// parseGetentGroup parses `getent group` output. Malformed lines and repeated
// names are skipped; the first occurrence of a name wins, like NSS lookups.
func parseGetentGroup(serverName, output string) []LocalGroup {
	groups := []LocalGroup{}
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		gid, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		if _, ok := seen[fields[0]]; ok {
			continue
		}
		seen[fields[0]] = struct{}{}
		groups = append(groups, LocalGroup{ServerName: serverName, Name: fields[0], GIDNumber: gid})
	}
	return groups
}

// parseDiscoveredLocalGroups returns local groups keyed by host. Hosts whose
// discovery task failed or was unreachable are absent, so callers keep their
// previous rows instead of wiping them.
func parseDiscoveredLocalGroups(res *results.AnsiblePlaybookJSONResults) map[string][]LocalGroup {
	byHost := make(map[string][]LocalGroup)
	for _, play := range res.Plays {
		for _, task := range play.Tasks {
			if task.Task == nil || task.Task.Name != discoverGroupsTaskName {
				continue
			}
			for host, item := range task.Hosts {
				if item == nil || item.Failed || item.Unreachable {
					continue
				}
				stdout, ok := item.Stdout.(string)
				if !ok {
					continue
				}
				byHost[host] = parseGetentGroup(host, stdout)
			}
		}
	}
	return byHost
}

// discoveryTargets returns the compute nodes that were provisioned successfully.
func discoveryTargets(servers []Server, successful map[uuid.UUID]bool) []Server {
	targets := make([]Server, 0, len(servers))
	for _, srv := range servers {
		if successful[srv.ID] && srv.AnsibleRole == computeNodeRole {
			targets = append(targets, srv)
		}
	}
	return targets
}

// ListLocalGroups returns local groups discovered on active compute nodes.
func (s *Service) ListLocalGroups(ctx context.Context) ([]LocalGroup, error) {
	traceCtx, span := s.tracer.Start(ctx, "ListLocalGroups")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	rows, err := s.queries.ListLocalGroups(traceCtx)
	if err != nil {
		return nil, databaseutil.WrapDBError(err, logger, "list local groups")
	}
	groups := make([]LocalGroup, len(rows))
	for i, row := range rows {
		groups[i] = LocalGroup{ServerName: row.AnsibleName, Name: row.Name, GIDNumber: row.GidNumber}
	}
	return groups, nil
}

// DiscoverLocalGroupsInBackground refreshes local groups of every active compute node.
func (s *Service) DiscoverLocalGroupsInBackground(ctx context.Context) {
	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Hour)

	go func() {
		defer cancel()
		logger := logutil.WithContext(bgCtx, s.logger)

		s.ansibleMu.Lock()
		defer s.ansibleMu.Unlock()

		servers, err := s.queries.ListByRoles(bgCtx, computeNodeRole)
		if err != nil {
			logger.Error("list compute nodes for local group discovery", zap.Error(err))
			return
		}
		active := make([]Server, 0, len(servers))
		for _, srv := range servers {
			if srv.Status == "active" {
				active = append(active, srv)
			}
		}
		if len(active) == 0 {
			return
		}
		if err := s.generateInventory(bgCtx); err != nil {
			logger.Error("generate inventory for local group discovery", zap.Error(err))
			return
		}
		if err := s.discoverLocalGroups(bgCtx, active); err != nil {
			logger.Error("discover local groups", zap.Error(err))
		}
	}()
}

// discoverLocalGroups runs the discovery playbook and replaces each responding
// server's rows. Callers must hold ansibleMu and have generated the inventory.
func (s *Service) discoverLocalGroups(ctx context.Context, servers []Server) error {
	if len(servers) == 0 {
		return nil
	}
	logger := logutil.WithContext(ctx, s.logger)

	names := make([]string, len(servers))
	for i, srv := range servers {
		names[i] = srv.AnsibleName
	}

	output := new(bytes.Buffer)
	exec := stdoutcallback.NewJSONStdoutCallbackExecute(
		execute.NewDefaultExecute(
			execute.WithCmd(playbook.NewAnsiblePlaybookCmd(
				playbook.WithPlaybooks(DiscoverGroupsPlaybook),
				playbook.WithPlaybookOptions(&playbook.AnsiblePlaybookOptions{
					Inventory: InventoryFile,
					Limit:     strings.Join(names, ","),
				}),
			)),
			execute.WithWrite(output),
			execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
			execute.WithCmdRunDir(ExecuteFolder),
		),
	)
	// A failure on some hosts still produces JSON for the others.
	execErr := exec.Execute(ctx)

	res, err := results.ParseJSONResultsStream(output)
	if err != nil {
		return errors.Join(execErr, fmt.Errorf("parse local group discovery output: %w", err))
	}

	byHost := parseDiscoveredLocalGroups(res)
	for _, srv := range servers {
		groups, ok := byHost[srv.AnsibleName]
		if !ok {
			logger.Warn("local group discovery failed, keeping previous rows", zap.String("server", srv.AnsibleName))
			continue
		}
		if err := s.replaceLocalGroups(ctx, srv.ID, groups); err != nil {
			return errors.Join(execErr, err)
		}
	}
	return execErr
}

func (s *Service) replaceLocalGroups(ctx context.Context, serverID uuid.UUID, groups []LocalGroup) error {
	logger := logutil.WithContext(ctx, s.logger)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return databaseutil.WrapDBError(err, logger, "begin tx for local groups")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := s.queries.WithTx(tx)
	if err = qtx.DeleteLocalGroupsByServerID(ctx, serverID); err != nil {
		return databaseutil.WrapDBError(err, logger, "delete local groups")
	}
	for _, group := range groups {
		if err = qtx.InsertLocalGroup(ctx, InsertLocalGroupParams{
			ServerID:  serverID,
			Name:      group.Name,
			GidNumber: group.GIDNumber,
		}); err != nil {
			return databaseutil.WrapDBError(err, logger, "insert local group")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return databaseutil.WrapDBError(err, logger, "commit local groups")
	}
	return nil
}
