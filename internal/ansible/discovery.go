package ansible

import (
	"strconv"
	"strings"

	results "github.com/apenella/go-ansible/v2/pkg/execute/result/json"
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
