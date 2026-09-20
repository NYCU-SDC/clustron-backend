package systemgroup

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"clustron-backend/internal"
	"clustron-backend/internal/ansible"
)

// MaxSystemGID is the highest gid treated as a system group; higher gids are user private groups.
const MaxSystemGID = 999

// DefaultDenylist is always applied; system_group_denylist only adds to it.
var DefaultDenylist = []string{
	"root", "sudo", "admin", "wheel", "adm", "shadow", "disk", "kmem", "sys", "staff",
	"lxd", "libvirt", "systemd-journal", "tty",
}

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// GIDServers lists the compute nodes on which a local group has a given gid.
type GIDServers struct {
	GIDNumber int64
	Servers   []string
}

// GIDConflict is a different local group using one of a candidate's gids on a compute node.
type GIDConflict struct {
	Server    string
	Name      string
	GIDNumber int64
}

// Candidate is a discovered local group that may be registered as a system group.
type Candidate struct {
	Name           string
	Consistent     bool
	GIDNumber      int64 // set only when Consistent
	GIDs           []GIDServers
	MissingServers []string
	Conflicts      []GIDConflict // nil when no other group shares the gid
	Registered     bool
}

func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return internal.ErrInvalidSystemGroupName
	}
	return nil
}

// NewDenylist builds the denylist set: DefaultDenylist plus the configured names,
// trimmed, with empty entries ignored.
func NewDenylist(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(DefaultDenylist)+len(names))
	for _, name := range DefaultDenylist {
		set[name] = struct{}{}
	}
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			set[name] = struct{}{}
		}
	}
	return set
}

// gidsByName maps group name -> gid -> server names.
func gidsByName(groups []ansible.LocalGroup) map[string]map[int64][]string {
	byName := make(map[string]map[int64][]string)
	for _, group := range groups {
		if byName[group.Name] == nil {
			byName[group.Name] = make(map[int64][]string)
		}
		byName[group.Name][group.GIDNumber] = append(byName[group.Name][group.GIDNumber], group.ServerName)
	}
	return byName
}

func isDenied(name string, gids map[int64][]string, denylist map[string]struct{}) bool {
	if _, ok := denylist[name]; ok {
		return true
	}
	for gid := range gids {
		if gid == 0 || gid > MaxSystemGID {
			return true
		}
	}
	return false
}

// gidConflicts lists local groups with a different name that use one of gids on
// any compute node, sorted by server then name.
func gidConflicts(groups []ansible.LocalGroup, name string, gids map[int64][]string) []GIDConflict {
	var conflicts []GIDConflict
	for _, group := range groups {
		if group.Name == name {
			continue
		}
		if _, ok := gids[group.GIDNumber]; ok {
			conflicts = append(conflicts, GIDConflict{Server: group.ServerName, Name: group.Name, GIDNumber: group.GIDNumber})
		}
	}
	slices.SortFunc(conflicts, func(a, b GIDConflict) int {
		return cmp.Or(strings.Compare(a.Server, b.Server), strings.Compare(a.Name, b.Name))
	})
	return conflicts
}

// BuildCandidates returns registrable local groups sorted by name.
func BuildCandidates(groups []ansible.LocalGroup, denylist, registered map[string]struct{}) []Candidate {
	allServers := make(map[string]struct{})
	for _, group := range groups {
		allServers[group.ServerName] = struct{}{}
	}

	byName := gidsByName(groups)
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	slices.Sort(names)

	candidates := make([]Candidate, 0, len(names))
	for _, name := range names {
		gids := byName[name]
		if isDenied(name, gids, denylist) {
			continue
		}

		gidList := make([]int64, 0, len(gids))
		for gid := range gids {
			gidList = append(gidList, gid)
		}
		slices.Sort(gidList)

		candidate := Candidate{Name: name, Consistent: len(gidList) == 1, MissingServers: []string{}}
		_, candidate.Registered = registered[name]
		present := make(map[string]struct{})
		for _, gid := range gidList {
			servers := slices.Sorted(slices.Values(gids[gid]))
			for _, server := range servers {
				present[server] = struct{}{}
			}
			candidate.GIDs = append(candidate.GIDs, GIDServers{GIDNumber: gid, Servers: servers})
		}
		if candidate.Consistent {
			candidate.GIDNumber = gidList[0]
		}
		for server := range allServers {
			if _, ok := present[server]; !ok {
				candidate.MissingServers = append(candidate.MissingServers, server)
			}
		}
		slices.Sort(candidate.MissingServers)
		candidate.Conflicts = gidConflicts(groups, name, gids)

		candidates = append(candidates, candidate)
	}
	return candidates
}

// ResolveGID returns the single gid a registrable local group has on every compute node.
func ResolveGID(groups []ansible.LocalGroup, name string, denylist map[string]struct{}) (int64, error) {
	if _, ok := denylist[name]; ok {
		return 0, internal.ErrSystemGroupDenied
	}
	gids, ok := gidsByName(groups)[name]
	if !ok {
		return 0, internal.ErrSystemGroupNotDiscovered
	}
	if isDenied(name, gids, denylist) {
		return 0, internal.ErrSystemGroupDenied
	}
	if len(gids) > 1 {
		for gid := range gids {
			slices.Sort(gids[gid])
		}
		return 0, internal.ErrSystemGroupGIDInconsistent{Name: name, GIDs: gids}
	}
	if conflicts := gidConflicts(groups, name, gids); len(conflicts) > 0 {
		usedBy := make(map[string]string, len(conflicts))
		for _, c := range conflicts {
			usedBy[c.Server] = c.Name
		}
		return 0, internal.ErrSystemGroupGIDConflict{Name: name, GIDNumber: conflicts[0].GIDNumber, UsedBy: usedBy}
	}
	for gid := range gids {
		return gid, nil
	}
	return 0, internal.ErrSystemGroupNotDiscovered
}
