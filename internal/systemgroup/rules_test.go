package systemgroup_test

import (
	"testing"

	"clustron-backend/internal"
	"clustron-backend/internal/ansible"
	"clustron-backend/internal/systemgroup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateName(t *testing.T) {
	for _, name := range []string{"docker", "_ssh", "render-2", "a"} {
		assert.NoError(t, systemgroup.ValidateName(name), name)
	}
	for _, name := range []string{"", "Docker", "1abc", "has space", "abcdefghijklmnopqrstuvwxyz0123456"} {
		assert.ErrorIs(t, systemgroup.ValidateName(name), internal.ErrInvalidSystemGroupName, name)
	}
}

func TestNewDenylistDefaultsWhenEmpty(t *testing.T) {
	assert.Contains(t, systemgroup.NewDenylist(nil), "sudo")
	custom := systemgroup.NewDenylist([]string{"docker"})
	assert.Contains(t, custom, "docker")
	assert.NotContains(t, custom, "sudo")
}

var discovered = []ansible.LocalGroup{
	{ServerName: "node01", Name: "docker", GIDNumber: 999},
	{ServerName: "node02", Name: "docker", GIDNumber: 999},
	{ServerName: "node01", Name: "video", GIDNumber: 44},
	{ServerName: "node02", Name: "video", GIDNumber: 45},
	{ServerName: "node01", Name: "render", GIDNumber: 110},
	{ServerName: "node01", Name: "sudo", GIDNumber: 27},
	{ServerName: "node01", Name: "root", GIDNumber: 0},
	{ServerName: "node01", Name: "alice", GIDNumber: 1000},
}

func TestBuildCandidates(t *testing.T) {
	denylist := systemgroup.NewDenylist(nil)
	registered := map[string]struct{}{"render": {}}

	got := systemgroup.BuildCandidates(discovered, denylist, registered)

	require.Len(t, got, 3) // docker, render, video; sudo/root/alice filtered
	assert.Equal(t, systemgroup.Candidate{
		Name: "docker", Consistent: true, GIDNumber: 999,
		GIDs:           []systemgroup.GIDServers{{GIDNumber: 999, Servers: []string{"node01", "node02"}}},
		MissingServers: []string{},
	}, got[0])
	assert.Equal(t, "render", got[1].Name)
	assert.True(t, got[1].Registered)
	assert.Equal(t, []string{"node02"}, got[1].MissingServers)
	assert.Equal(t, "video", got[2].Name)
	assert.False(t, got[2].Consistent)
	assert.Equal(t, []systemgroup.GIDServers{
		{GIDNumber: 44, Servers: []string{"node01"}},
		{GIDNumber: 45, Servers: []string{"node02"}},
	}, got[2].GIDs)
}

func TestResolveGID(t *testing.T) {
	denylist := systemgroup.NewDenylist(nil)

	gid, err := systemgroup.ResolveGID(discovered, "docker", denylist)
	require.NoError(t, err)
	assert.Equal(t, int64(999), gid)

	_, err = systemgroup.ResolveGID(discovered, "sudo", denylist)
	assert.ErrorIs(t, err, internal.ErrSystemGroupDenied)

	_, err = systemgroup.ResolveGID(discovered, "root", systemgroup.NewDenylist([]string{"docker"}))
	assert.ErrorIs(t, err, internal.ErrSystemGroupDenied, "gid 0 is denied even if not denylisted")

	_, err = systemgroup.ResolveGID(discovered, "alice", denylist)
	assert.ErrorIs(t, err, internal.ErrSystemGroupDenied, "gid >= 1000 is denied")

	_, err = systemgroup.ResolveGID(discovered, "missing", denylist)
	assert.ErrorIs(t, err, internal.ErrSystemGroupNotDiscovered)

	_, err = systemgroup.ResolveGID(discovered, "video", denylist)
	var inconsistent internal.ErrSystemGroupGIDInconsistent
	require.ErrorAs(t, err, &inconsistent)
	assert.Equal(t, map[int64][]string{44: {"node01"}, 45: {"node02"}}, inconsistent.GIDs)
}
