package ansible

import (
	"reflect"
	"strings"
	"testing"

	results "github.com/apenella/go-ansible/v2/pkg/execute/result/json"
	"github.com/google/uuid"
)

func TestDiscoveryTargets(t *testing.T) {
	okCompute := Server{ID: uuid.New(), AnsibleName: "node01", AnsibleRole: computeNodeRole}
	failedCompute := Server{ID: uuid.New(), AnsibleName: "node02", AnsibleRole: computeNodeRole}
	okHead := Server{ID: uuid.New(), AnsibleName: "head", AnsibleRole: headNodeRole}
	successful := map[uuid.UUID]bool{okCompute.ID: true, failedCompute.ID: false, okHead.ID: true}

	got := discoveryTargets([]Server{okCompute, failedCompute, okHead}, successful)

	if len(got) != 1 || got[0].ID != okCompute.ID {
		t.Fatalf("discoveryTargets() = %v, want only node01", got)
	}
}

func TestParseGetentGroup(t *testing.T) {
	output := "root:x:0:\ndocker:x:999:alice,bob\nbroken\nbad:x:notanumber:\ndocker:x:998:\n\n"

	got := parseGetentGroup("node01", output)

	want := []LocalGroup{
		{ServerName: "node01", Name: "root", GIDNumber: 0},
		{ServerName: "node01", Name: "docker", GIDNumber: 999},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGetentGroup() = %#v, want %#v", got, want)
	}
}

func TestParseDiscoveredLocalGroups(t *testing.T) {
	raw := `{"plays":[{"play":{"name":"Discover local groups"},"tasks":[
		{"task":{"name":"Other task"},"hosts":{"node01":{"stdout":"ignored:x:1:"}}},
		{"task":{"name":"Read local groups"},"hosts":{
			"node01":{"stdout":"docker:x:999:\nvideo:x:44:"},
			"node02":{"failed":true,"stdout":"docker:x:999:"},
			"node03":{"unreachable":true},
			"node04":{"stdout":""}
		}}
	]}],"stats":{}}`
	res, err := results.ParseJSONResultsStream(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	got := parseDiscoveredLocalGroups(res)

	if len(got) != 2 {
		t.Fatalf("hosts = %v, want node01 and node04 only", got)
	}
	wantNode01 := []LocalGroup{
		{ServerName: "node01", Name: "docker", GIDNumber: 999},
		{ServerName: "node01", Name: "video", GIDNumber: 44},
	}
	if !reflect.DeepEqual(got["node01"], wantNode01) {
		t.Errorf("node01 = %#v, want %#v", got["node01"], wantNode01)
	}
	if groups, ok := got["node04"]; !ok || len(groups) != 0 {
		t.Errorf("node04 = %#v, present=%v; want present with no groups", groups, ok)
	}
}
