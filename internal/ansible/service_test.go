package ansible

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"clustron-backend/internal"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestDuplicateServerField(t *testing.T) {
	params := CreateParams{
		AnsibleName:   "cpu3",
		IpAddress:     pgtype.Text{String: "192.0.2.3", Valid: true},
		PrivateIp:     pgtype.Text{String: "10.0.0.3", Valid: true},
		SshConfigHost: pgtype.Text{String: "cpu3-ssh", Valid: true},
	}
	tests := []struct {
		constraint string
		wantDetail string
	}{
		{constraint: "servers_ansible_name_key", wantDetail: `ansible_name "cpu3"`},
		{constraint: "servers_ip_address_key", wantDetail: `ip_address "192.0.2.3"`},
		{constraint: "servers_ssh_config_host_key", wantDetail: `ssh_config_host "cpu3-ssh"`},
		{constraint: "servers_private_ip_key", wantDetail: `private_ip "10.0.0.3"`},
	}

	for _, tt := range tests {
		t.Run(tt.constraint, func(t *testing.T) {
			field, value := duplicateServerField(tt.constraint, params)
			detail := fmt.Sprintf(`%s %q`, field, value)
			if detail != tt.wantDetail {
				t.Fatalf("duplicateServerField() detail = %q, want %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestMapAllowedLoginGroupError(t *testing.T) {
	serverID := uuid.New()
	groupID := uuid.New()
	tests := []struct {
		name       string
		constraint string
		wantValue  string
	}{
		{name: "server removed", constraint: "allowed_login_groups_server_id_fkey", wantValue: serverID.String()},
		{name: "group removed", constraint: "allowed_login_groups_group_id_fkey", wantValue: groupID.String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapAllowedLoginGroupError(&pgconn.PgError{Code: "23503", ConstraintName: tt.constraint}, serverID, groupID, zap.NewNop())
			if !errors.Is(err, handlerutil.ErrNotFound) {
				t.Fatalf("mapAllowedLoginGroupError() error = %v, want ErrNotFound", err)
			}
			if !strings.Contains(err.Error(), tt.wantValue) {
				t.Fatalf("mapAllowedLoginGroupError() error = %q, want value %q", err, tt.wantValue)
			}
		})
	}
}

func validAddNodeRequest(name string) AddNodeRequest {
	return AddNodeRequest{
		AnsibleName: name,
		IpAddress:   "192.0.2.1",
		SshUser:     "ubuntu",
		AnsibleRole: computeNodeRole,
	}
}

func TestAddNodeRequestAnsibleNameValidation(t *testing.T) {
	tests := []struct {
		name        string
		ansibleName string
		wantErr     bool
	}{
		{name: "hostname", ansibleName: "test-head"},
		{name: "fqdn", ansibleName: "head.example.com"},
		{name: "maximum length", ansibleName: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
		{name: "space", ansibleName: "test head", wantErr: true},
		{name: "underscore", ansibleName: "test_head", wantErr: true},
		{name: "too long", ansibleName: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63), wantErr: true},
		{name: "empty", wantErr: true},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := AddNodeRequest{
				AnsibleName: tt.ansibleName,
				IpAddress:   "192.0.2.1",
				SshUser:     "ubuntu",
				AnsibleRole: headNodeRole,
			}

			err := validate.Struct(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validator.Struct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddNodeRequestSshUserValidation(t *testing.T) {
	tests := []struct {
		name          string
		ipAddress     string
		sshConfigHost string
		privateIP     string
		sshUser       string
		wantErr       bool
	}{
		{name: "IP with user", ipAddress: "192.0.2.1", sshUser: "ubuntu"},
		{name: "IP without user", ipAddress: "192.0.2.1", wantErr: true},
		{name: "SSH config with user", sshConfigHost: "compute-node", privateIP: "192.0.2.2", sshUser: "ubuntu"},
		{name: "SSH config without user", sshConfigHost: "compute-node", privateIP: "192.0.2.2"},
		{name: "SSH config without private IP", sshConfigHost: "compute-node", wantErr: true},
		{name: "IP and SSH config without user", ipAddress: "192.0.2.1", sshConfigHost: "compute-node", wantErr: true},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := AddNodeRequest{
				AnsibleName:   "compute-node",
				IpAddress:     tt.ipAddress,
				SshConfigHost: tt.sshConfigHost,
				PrivateIp:     tt.privateIP,
				SshUser:       tt.sshUser,
				AnsibleRole:   computeNodeRole,
			}

			err := validate.Struct(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validator.Struct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddNodeRequestIPValidation(t *testing.T) {
	tests := []struct {
		name    string
		req     AddNodeRequest
		wantErr bool
	}{
		{name: "direct IP", req: validAddNodeRequest("compute-01")},
		{
			name: "SSH config with private IP",
			req: AddNodeRequest{
				AnsibleName:   "compute-01",
				SshConfigHost: "compute-01",
				PrivateIp:     "10.0.0.1",
				AnsibleRole:   computeNodeRole,
			},
		},
		{
			name: "SSH config without private IP",
			req: AddNodeRequest{
				AnsibleName:   "compute-01",
				SshConfigHost: "compute-01",
				AnsibleRole:   computeNodeRole,
			},
			wantErr: true,
		},
		{
			name: "invalid direct IP",
			req: AddNodeRequest{
				AnsibleName: "compute-01",
				IpAddress:   "not-an-ip",
				SshUser:     "ubuntu",
				AnsibleRole: computeNodeRole,
			},
			wantErr: true,
		},
		{
			name: "invalid private IP",
			req: AddNodeRequest{
				AnsibleName:   "compute-01",
				SshConfigHost: "compute-01",
				PrivateIp:     "not-an-ip",
				AnsibleRole:   computeNodeRole,
			},
			wantErr: true,
		},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validator.Struct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerRequestStringValidation(t *testing.T) {
	longValue := strings.Repeat("a", 256)
	tests := []struct {
		name string
		req  AddNodeRequest
	}{
		{name: "SSH config host too long", req: AddNodeRequest{AnsibleName: "cpu3", SshConfigHost: longValue, PrivateIp: "10.0.0.3", AnsibleRole: computeNodeRole}},
		{name: "SSH user too long", req: AddNodeRequest{AnsibleName: "cpu3", IpAddress: "192.0.2.3", SshUser: longValue, AnsibleRole: computeNodeRole}},
		{name: "SSH key name too long", req: AddNodeRequest{AnsibleName: "cpu3", IpAddress: "192.0.2.3", SshUser: "ubuntu", SshKeyName: longValue, AnsibleRole: computeNodeRole}},
		{name: "role too long", req: AddNodeRequest{AnsibleName: "cpu3", IpAddress: "192.0.2.3", SshUser: "ubuntu", AnsibleRole: longValue}},
		{name: "partition too long", req: AddNodeRequest{AnsibleName: "cpu3", IpAddress: "192.0.2.3", SshUser: "ubuntu", AnsibleRole: computeNodeRole, SlurmPartition: longValue}},
		{name: "unknown role", req: AddNodeRequest{AnsibleName: "cpu3", IpAddress: "192.0.2.3", SshUser: "ubuntu", AnsibleRole: "worker"}},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validate.Struct(tt.req); err == nil {
				t.Fatal("validator.Struct() error = nil, want validation error")
			}
		})
	}
}

func TestUpdateRoleRequestValidation(t *testing.T) {
	validate := validator.New()
	for _, role := range []string{headNodeRole, computeNodeRole} {
		if err := validate.Struct(UpdateRoleRequest{AnsibleRole: role}); err != nil {
			t.Errorf("validator.Struct(%q) error = %v", role, err)
		}
	}
	if err := validate.Struct(UpdateRoleRequest{AnsibleRole: "worker"}); err == nil {
		t.Fatal("validator.Struct(unknown role) error = nil, want validation error")
	}
}

func TestAddNodesRequestValidation(t *testing.T) {
	validServers := []AddNodeRequest{validAddNodeRequest("compute-01")}
	tooManyServers := make([]AddNodeRequest, 51)
	for i := range tooManyServers {
		tooManyServers[i] = validAddNodeRequest("compute-01")
	}

	tests := []struct {
		name    string
		req     AddNodesRequest
		wantErr bool
	}{
		{name: "one server", req: AddNodesRequest{Servers: validServers}},
		{name: "empty", req: AddNodesRequest{}, wantErr: true},
		{name: "more than fifty", req: AddNodesRequest{Servers: tooManyServers}, wantErr: true},
		{name: "invalid nested server", req: AddNodesRequest{Servers: []AddNodeRequest{{}}}, wantErr: true},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validator.Struct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToCreateParams(t *testing.T) {
	cpuCores := int32(32)
	memoryMB := int32(131072)
	req := AddNodeRequest{
		AnsibleName:    "compute-01",
		IpAddress:      "192.0.2.1",
		PrivateIp:      "10.0.0.1",
		SshUser:        "ubuntu",
		SshKeyName:     "cluster-key",
		AnsibleRole:    computeNodeRole,
		SlurmPartition: "gpu",
		CpuCores:       &cpuCores,
		MemoryMb:       &memoryMB,
	}

	got := toCreateParams(req)
	want := CreateParams{
		AnsibleName:    "compute-01",
		IpAddress:      pgtype.Text{String: "192.0.2.1", Valid: true},
		PrivateIp:      pgtype.Text{String: "10.0.0.1", Valid: true},
		SshUser:        pgtype.Text{String: "ubuntu", Valid: true},
		SshKeyName:     pgtype.Text{String: "cluster-key", Valid: true},
		AnsibleRole:    computeNodeRole,
		SlurmPartition: pgtype.Text{String: "gpu", Valid: true},
		CpuCores:       pgtype.Int4{Int32: cpuCores, Valid: true},
		MemoryMb:       pgtype.Int4{Int32: memoryMB, Valid: true},
	}

	if got != want {
		t.Fatalf("toCreateParams() = %#v, want %#v", got, want)
	}
}

func TestHostVarsAnsibleUserYAML(t *testing.T) {
	tests := []struct {
		name            string
		ansibleUser     string
		wantAnsibleUser bool
	}{
		{name: "configured user", ansibleUser: "ubuntu", wantAnsibleUser: true},
		{name: "SSH config user"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := yaml.Marshal(HostVars{AnsibleUser: tt.ansibleUser})
			if err != nil {
				t.Fatalf("yaml.Marshal() error = %v", err)
			}

			hasAnsibleUser := strings.Contains(string(data), "ansible_user:")
			if hasAnsibleUser != tt.wantAnsibleUser {
				t.Fatalf("yaml.Marshal() = %q, want ansible_user field %v", data, tt.wantAnsibleUser)
			}
		})
	}
}

func TestValidateAllowedLoginGroupTarget(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		groupIDs []uuid.UUID
		wantErr  error
	}{
		{name: "compute node with groups", role: computeNodeRole, groupIDs: []uuid.UUID{uuid.New()}},
		{name: "compute node without groups", role: computeNodeRole, groupIDs: []uuid.UUID{}},
		{name: "head node cleanup", role: headNodeRole, groupIDs: []uuid.UUID{}},
		{name: "head node with groups", role: headNodeRole, groupIDs: []uuid.UUID{uuid.New()}, wantErr: internal.ErrAllowedLoginGroupsUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllowedLoginGroupTarget(tt.role, tt.groupIDs)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateAllowedLoginGroupTarget() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAllowedLoginGroupRoleChange(t *testing.T) {
	tests := []struct {
		name                  string
		role                  string
		hasAllowedLoginGroups bool
		wantErr               error
	}{
		{name: "head node without groups", role: headNodeRole},
		{name: "head node with groups", role: headNodeRole, hasAllowedLoginGroups: true, wantErr: internal.ErrAllowedLoginGroupsRoleConflict},
		{name: "compute node with groups", role: computeNodeRole, hasAllowedLoginGroups: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllowedLoginGroupRoleChange(tt.role, tt.hasAllowedLoginGroups)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateAllowedLoginGroupRoleChange() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAnsibleError(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		want       []string
		wantAbsent []string
	}{
		{
			name: "legacy fatal output",
			output: "TASK [Install package]\n" +
				"fatal: [compute-01]: FAILED! => {\"msg\": \"package not found\"}\n" +
				"PLAY RECAP ****\n" +
				"compute-01 : ok=1 changed=0 unreachable=0 failed=1\n",
			want: []string{
				"Stage: Install package",
				"fatal: [compute-01]: FAILED!",
				"PLAY RECAP:",
			},
			wantAbsent: []string{"Output tail:"},
		},
		{
			name: "new error output",
			output: "TASK [Validate configuration]\n" +
				"[ERROR]: Task failed: configuration is invalid\n" +
				"PLAY RECAP ****\n" +
				"compute-01 : ok=0 changed=0 unreachable=0 failed=1\n" +
				"TASKS RECAP ****\n" +
				"Validate configuration ----------------------------- 0.14s\n",
			want: []string{
				"Stage: Validate configuration",
				"[ERROR]: Task failed: configuration is invalid",
				"compute-01 : ok=0 changed=0 unreachable=0 failed=1",
			},
			wantAbsent: []string{"Output tail:", "TASKS RECAP", "0.14s"},
		},
		{
			name:   "unknown output falls back to raw tail",
			output: "unexpected callback output\nconnection closed by remote host\n",
			want: []string{
				"Output tail:",
				"unexpected callback output",
				"connection closed by remote host",
			},
		},
		{
			name:   "raw tail is bounded",
			output: "oldest line\n" + strings.Repeat("middle line\n", maxAnsibleErrorOutputLines-1) + "newest line",
			want:   []string{"middle line", "newest line"},
			wantAbsent: []string{
				"oldest line",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAnsibleError(tt.output)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("parseAnsibleError() = %q, want substring %q", got, want)
				}
			}
			for _, unwanted := range tt.wantAbsent {
				if strings.Contains(got, unwanted) {
					t.Errorf("parseAnsibleError() = %q, unwanted substring %q", got, unwanted)
				}
			}
		})
	}
}

func TestParseAnsibleRecap(t *testing.T) {
	output := "PLAY RECAP ****\n" +
		"compute-01 : ok=12 changed=3 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0\n" +
		"compute-02 : ok=4 changed=0 unreachable=1 failed=0 skipped=0 rescued=0 ignored=0\n" +
		"compute-03 : ok=8 changed=1 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n" +
		"TASKS RECAP ****\n" +
		"common : configure host -------------------------------- 1.00s\n"

	got := parseAnsibleRecap(output)
	want := map[string]bool{
		"compute-01": true,
		"compute-02": false,
		"compute-03": false,
	}
	if len(got) != len(want) {
		t.Fatalf("parseAnsibleRecap() = %#v, want %#v", got, want)
	}
	for host, wantSuccess := range want {
		if got[host] != wantSuccess {
			t.Errorf("parseAnsibleRecap()[%q] = %v, want %v", host, got[host], wantSuccess)
		}
	}
}
