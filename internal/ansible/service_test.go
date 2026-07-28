package ansible

import (
	"errors"
	"strings"
	"testing"

	"clustron-backend/internal"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

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
		sshUser       string
		wantErr       bool
	}{
		{name: "IP with user", ipAddress: "192.0.2.1", sshUser: "ubuntu"},
		{name: "IP without user", ipAddress: "192.0.2.1", wantErr: true},
		{name: "SSH config with user", sshConfigHost: "compute-node", sshUser: "ubuntu"},
		{name: "SSH config without user", sshConfigHost: "compute-node"},
		{name: "IP and SSH config without user", ipAddress: "192.0.2.1", sshConfigHost: "compute-node", wantErr: true},
	}

	validate := validator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := AddNodeRequest{
				AnsibleName:   "compute-node",
				IpAddress:     tt.ipAddress,
				SshConfigHost: tt.sshConfigHost,
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
