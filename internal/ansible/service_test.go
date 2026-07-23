package ansible

import (
	"errors"
	"testing"

	"clustron-backend/internal"

	"github.com/google/uuid"
)

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
