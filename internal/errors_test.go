package internal

import (
	"fmt"
	"net/http"
	"testing"
)

func TestErrorHandlerSystemGroupErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"invalid name", ErrInvalidSystemGroupName, http.StatusBadRequest},
		{"denied", fmt.Errorf("wrap: %w", ErrSystemGroupDenied), http.StatusForbidden},
		{"not discovered", ErrSystemGroupNotDiscovered, http.StatusNotFound},
		{"no ldap account", ErrUserHasNoLDAPAccount, http.StatusBadRequest},
		{"inconsistent gid", ErrSystemGroupGIDInconsistent{Name: "video", GIDs: map[int64][]string{44: {"node01"}, 45: {"node02"}}}, http.StatusConflict},
		{"gid used by another group", ErrSystemGroupGIDConflict{Name: "docker", GIDNumber: 999, UsedBy: map[string]string{"cpu01": "systemd-journal"}}, http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ErrorHandler(tt.err).Status; got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestErrSystemGroupGIDInconsistentMessage(t *testing.T) {
	err := ErrSystemGroupGIDInconsistent{Name: "video", GIDs: map[int64][]string{45: {"node02"}, 44: {"node01", "node03"}}}
	want := `group "video" has different gids across compute nodes: 44 on node01, node03; 45 on node02`
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
