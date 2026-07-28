package internal

import (
	"net/http"
	"testing"
)

func TestAllowedLoginGroupErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "unsupported server role", err: ErrAllowedLoginGroupsUnsupported, wantStatus: http.StatusUnprocessableEntity},
		{name: "role change conflict", err: ErrAllowedLoginGroupsRoleConflict, wantStatus: http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ErrorHandler(tt.err)
			if got.Status != tt.wantStatus {
				t.Fatalf("ErrorHandler() status = %d, want %d", got.Status, tt.wantStatus)
			}
		})
	}
}

func TestServerAlreadyExistsErrorMapping(t *testing.T) {
	got := ErrorHandler(ErrServerAlreadyExists)
	if got.Status != http.StatusBadRequest {
		t.Fatalf("ErrorHandler() status = %d, want %d", got.Status, http.StatusBadRequest)
	}
}
