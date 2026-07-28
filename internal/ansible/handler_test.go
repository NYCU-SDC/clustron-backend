package ansible

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustron-backend/internal"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type addNodesStore struct {
	Store
	gotParams []CreateParams
}

func (s *addNodesStore) AddNodes(_ context.Context, params []CreateParams) ([]Server, error) {
	s.gotParams = params
	servers := make([]Server, len(params))
	for i, param := range params {
		servers[i] = Server{
			ID:            uuid.New(),
			AnsibleName:   param.AnsibleName,
			IpAddress:     param.IpAddress,
			SshConfigHost: param.SshConfigHost,
			SshUser:       param.SshUser,
			AnsibleRole:   param.AnsibleRole,
			Status:        "provisioning",
		}
	}
	return servers, nil
}

func TestHandlerAddNodes(t *testing.T) {
	store := &addNodesStore{}
	handler := NewHandler(store, validator.New(), zap.NewNop(), internal.NewProblemWriter())
	body := []byte(`{
		"servers": [
			{
				"ansible_name": "compute-01",
				"ip_address": "192.0.2.1",
				"ssh_user": "ubuntu",
				"ansible_role": "compute_nodes"
			},
			{
				"ansible_name": "compute-02",
				"ssh_config_host": "compute-02",
				"private_ip": "10.0.0.2",
				"ansible_role": "compute_nodes"
			}
		]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/servers/batch", bytes.NewReader(body))
	recorder := httptest.NewRecorder()

	handler.AddNodes(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if len(store.gotParams) != 2 {
		t.Fatalf("AddNodes params length = %d, want 2", len(store.gotParams))
	}
	if !store.gotParams[0].IpAddress.Valid || store.gotParams[0].IpAddress.String != "192.0.2.1" {
		t.Errorf("first server IP = %#v, want 192.0.2.1", store.gotParams[0].IpAddress)
	}
	if !store.gotParams[1].SshConfigHost.Valid || store.gotParams[1].SshConfigHost.String != "compute-02" {
		t.Errorf("second server SSH config host = %#v, want compute-02", store.gotParams[1].SshConfigHost)
	}

	var response AddNodesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Servers) != 2 {
		t.Fatalf("response servers length = %d, want 2", len(response.Servers))
	}
	for _, server := range response.Servers {
		if server.Status != "provisioning" {
			t.Errorf("server %q status = %q, want provisioning", server.AnsibleName, server.Status)
		}
	}
}
