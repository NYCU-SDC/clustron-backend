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

type allowedLoginGroupsStore struct {
	Store
	gotServerID uuid.UUID
	gotGroups   []AllowedLoginGroupSelection
	groups      []AllowedLoginGroupDetail
}

func (s *allowedLoginGroupsStore) SetAllowedLoginGroups(_ context.Context, serverID uuid.UUID, groups []AllowedLoginGroupSelection) error {
	s.gotServerID = serverID
	s.gotGroups = groups
	return nil
}

func (s *allowedLoginGroupsStore) ListAllowedLoginGroups(_ context.Context, serverID uuid.UUID) ([]AllowedLoginGroupDetail, error) {
	s.gotServerID = serverID
	return s.groups, nil
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

func TestHandlerUpdateAllowedLoginGroupsUsesGroupIDAndType(t *testing.T) {
	serverID := uuid.New()
	baseGroupID := uuid.New()
	adminGroupID := uuid.New()
	store := &allowedLoginGroupsStore{}
	handler := NewHandler(store, validator.New(), zap.NewNop(), internal.NewProblemWriter())
	body := []byte(`{
		"groups": [
			{"groupId": "` + baseGroupID.String() + `", "type": "BASE"},
			{"groupId": "` + adminGroupID.String() + `", "type": "ADMIN"}
		]
	}`)
	req := httptest.NewRequest(http.MethodPut, "/api/servers/"+serverID.String()+"/allowedLoginGroups", bytes.NewReader(body))
	req.SetPathValue("server_id", serverID.String())
	recorder := httptest.NewRecorder()

	handler.UpdateAllowedLoginGroups(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	if store.gotServerID != serverID {
		t.Fatalf("server ID = %s, want %s", store.gotServerID, serverID)
	}
	want := []AllowedLoginGroupSelection{
		{GroupID: baseGroupID, Type: GroupTypeBASE},
		{GroupID: adminGroupID, Type: GroupTypeADMIN},
	}
	if len(store.gotGroups) != len(want) {
		t.Fatalf("groups length = %d, want %d", len(store.gotGroups), len(want))
	}
	for i := range want {
		if store.gotGroups[i] != want[i] {
			t.Errorf("group %d = %#v, want %#v", i, store.gotGroups[i], want[i])
		}
	}
}

func TestHandlerUpdateAllowedLoginGroupsRejectsInvalidType(t *testing.T) {
	serverID := uuid.New()
	store := &allowedLoginGroupsStore{}
	handler := NewHandler(store, validator.New(), zap.NewNop(), internal.NewProblemWriter())
	body := []byte(`{"groups":[{"groupId":"` + uuid.NewString() + `","type":"OWNER"}]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/servers/"+serverID.String()+"/allowedLoginGroups", bytes.NewReader(body))
	req.SetPathValue("server_id", serverID.String())
	recorder := httptest.NewRecorder()

	handler.UpdateAllowedLoginGroups(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if store.gotGroups != nil {
		t.Fatal("store was called for an invalid group type")
	}
}

func TestHandlerGetAllowedLoginGroupsReturnsGroupType(t *testing.T) {
	serverID := uuid.New()
	groupID := uuid.New()
	store := &allowedLoginGroupsStore{groups: []AllowedLoginGroupDetail{{
		GroupID: groupID,
		Type:    GroupTypeADMIN,
		Title:   "Research",
		LdapCN:  "research-admin",
	}}}
	handler := NewHandler(store, validator.New(), zap.NewNop(), internal.NewProblemWriter())
	req := httptest.NewRequest(http.MethodGet, "/api/servers/"+serverID.String()+"/allowedLoginGroups", nil)
	req.SetPathValue("server_id", serverID.String())
	recorder := httptest.NewRecorder()

	handler.GetAllowedLoginGroups(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response []AllowedLoginGroupResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response) != 1 {
		t.Fatalf("response length = %d, want 1", len(response))
	}
	if response[0].GroupID != groupID.String() || response[0].Type != "ADMIN" || response[0].LdapCN != "research-admin" {
		t.Fatalf("response = %#v, want group ID %s with ADMIN type and research-admin CN", response[0], groupID)
	}
}
