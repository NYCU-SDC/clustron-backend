package ansible_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"clustron-backend/internal/ansible"
	ansiblemocks "clustron-backend/internal/ansible/mocks"
)

func newTestHandler(store *ansiblemocks.Store) *ansible.Handler {
	return ansible.NewHandler(store, validator.New(), zap.NewNop(), problem.New())
}

func newPartitionRequest(method, partitionName string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, "/api/partitions/"+partitionName+"/allowedGroups", nil)
	} else {
		r = httptest.NewRequest(method, "/api/partitions/"+partitionName+"/allowedGroups", bytes.NewReader(body))
	}
	r.SetPathValue("partition_name", partitionName)
	return r
}

func TestHandlerAddNodes(t *testing.T) {
	testCases := []struct {
		name           string
		body           string
		setupMock      func(store *ansiblemocks.Store)
		expectedStatus int
		expectedCount  int
	}{
		{
			name: "creates two servers",
			body: `{
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
			}`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("AddNodes", mock.Anything, mock.MatchedBy(func(params []ansible.CreateParams) bool {
					return len(params) == 2
				})).Return([]ansible.Server{
					{ID: uuid.New(), AnsibleName: "compute-01", Status: "provisioning"},
					{ID: uuid.New(), AnsibleName: "compute-02", Status: "provisioning"},
				}, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedCount:  2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := ansiblemocks.NewStore(t)
			tc.setupMock(store)

			h := ansible.NewHandler(store, validator.New(), zap.NewNop(), problem.New())
			req := httptest.NewRequest(http.MethodPost, "/api/servers/batch", bytes.NewReader([]byte(tc.body)))
			w := httptest.NewRecorder()

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
			EnableSlurm:   param.EnableSlurm,
			MountNfsHome:  param.MountNfsHome,
		}
			h.AddNodes(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedStatus == http.StatusCreated {
				var response ansible.AddNodesResponse
				assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				assert.Len(t, response.Servers, tc.expectedCount)
				for _, server := range response.Servers {
					assert.Equal(t, "provisioning", server.Status)
				}
			}
		})
	}
}

func TestHandler_GetPartitionAllowedGroups(t *testing.T) {
	groupID := uuid.New()

	testCases := []struct {
		name           string
		setupMock      func(store *ansiblemocks.Store)
		expectedStatus int
		expectedGroups []ansible.PartitionAllowedGroupResponse
	}{
		{
			name: "returns the allowed groups with their type",
			setupMock: func(store *ansiblemocks.Store) {
				store.On("ListPartitionAllowedGroups", mock.Anything, "gpu").Return([]ansible.PartitionAllowedGroupDetail{
					{GroupID: groupID, Type: ansible.GroupTypeBASE, Title: "CS Lab", LdapCN: "cs-lab"},
					{GroupID: groupID, Type: ansible.GroupTypeADMIN, Title: "CS Lab", LdapCN: "cs-lab-admin"},
				}, nil)
			},
			{
				"ansible_name": "compute-02",
				"ssh_config_host": "compute-02",
				"private_ip": "10.0.0.2",
				"ansible_role": "compute_nodes",
				"features": {
					"slurm": false,
					"nfs_home": false
				}
			}
		]
	}
	req := httptest.NewRequest(http.MethodPost, "/api/servers/batch", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
			expectedStatus: http.StatusOK,
			expectedGroups: []ansible.PartitionAllowedGroupResponse{
				{GroupID: groupID.String(), Type: "BASE", Title: "CS Lab", LdapCN: "cs-lab"},
				{GroupID: groupID.String(), Type: "ADMIN", Title: "CS Lab", LdapCN: "cs-lab-admin"},
			},
		},
		{
			name: "unrestricted partition returns an empty list",
			setupMock: func(store *ansiblemocks.Store) {
				store.On("ListPartitionAllowedGroups", mock.Anything, "gpu").Return([]ansible.PartitionAllowedGroupDetail{}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedGroups: []ansible.PartitionAllowedGroupResponse{},
		},
		{
			name: "unknown partition",
			setupMock: func(store *ansiblemocks.Store) {
				store.On("ListPartitionAllowedGroups", mock.Anything, "gpu").Return(
					nil, handlerutil.NewNotFoundError("partitions", "name", "gpu", ""),
				)
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := ansiblemocks.NewStore(t)
			tc.setupMock(store)

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
	if !store.gotParams[0].EnableSlurm || !store.gotParams[0].MountNfsHome {
		t.Errorf("first server features = (%v, %v), want defaults (true, true)", store.gotParams[0].EnableSlurm, store.gotParams[0].MountNfsHome)
	}
	if store.gotParams[1].EnableSlurm || store.gotParams[1].MountNfsHome {
		t.Errorf("second server features = (%v, %v), want (false, false)", store.gotParams[1].EnableSlurm, store.gotParams[1].MountNfsHome)
	}

	var response AddNodesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Servers) != 2 {
		t.Fatalf("response servers length = %d, want 2", len(response.Servers))
	}
	for _, server := range response.Servers {
		wantFeatures := server.AnsibleName == "compute-01"
		if server.Features.Slurm != wantFeatures || server.Features.NfsHome != wantFeatures {
			t.Errorf("server %q response features = (%v, %v), want %v", server.AnsibleName, server.Features.Slurm, server.Features.NfsHome, wantFeatures)
		}
		if server.Status != "provisioning" {
			t.Errorf("server %q status = %q, want provisioning", server.AnsibleName, server.Status)
		}
			w := httptest.NewRecorder()
			newTestHandler(store).GetPartitionAllowedGroups(w, newPartitionRequest(http.MethodGet, "gpu", nil))

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedStatus == http.StatusOK {
				var got []ansible.PartitionAllowedGroupResponse
				assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
				assert.Equal(t, tc.expectedGroups, got)
			}
		})
	}
}

func TestHandler_UpdatePartitionAllowedGroups(t *testing.T) {
	groupID := uuid.New()
	base := []ansible.AllowedLoginGroupSelection{{GroupID: groupID, Type: ansible.GroupTypeBASE}}
	baseBody := `[{"groupId":"` + groupID.String() + `","groupType":"BASE"}]`

	testCases := []struct {
		name           string
		body           string
		setupMock      func(store *ansiblemocks.Store)
		expectedStatus int
	}{
		{
			name: "assigns a group's BASE account to a partition",
			body: baseBody,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", base).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "assigns a group's ADMIN account to a partition",
			body: `[{"groupId":"` + groupID.String() + `","groupType":"ADMIN"}]`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu",
					[]ansible.AllowedLoginGroupSelection{{GroupID: groupID, Type: ansible.GroupTypeADMIN}}).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "empty list re-opens the partition",
			body: `[]`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", []ansible.AllowedLoginGroupSelection{}).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "non-uuid group id is rejected before reaching the store",
			body:           `[{"groupId":"not-a-uuid","groupType":"BASE"}]`,
			setupMock:      func(store *ansiblemocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unknown group type is rejected before reaching the store",
			body:           `[{"groupId":"` + groupID.String() + `","groupType":"OWNER"}]`,
			setupMock:      func(store *ansiblemocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "old object body is rejected",
			body:           `{"groupIds":["` + groupID.String() + `"]}`,
			setupMock:      func(store *ansiblemocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "unknown partition",
			body: baseBody,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", base).Return(
					handlerutil.NewNotFoundError("partitions", "name", "gpu", ""),
				)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "store failure",
			body: baseBody,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", base).Return(errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := ansiblemocks.NewStore(t)
			tc.setupMock(store)

			w := httptest.NewRecorder()
			newTestHandler(store).UpdatePartitionAllowedGroups(w, newPartitionRequest(http.MethodPut, "gpu", []byte(tc.body)))

			assert.Equal(t, tc.expectedStatus, w.Code, w.Body.String())
		})
	}
}

func newAllowedLoginGroupsRequest(method string, serverID uuid.UUID, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, "/api/servers/"+serverID.String()+"/allowedLoginGroups", nil)
	} else {
		r = httptest.NewRequest(method, "/api/servers/"+serverID.String()+"/allowedLoginGroups", bytes.NewReader(body))
	}
	r.SetPathValue("server_id", serverID.String())
	return r
}

func TestHandler_UpdateAllowedLoginGroups_UsesGroupIDAndType(t *testing.T) {
	serverID, baseGroupID, adminGroupID := uuid.New(), uuid.New(), uuid.New()
	store := ansiblemocks.NewStore(t)
	store.On("SetAllowedLoginGroups", mock.Anything, serverID, []ansible.AllowedLoginGroupSelection{
		{GroupID: baseGroupID, Type: ansible.GroupTypeBASE},
		{GroupID: adminGroupID, Type: ansible.GroupTypeADMIN},
	}).Return(nil)
	body := `[{"groupId":"` + baseGroupID.String() + `","groupType":"BASE"},{"groupId":"` + adminGroupID.String() + `","groupType":"ADMIN"}]`

	w := httptest.NewRecorder()
	newTestHandler(store).UpdateAllowedLoginGroups(w, newAllowedLoginGroupsRequest(http.MethodPut, serverID, []byte(body)))

	assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
}

func TestHandler_UpdateAllowedLoginGroups_RejectsInvalidType(t *testing.T) {
	serverID := uuid.New()
	// No expectations: any store call fails the test.
	store := ansiblemocks.NewStore(t)
	body := `[{"groupId":"` + uuid.NewString() + `","groupType":"OWNER"}]`

	w := httptest.NewRecorder()
	newTestHandler(store).UpdateAllowedLoginGroups(w, newAllowedLoginGroupsRequest(http.MethodPut, serverID, []byte(body)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "oneof")
}

func TestHandler_GetAllowedLoginGroups_ReturnsGroupType(t *testing.T) {
	serverID, groupID := uuid.New(), uuid.New()
	store := ansiblemocks.NewStore(t)
	store.On("ListAllowedLoginGroups", mock.Anything, serverID).Return([]ansible.AllowedLoginGroupDetail{
		{GroupID: groupID, Type: ansible.GroupTypeADMIN, Title: "Research", LdapCN: "research-admin"},
	}, nil)

	w := httptest.NewRecorder()
	newTestHandler(store).GetAllowedLoginGroups(w, newAllowedLoginGroupsRequest(http.MethodGet, serverID, nil))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []ansible.AllowedLoginGroupResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, []ansible.AllowedLoginGroupResponse{
		{GroupID: groupID.String(), Type: "ADMIN", Title: "Research", LdapCN: "research-admin"},
	}, got)
}
