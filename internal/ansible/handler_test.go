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
		expectedGroups int
	}{
		{
			name: "returns the allowed groups",
			setupMock: func(store *ansiblemocks.Store) {
				store.On("ListPartitionAllowedGroups", mock.Anything, "gpu").Return(
					[]ansible.PartitionAllowedGroupDetail{{GroupID: groupID, Title: "CS Lab", LdapCN: "cs-lab"}}, nil,
				)
			},
			expectedStatus: http.StatusOK,
			expectedGroups: 1,
		},
		{
			name: "unrestricted partition returns an empty list",
			setupMock: func(store *ansiblemocks.Store) {
				store.On("ListPartitionAllowedGroups", mock.Anything, "gpu").Return([]ansible.PartitionAllowedGroupDetail{}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedGroups: 0,
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

			w := httptest.NewRecorder()
			newTestHandler(store).GetPartitionAllowedGroups(w, newPartitionRequest(http.MethodGet, "gpu", nil))

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedStatus == http.StatusOK {
				var got []ansible.PartitionAllowedGroupResponse
				assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
				assert.Len(t, got, tc.expectedGroups)
			}
		})
	}
}

func TestHandler_UpdatePartitionAllowedGroups(t *testing.T) {
	groupID := uuid.New()

	testCases := []struct {
		name           string
		body           string
		setupMock      func(store *ansiblemocks.Store)
		expectedStatus int
	}{
		{
			name: "assigns groups to a partition",
			body: `{"groupIds":["` + groupID.String() + `"]}`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", []uuid.UUID{groupID}).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "empty list re-opens the partition",
			body: `{"groupIds":[]}`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", []uuid.UUID{}).Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "non-uuid group id is rejected before reaching the store",
			body:           `{"groupIds":["not-a-uuid"]}`,
			setupMock:      func(store *ansiblemocks.Store) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "unknown partition",
			body: `{"groupIds":["` + groupID.String() + `"]}`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", []uuid.UUID{groupID}).Return(
					handlerutil.NewNotFoundError("partitions", "name", "gpu", ""),
				)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "store failure",
			body: `{"groupIds":["` + groupID.String() + `"]}`,
			setupMock: func(store *ansiblemocks.Store) {
				store.On("SetPartitionAllowedGroups", mock.Anything, "gpu", []uuid.UUID{groupID}).Return(errors.New("db error"))
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

			assert.Equal(t, tc.expectedStatus, w.Code)
		})
	}
}
