package ansible_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"clustron-backend/internal/ansible"
	ansiblemocks "clustron-backend/internal/ansible/mocks"
)

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
