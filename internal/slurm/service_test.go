package slurm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestParseUserAssociationResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ParsedUserAssociationResponse
	}{
		{
			name: "valid user association response with multiple users and associations",
			input: ` Adding User(s)\n` +
				`  user1\n` +
				`  user2\n` +
				` Settings\n` +
				`  Default Account = testaccount\n` +
				`  Admin Level = None\n` +
				` Associations\n` +
				`  C = head       A = testaccount                U = user1     \n` +
				`  C = head       A = testaccount                U = user2     \n`,
			expected: ParsedUserAssociationResponse{
				AddedUsers:     []string{"user1", "user2"},
				DefaultAccount: "testaccount",
				AdminLevel:     "None",
				Associations: []Association{
					{User: "user1", Account: "testaccount", Cluster: "head"},
					{User: "user2", Account: "testaccount", Cluster: "head"},
				},
			},
		},
		{
			name:  "empty or empty lines only",
			input: "\n\n",
			expected: ParsedUserAssociationResponse{
				AddedUsers:   nil,
				Associations: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUserAssociationResponse(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseAccountAssociationResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ParsedAccountAssociationResponse
	}{
		{
			name: "valid account association response",
			input: ` Adding Account(s)\n` +
				`  acc1\n` +
				` Settings\n` +
				`  Description = test account description\n` +
				`  Organization = testorg\n` +
				` Associations\n` +
				`  A = acc1       C = dev-cluster\n`,
			expected: ParsedAccountAssociationResponse{
				AddedAccounts: []string{"acc1"},
				Description:   "test account description",
				Organization:  "testorg",
				Associations: []Association{
					{Account: "acc1", Cluster: "dev-cluster"},
				},
			},
		},
		{
			name: "ignore root level lines",
			input: `freeform message to ignore\n` +
				` Adding Account(s)\n` +
				`  acc2\n`,
			expected: ParsedAccountAssociationResponse{
				AddedAccounts: []string{"acc2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseAccountAssociationResponse(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCreateAccountAssociationParent(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		wantParent string // "" means the field must be absent from the request
	}{
		{name: "with parent", parent: "proj101", wantParent: "proj101"},
		{name: "without parent keeps account under root", parent: "", wantParent: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/slurmdb/v0.0.44/accounts_association", r.URL.Path)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"added_accounts": " Adding Account(s)\n  proj101-base\n", "errors": [], "warnings": []}`))
			}))
			defer server.Close()

			svc := NewService(zap.NewNop(), "", server.URL, "v0.0.44", "root-token", nil, nil)

			resp, err := svc.CreateAccountAssociation(context.Background(), []string{"proj101-base"}, nil, tt.parent)
			require.NoError(t, err)
			assert.Equal(t, []string{"proj101-base"}, resp.AddedAccounts)

			cond, ok := gotBody["association_condition"].(map[string]any)
			require.True(t, ok, "request must contain association_condition")
			assert.Equal(t, []any{"proj101-base"}, cond["accounts"])

			assoc, _ := cond["association"].(map[string]any)
			if tt.wantParent == "" {
				_, present := assoc["parent"]
				assert.False(t, present, "parent must be omitted when empty")
			} else {
				assert.Equal(t, tt.wantParent, assoc["parent"])
			}
		})
	}
}
