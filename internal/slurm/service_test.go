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
	testCases := []struct {
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUserAssociationResponse(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestParseAccountAssociationResponse(t *testing.T) {
	testCases := []struct {
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAccountAssociationResponse(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestCreateAccountAssociationParent(t *testing.T) {
	testCases := []struct {
		name             string
		accounts         []string
		parent           string
		expectedAccounts []any
		expectedParent   any // value of association_condition.association.parent; nil means the field must be omitted
	}{
		{
			name:             "with parent nests the accounts under it",
			accounts:         []string{"proj101-base", "proj101-admin"},
			parent:           "proj101",
			expectedAccounts: []any{"proj101-base", "proj101-admin"},
			expectedParent:   "proj101",
		},
		{
			name:             "without parent keeps the account under root",
			accounts:         []string{"proj101"},
			parent:           "",
			expectedAccounts: []any{"proj101"},
			expectedParent:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			resp, err := svc.CreateAccountAssociation(context.Background(), tc.accounts, nil, tc.parent)
			require.NoError(t, err)
			assert.Equal(t, []string{"proj101-base"}, resp.AddedAccounts)

			cond, ok := gotBody["association_condition"].(map[string]any)
			require.True(t, ok, "request must contain association_condition")
			assert.Equal(t, tc.expectedAccounts, cond["accounts"])

			assoc, ok := cond["association"].(map[string]any)
			require.True(t, ok, "request must contain association_condition.association")
			assert.Equal(t, tc.expectedParent, assoc["parent"])
		})
	}
}
