package slurm

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
