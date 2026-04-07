package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Validate(t *testing.T) {
	tests := []struct {
		name           string
		userDN         string
		groupDN        string
		overrideUserDN string
		wantErr        bool
		errContains    string
	}{
		{
			name: "Should validate default People and Groups DNs",
		},
		{
			name:    "Should validate configured user and group DNs",
			userDN:  "ou=ClustronUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
			groupDN: "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		},
		{
			name:           "Should return error when configured user DN does not exist",
			groupDN:        "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
			overrideUserDN: "ou=MissingUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
			wantErr:        true,
			errContains:    "failed to search for LDAP user DN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClientWithDNs(t, tc.userDN, tc.groupDN)
			defer done()

			if tc.overrideUserDN != "" {
				client.Config.LDAPUserDN = tc.overrideUserDN
			}

			err := client.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestClient_UsesConfiguredUserAndGroupDNs(t *testing.T) {
	tests := []struct {
		name    string
		userDN  string
		groupDN string
	}{
		{
			name:    "Should store users and groups under configured DNs",
			userDN:  "ou=ClustronUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
			groupDN: "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, done := newTestClientWithDNs(t, tc.userDN, tc.groupDN)
			defer done()

			setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
			setupGroup(t, client, groupName, gidNumber, []string{user1})

			userEntry, err := client.GetUserInfo(user1)
			require.NoError(t, err)
			assert.Equal(t, "uid="+user1+","+tc.userDN, userEntry.DN)

			groupEntry, err := client.GetGroupInfo(groupName)
			require.NoError(t, err)
			assert.Equal(t, "cn="+groupName+","+tc.groupDN, groupEntry.DN)

			rawUserEntry, err := client.Conn.Search(ldap.NewSearchRequest(
				tc.userDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(uid="+user1+")",
				[]string{"dn"},
				nil,
			))
			require.NoError(t, err)
			require.Len(t, rawUserEntry.Entries, 1)

			rawGroupEntry, err := client.Conn.Search(ldap.NewSearchRequest(
				tc.groupDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(cn="+groupName+")",
				[]string{"dn"},
				nil,
			))
			require.NoError(t, err)
			require.Len(t, rawGroupEntry.Entries, 1)
		})
	}
}
