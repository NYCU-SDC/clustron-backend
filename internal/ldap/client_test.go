package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Validate(t *testing.T) {
	t.Run("Should validate default People and Groups DNs", func(t *testing.T) {
		client, done := newTestClient(t)
		defer done()

		require.NoError(t, client.Validate())
	})

	t.Run("Should validate configured user and group DNs", func(t *testing.T) {
		userDN := "ou=ClustronUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"
		groupDN := "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"

		client, done := newTestClientWithDNs(t, userDN, groupDN)
		defer done()

		require.NoError(t, client.Validate())
	})

	t.Run("Should return error when configured user DN does not exist", func(t *testing.T) {
		userDN := "ou=MissingUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"
		groupDN := "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"

		client, done := newTestClientWithDNs(t, "", groupDN)
		defer done()

		client.Config.LDAPUserDN = userDN

		err := client.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to search for LDAP user DN")
	})
}

func TestClient_UsesConfiguredUserAndGroupDNs(t *testing.T) {
	userDN := "ou=ClustronUsers,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"
	groupDN := "ou=ClustronGroups,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club"

	client, done := newTestClientWithDNs(t, userDN, groupDN)
	defer done()

	setupUser(t, client, user1, "CN1", "SN1", "ssh-rsa AAAA1", "10001")
	setupGroup(t, client, groupName, gidNumber, []string{user1})

	userEntry, err := client.GetUserInfo(user1)
	require.NoError(t, err)
	assert.Equal(t, "uid="+user1+","+userDN, userEntry.DN)

	groupEntry, err := client.GetGroupInfo(groupName)
	require.NoError(t, err)
	assert.Equal(t, "cn="+groupName+","+groupDN, groupEntry.DN)

	rawUserEntry, err := client.Conn.Search(ldap.NewSearchRequest(
		userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid="+user1+")",
		[]string{"dn"},
		nil,
	))
	require.NoError(t, err)
	require.Len(t, rawUserEntry.Entries, 1)

	rawGroupEntry, err := client.Conn.Search(ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn="+groupName+")",
		[]string{"dn"},
		nil,
	))
	require.NoError(t, err)
	require.Len(t, rawGroupEntry.Entries, 1)
}
