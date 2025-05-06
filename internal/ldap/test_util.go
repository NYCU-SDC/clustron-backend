package ldap

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
	"time"
)

func newTestClient(t *testing.T) (*Client, func()) {
	t.Helper()

	logger := zap.NewNop()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	pool.MaxWait = 120 * time.Second

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "1.5.0",
		Env: []string{
			"LDAP_ORGANISATION=Clustron",
			"LDAP_DOMAIN=clustron.prj.internal.sdc.nycu.club",
			"LDAP_ADMIN_PASSWORD=admin",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	require.NoError(t, err)

	cleanup := func() { _ = pool.Purge(resource) }

	port := resource.GetPort("389/tcp")
	require.NoError(t, pool.Retry(func() error {
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%s", port))
		if err != nil {
			return err
		}
		defer func(conn *ldap.Conn) {
			_ = conn.Close()
		}(conn)
		return conn.Bind("cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club", "admin")
	}))

	cfg := &Config{
		LDAPHost:    "localhost",
		LDAPPort:    port,
		LDAPBaseDN:  "dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindDN:  "cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindPwd: "admin",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	require.NoError(t, setupBaseDIT(client.Conn, cfg.LDAPBaseDN))

	return client, cleanup
}

func setupBaseDIT(c *ldap.Conn, baseDN string) error {
	orgUnits := []string{"People", "Groups"}

	for _, ou := range orgUnits {
		req := ldap.NewAddRequest(fmt.Sprintf("ou=%s,%s", ou, baseDN), nil)
		req.Attribute("objectClass", []string{"organizationalUnit"})
		req.Attribute("ou", []string{ou})

		err := c.Add(req)
		if err != nil {
			var ldapErr *ldap.Error
			if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultEntryAlreadyExists {
				continue
			}
			return fmt.Errorf("failed to create ou=%s: %w", ou, err)
		}
	}
	return nil
}

func setupUser(t *testing.T, c *Client, uid, cn, sn, key, uidNumber string) {
	t.Helper()
	require.NoError(t, c.CreateUser(uid, cn, sn, key, uidNumber))
}

func setupGroup(t *testing.T, c *Client, groupName, gidNumber string, members []string) {
	t.Helper()
	require.NoError(t, c.CreateGroup(groupName, gidNumber, members))
}
