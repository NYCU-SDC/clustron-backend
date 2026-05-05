package ldap

import (
	"bufio"
	"context"
	"errors"
	"fmt"

	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestClient(t *testing.T) (*Client, func()) {
	t.Helper()
	return newTestClientWithDNs(t, "", "")
}

func newTestClientWithDNs(t *testing.T, userDN, groupDN string) (*Client, func()) {
	t.Helper()

	logger, _ := zap.NewDevelopment()

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
	require.NoError(t, waitForLDAPReady(pool, resource, 30*time.Second))

	cleanup := func() {
		logger.Info("cleaning up test resources")

		err = pool.Purge(resource)
		if err != nil {
			logger.Error("failed to purge resource", zap.Error(err))
		}
	}

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
		LDAPUserDN:  userDN,
		LDAPGroupDN: groupDN,
		LDAPBindDN:  "cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindPwd: "admin",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	require.NoError(t, setupBaseDIT(client.Conn, client.userBaseDN(), client.groupBaseDN()))

	return client, cleanup
}

func waitForLDAPReady(pool *dockertest.Pool, resource *dockertest.Resource, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	const readyStr = "slapd starting"

	return pool.Retry(func() error {
		var logs strings.Builder

		err := pool.Client.Logs(docker.LogsOptions{
			Context:      ctx,
			Container:    resource.Container.ID,
			OutputStream: &logs,
			ErrorStream:  &logs,
			Stdout:       true,
			Stderr:       true,
			Timestamps:   false,
		})
		if err != nil {
			return fmt.Errorf("failed to get logs: %w", err)
		}

		scanner := bufio.NewScanner(strings.NewReader(logs.String()))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), readyStr) {
				return nil
			}
		}

		return errors.New("slapd not ready yet")
	})
}

func setupBaseDIT(c *ldap.Conn, dns ...string) error {
	for _, dn := range dns {
		req := ldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"organizationalUnit"})
		req.Attribute("ou", []string{extractRDNValue(dn, "ou")})

		err := c.Add(req)
		if err != nil {
			var ldapErr *ldap.Error
			if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultEntryAlreadyExists {
				continue
			}
			return fmt.Errorf("failed to create dn=%s: %w", dn, err)
		}
	}
	return nil
}

func extractRDNValue(dn, key string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return ""
	}

	rdnParts := strings.SplitN(parts[0], "=", 2)
	if len(rdnParts) != 2 {
		return ""
	}
	if !strings.EqualFold(strings.TrimSpace(rdnParts[0]), key) {
		return ""
	}

	return strings.TrimSpace(rdnParts[1])
}

func setupUser(t *testing.T, c *Client, uid, cn, sn, key, uidNumber string) {
	t.Helper()
	require.NoError(t, c.CreateUser(uid, cn, sn, key, uidNumber))
}

func setupGroup(t *testing.T, c *Client, groupName, gidNumber string, members []string) {
	t.Helper()
	require.NoError(t, c.CreateGroup(groupName, gidNumber, members))
}
