package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/moby/moby/api/types/container"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()

	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	pool, err := dockertest.NewPool(ctx, "")
	require.NoError(t, err)

	resource, err := pool.Run(ctx, "osixia/openldap",
		dockertest.WithTag("1.5.0"),
		dockertest.WithEnv([]string{
			"LDAP_ORGANISATION=Clustron",
			"LDAP_DOMAIN=clustron.prj.internal.sdc.nycu.club",
			"LDAP_ADMIN_PASSWORD=admin",
		}),
		dockertest.WithHostConfig(func(config *container.HostConfig) {
			config.AutoRemove = true
			config.RestartPolicy = container.RestartPolicy{Name: "no"}
		}),
	)
	require.NoError(t, err)
	require.NoError(t, waitForLDAPReady(ctx, pool, resource, 30*time.Second))

	t.Cleanup(func() {
		logger.Info("cleaning up test resources")
		if err := resource.Close(ctx); err != nil {
			logger.Error("failed to close resource", zap.Error(err))
		}
		if err := pool.Close(ctx); err != nil {
			logger.Error("failed to close pool", zap.Error(err))
		}
	})

	port := resource.GetPort("389/tcp")
	logger.Info("Starting LDAP connection check...", zap.String("port", port))
	require.NoError(t, pool.Retry(ctx, 60*time.Second, func() error {
		logger.Info("Attempting Dial...")
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%s", port))
		if err != nil {
			return err
		}
		defer func(conn *ldap.Conn) {
			_ = conn.Close()
		}(conn)

		conn.SetTimeout(2 * time.Second)
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

	return client
}

func waitForLDAPReady(ctx context.Context, pool dockertest.ClosablePool, resource dockertest.Resource, timeout time.Duration) error {
	const readyStr = "slapd starting"

	return pool.Retry(ctx, timeout, func() error {
		stdout, stderr, err := resource.Logs(ctx)
		if err != nil {
			return fmt.Errorf("failed to get logs: %w", err)
		}

		if strings.Contains(stdout, readyStr) || strings.Contains(stderr, readyStr) {
			return nil
		}

		return errors.New("slapd not ready yet")
	})
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
