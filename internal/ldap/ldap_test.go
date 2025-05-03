package ldap

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.uber.org/zap"
	"os"
	"testing"
	"time"
)

var client *Client

func TestMain(m *testing.M) {
	logger, _ := zap.NewDevelopment()
	pool, err := dockertest.NewPool("")
	if err != nil {
		logger.Fatal("Could not connect to docker", zap.Error(err))
	}
	pool.MaxWait = 120 * time.Second

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "osixia/openldap",
		Tag:        "1.5.0",
		Env: []string{
			"LDAP_ORGANISATION=Clustron",
			"LDAP_DOMAIN=clustron.prj.internal.sdc.nycu.club",
			"LDAP_ADMIN_PASSWORD=admin",
		},
		Mounts: []string{
			"/Users/yichen/GolandProjects/clustron-backend/internal/ldap/testdata/openssh-lpk.ldif:/container/service/slapd/assets/config/bootstrap/ldif/50-openssh-lpk.ldif",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	if err != nil {
		logger.Fatal("Could not start resource", zap.Error(err))
	}

	port := resource.GetPort("389/tcp")
	fmt.Println("LDAP is listening on", port)

	err = pool.Retry(func() error {
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%s", port))
		if err != nil {
			return err
		}
		defer func(conn *ldap.Conn) {
			err := conn.Close()
			if err != nil {
				logger.Warn("Failed to close LDAP connection", zap.Error(err))
			}
		}(conn)
		return conn.Bind("cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club", "admin")
	})
	if err != nil {
		logger.Fatal("Failed to connect to LDAP server", zap.Error(err))
	}

	cfg := &Config{
		LDAPHost:    "localhost",
		LDAPPort:    port,
		LDAPBaseDN:  "dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindDN:  "cn=admin,dc=clustron,dc=prj,dc=internal,dc=sdc,dc=nycu,dc=club",
		LDAPBindPwd: "admin",
	}

	client, err = NewClient(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create LDAP client", zap.Error(err))
	}

	if err := setupBaseDIT(client.Conn, cfg.LDAPBaseDN); err != nil {
		logger.Fatal("Failed to setup base DIT", zap.Error(err))
	}

	code := m.Run()

	// Explicitly purge the container before exit
	if purgeErr := pool.Purge(resource); purgeErr != nil {
		logger.Warn("Failed to purge resource", zap.Error(purgeErr))
	}

	os.Exit(code)
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
