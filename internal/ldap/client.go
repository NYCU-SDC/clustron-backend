package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

type LDAPClient interface {
	CreateGroup(groupName, gidNumber string, memberUids []string) error
	AddUserToGroup(groupName, memberUid string) error
	CreateUser(uid, cn, sn, sshPublicKey, uidNumber string) error
	AddSSHPublicKey(uid, publicKey string) error
	GetUserInfo(uid string) (*ldap.Entry, error)
	GetGroupInfo(groupName string) (*ldap.Entry, error)
}

type Client struct {
	Conn   *ldap.Conn
	Config *Config
	Logger *zap.Logger
}

func NewClient(cfg *Config, logger *zap.Logger) (*Client, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%s", cfg.LDAPHost, cfg.LDAPPort))
	if err != nil {
		logger.Error("Failed to connect to LDAP server", zap.Error(err))
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if err := conn.Bind(cfg.LDAPBindDN, cfg.LDAPBindPwd); err != nil {
		logger.Error("Failed to bind LDAP", zap.Error(err))
		return nil, fmt.Errorf("failed to bind LDAP: %w", err)
	}

	client := &Client{Conn: conn, Config: cfg, Logger: logger}
	if err := client.ClearAllPeopleAndGroups(); err != nil {
		logger.Error("Failed to clear all people and groups", zap.Error(err))
		return nil, fmt.Errorf("failed to clear all people and groups: %w", err)
	}

	logger.Info("LDAP connection established and bound successfully")
	return client, nil
}

func (c *Client) Close() {
	if err := c.Conn.Close(); err != nil {
		c.Logger.Warn("Failed to close LDAP connection", zap.Error(err))
	} else {
		c.Logger.Info("LDAP connection closed successfully")
	}
}

func (c *Client) ClearAllPeopleAndGroups() error {
	bases := []struct {
		ou     string
		baseDN string
	}{
		{"People", fmt.Sprintf("ou=People,%s", c.Config.LDAPBaseDN)},
		{"Groups", fmt.Sprintf("ou=Groups,%s", c.Config.LDAPBaseDN)},
	}
	for _, b := range bases {
		searchReq := ldap.NewSearchRequest(
			b.baseDN,
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)
		res, err := c.Conn.Search(searchReq)
		if err != nil {
			c.Logger.Error("LDAP search failed", zap.String("base", b.baseDN), zap.Error(err))
			return err
		}
		for _, entry := range res.Entries {
			// skip ou=People, ou=Groups itself
			if entry.DN == b.baseDN {
				continue
			}
			delReq := ldap.NewDelRequest(entry.DN, nil)
			if err := c.Conn.Del(delReq); err != nil {
				c.Logger.Warn("Failed to delete entry", zap.String("dn", entry.DN), zap.Error(err))
			}
		}
	}
	return nil
}
