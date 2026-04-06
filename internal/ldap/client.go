package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

//go:generate mockery --name=LDAPClient
type LDAPClient interface {
	CreateGroup(groupName, gidNumber string, memberUids []string) error
	DeleteGroup(groupName string) error
	AddUserToGroup(groupName, memberUid string) error
	CreateUser(uid, cn, sn, sshPublicKey, uidNumber string) error
	DeleteUser(uid string) error
	AddSSHPublicKey(uid, publicKey string) error
	DeleteSSHPublicKey(uid string, publicKey string) error
	GetUserInfo(uid string) (*ldap.Entry, error)
	GetGroupInfo(groupName string) (*ldap.Entry, error)
	RemoveUserFromGroup(groupName, memberUid string) error
	ExistSSHPublicKey(publicKey string) (bool, error)
	GetAllUIDNumbers() ([]string, error)
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

func (c *Client) userBaseDN() string {
	if strings.TrimSpace(c.Config.LDAPUserDN) != "" {
		return c.Config.LDAPUserDN
	}

	return "ou=People," + c.Config.LDAPBaseDN
}

func (c *Client) groupBaseDN() string {
	if strings.TrimSpace(c.Config.LDAPGroupDN) != "" {
		return c.Config.LDAPGroupDN
	}

	return "ou=Groups," + c.Config.LDAPBaseDN
}

func (c *Client) Validate() error {
	// Check if base DN exists
	searchRequest := ldap.NewSearchRequest(
		c.Config.LDAPBaseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	sr, err := c.Conn.Search(searchRequest)
	if err != nil {
		c.Logger.Error("Failed to search LDAP base DN", zap.Error(err))
		return fmt.Errorf("failed to search LDAP base DN: %w", err)
	}
	if len(sr.Entries) == 0 {
		c.Logger.Error("Base DN does not exist in LDAP", zap.String("baseDN", c.Config.LDAPBaseDN))
		return fmt.Errorf("base DN does not exist in LDAP: %s", c.Config.LDAPBaseDN)
	}

	searchPeopleOURequest := ldap.NewSearchRequest(
		c.userBaseDN(),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	sr, err = c.Conn.Search(searchPeopleOURequest)
	if err != nil {
		c.Logger.Error("Failed to search for LDAP user DN", zap.String("userDN", c.userBaseDN()), zap.Error(err))
		return fmt.Errorf("failed to search for LDAP user DN: %w", err)
	}
	if len(sr.Entries) == 0 {
		c.Logger.Error("LDAP user DN does not exist in LDAP", zap.String("userDN", c.userBaseDN()))
		return fmt.Errorf("LDAP user DN does not exist in LDAP: %s", c.userBaseDN())
	}

	searchGroupsOURequest := ldap.NewSearchRequest(
		c.groupBaseDN(),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	sr, err = c.Conn.Search(searchGroupsOURequest)
	if err != nil {
		c.Logger.Error("Failed to search for LDAP group DN", zap.String("groupDN", c.groupBaseDN()), zap.Error(err))
		return fmt.Errorf("failed to search for LDAP group DN: %w", err)
	}
	if len(sr.Entries) == 0 {
		c.Logger.Error("LDAP group DN does not exist in LDAP", zap.String("groupDN", c.groupBaseDN()))
		return fmt.Errorf("LDAP group DN does not exist in LDAP: %s", c.groupBaseDN())
	}

	c.Logger.Info("LDAP structure validated successfully")
	return nil
}
