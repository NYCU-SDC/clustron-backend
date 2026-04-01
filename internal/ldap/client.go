package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

//mockery:generate: true
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
		fmt.Sprintf("ou=People,%s", c.Config.LDAPBaseDN),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		[]string{"dn"},
		nil,
	)
	sr, err = c.Conn.Search(searchPeopleOURequest)
	if err != nil {
		c.Logger.Error("Failed to search for People OU", zap.Error(err))
		return fmt.Errorf("failed to search for People OU: %w", err)
	}
	if len(sr.Entries) == 0 {
		c.Logger.Error("People OU does not exist in LDAP", zap.String("baseDN", c.Config.LDAPBaseDN))
		return fmt.Errorf("people OU does not exist in LDAP: %s", c.Config.LDAPBaseDN)
	}

	searchGroupsOURequest := ldap.NewSearchRequest(
		fmt.Sprintf("ou=Groups,%s", c.Config.LDAPBaseDN),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		[]string{"dn"},
		nil,
	)
	sr, err = c.Conn.Search(searchGroupsOURequest)
	if err != nil {
		c.Logger.Error("Failed to search for Groups OU", zap.Error(err))
		return fmt.Errorf("failed to search for Groups OU: %w", err)
	}
	if len(sr.Entries) == 0 {
		c.Logger.Error("Groups OU does not exist in LDAP", zap.String("baseDN", c.Config.LDAPBaseDN))
		return fmt.Errorf("groups OU does not exist in LDAP: %s", c.Config.LDAPBaseDN)
	}

	c.Logger.Info("LDAP structure validated successfully")
	return nil
}
