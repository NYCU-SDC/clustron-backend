package ldap

import (
	"fmt"

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
