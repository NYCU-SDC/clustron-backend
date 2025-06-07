package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

type Client struct {
	Conn   *ldap.Conn
	Config *Config
	Logger *zap.Logger
}

func NewClient(cfg *Config, logger *zap.Logger) (*Client, error) {
	logger.Info("LDAP config", zap.Any("config", cfg))
	logger.Info("LDAP host", zap.String("host", cfg.LDAPHost))
	logger.Info("LDAP port", zap.String("port", cfg.LDAPPort))
	logger.Info("LDAP base DN", zap.String("base_dn", cfg.LDAPBaseDN))
	logger.Info("LDAP bind DN", zap.String("bind_dn", cfg.LDAPBindDN))
	logger.Info("LDAP bind pwd", zap.String("bind_pwd", cfg.LDAPBindPwd))

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%s", cfg.LDAPHost, cfg.LDAPPort))
	if err != nil {
		logger.Error("Failed to connect to LDAP server", zap.Error(err))
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if err := conn.Bind(cfg.LDAPBindDN, cfg.LDAPBindPwd); err != nil {
		logger.Error("Failed to bind LDAP", zap.Error(err))
		return nil, fmt.Errorf("failed to bind LDAP: %w", err)
	}

	logger.Info("LDAP connection established and bound successfully")
	return &Client{Conn: conn, Config: cfg, Logger: logger}, nil
}

func (c *Client) Close() {
	if err := c.Conn.Close(); err != nil {
		c.Logger.Warn("Failed to close LDAP connection", zap.Error(err))
	} else {
		c.Logger.Info("LDAP connection closed successfully")
	}
}
