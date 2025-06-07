package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

const (
	StartUidNumber = 10000
	StartGidNumber = 10000
)

type Client struct {
	Conn    *ldap.Conn
	Config  *Config
	Logger  *zap.Logger
	Queries *Queries
}

func NewClient(cfg *Config, logger *zap.Logger, queries *Queries) (*Client, error) {
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
	return &Client{Conn: conn, Config: cfg, Logger: logger, Queries: queries}, nil
}

func (c *Client) Close() {
	if err := c.Conn.Close(); err != nil {
		c.Logger.Warn("Failed to close LDAP connection", zap.Error(err))
	} else {
		c.Logger.Info("LDAP connection closed successfully")
	}
}

func (c *Client) GetAvailableUidNumber(ctx context.Context) (int32, error) {
	used, err := c.Queries.GetAllUidNumbers(ctx)
	if err != nil {
		return 0, err
	}
	// Start from 10000
	next := StartUidNumber
	usedSet := make(map[int32]struct{}, len(used))
	for _, n := range used {
		usedSet[int32(n)] = struct{}{}
	}
	for {
		if _, ok := usedSet[int32(next)]; !ok {
			return int32(next), nil
		}
		next++
	}
}

func (c *Client) GetAvailableGidNumber(ctx context.Context) (int32, error) {
	used, err := c.Queries.GetAllGidNumbers(ctx)
	if err != nil {
		return 0, err
	}
	// Start from 10000
	next := StartGidNumber
	usedSet := make(map[int32]struct{}, len(used))
	for _, n := range used {
		usedSet[int32(n)] = struct{}{}
	}
	for {
		if _, ok := usedSet[int32(next)]; !ok {
			return int32(next), nil
		}
		next++
	}
}

func (c *Client) InsertUidNumber(ctx context.Context, number int32) error {
	err := c.Queries.InsertUidNumber(ctx, number)
	if err != nil {
		c.Logger.Error("Failed to insert uid number", zap.Error(err))
		return fmt.Errorf("failed to insert uid number: %w", err)
	}
	return nil
}

func (c *Client) InsertGidNumber(ctx context.Context, number int32) error {
	err := c.Queries.InsertGidNumber(ctx, number)
	if err != nil {
		c.Logger.Error("Failed to insert gid number", zap.Error(err))
		return fmt.Errorf("failed to insert gid number: %w", err)
	}
	return nil
}
