package ldap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

const (
	// dialTimeout bounds establishing the TCP connection. go-ldap defaults to
	// 60s, which is far too long to make a request wait on an unreachable
	// server before the reconnect can give up and back off.
	dialTimeout = 5 * time.Second
	// requestTimeout bounds a single LDAP operation. go-ldap applies no
	// request timeout by default, so a server that accepts the connection but
	// never answers would block the caller forever.
	requestTimeout = 10 * time.Second

	// reconnectMinBackoff is how long the first failed reconnect suppresses
	// the next dial for; every further failure doubles it up to
	// reconnectMaxBackoff. While suppressed, requests fail immediately instead
	// of queueing behind a dial that is not going to succeed.
	reconnectMinBackoff = 500 * time.Millisecond
	reconnectMaxBackoff = 30 * time.Second
)

type Client struct {
	// mu guards conn, generation and closed. The connection is swapped out by
	// reconnect, so every access to conn must go through withConn.
	mu   sync.RWMutex
	conn *ldap.Conn
	// generation counts how many times conn has been replaced. A caller that
	// hits a dead connection reports the generation it saw, which lets
	// reconnect tell "the connection is still broken" apart from "another
	// goroutine already replaced it".
	generation uint64
	// closed is set by Close and is never cleared: a client shut down on
	// purpose must not be revived by a reconnect.
	closed bool
	// reconnectMu serializes reconnect attempts so that a burst of failing
	// requests results in a single dial instead of one dial per request. It
	// also guards the backoff state below.
	reconnectMu sync.Mutex
	// backoff is the current suppression window, 0 while the server is
	// healthy. nextAttempt is when dialing is allowed again and lastDialErr is
	// the failure that caused the wait, reported to whoever is turned away.
	backoff     time.Duration
	nextAttempt time.Time
	lastDialErr error

	Config      *Config
	Logger      *zap.Logger
	LDAPUserDN  string
	LDAPGroupDN string
}

// withConn runs fn against the current LDAP connection, reconnecting and
// retrying once if the connection turned out to be dead.
//
// The connection pointer is read under the lock but fn runs after the lock is
// released: *ldap.Conn multiplexes concurrent requests internally, so several
// goroutines can share one connection, and holding the lock for the duration
// of fn would let a single stuck request block every reconnect.
func (c *Client) withConn(fn func(conn *ldap.Conn) error) error {
	conn, generation, err := c.currentConn()
	if err != nil {
		return err
	}

	err = fn(conn)
	if err == nil || !isConnectionError(conn, err) {
		return err
	}

	c.Logger.Warn("LDAP connection lost, reconnecting", zap.Error(err))

	conn, reconnectErr := c.reconnect(generation)
	if reconnectErr != nil {
		return errors.Join(err, reconnectErr)
	}

	return fn(conn)
}

// currentConn returns the connection to use and the generation it belongs to.
func (c *Client) currentConn() (*ldap.Conn, uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		c.Logger.Error("LDAP connection is not established")
		return nil, 0, ErrConnNotEstablished
	}

	return c.conn, c.generation, nil
}

// reconnect replaces the connection that staleGeneration refers to and returns
// the connection to retry on. If another goroutine already reconnected, its
// connection is returned instead and no new one is dialed.
func (c *Client) reconnect(staleGeneration uint64) (*ldap.Conn, error) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.mu.RLock()
	conn, generation, closed := c.conn, c.generation, c.closed
	c.mu.RUnlock()

	if closed {
		return nil, ErrConnNotEstablished
	}
	if generation != staleGeneration && conn != nil {
		c.Logger.Debug("LDAP connection already re-established by another request")
		return conn, nil
	}

	if wait := time.Until(c.nextAttempt); wait > 0 {
		c.Logger.Debug("Skipping LDAP reconnect while backing off", zap.Duration("retryIn", wait))
		return nil, fmt.Errorf("%w, retrying in %s: %w", ErrReconnectBackoff, wait.Truncate(time.Millisecond), c.lastDialErr)
	}

	newConn, err := dialAndBind(c.Config, c.Logger)
	if err != nil {
		c.backoff = nextBackoff(c.backoff)
		c.nextAttempt = time.Now().Add(c.backoff)
		c.lastDialErr = err
		c.Logger.Error("Failed to re-establish LDAP connection",
			zap.Duration("retryIn", c.backoff), zap.Error(err))
		return nil, err
	}

	c.backoff = 0
	c.nextAttempt = time.Time{}
	c.lastDialErr = nil

	c.mu.Lock()
	// Close raced us to it; drop the connection we just made rather than
	// resurrecting a client that was deliberately shut down.
	if c.closed {
		c.mu.Unlock()
		_ = newConn.Close()
		return nil, ErrConnNotEstablished
	}
	oldConn := c.conn
	c.conn = newConn
	c.generation++
	generation = c.generation
	c.mu.Unlock()

	// Releases the socket if the old connection was only half dead. Closing an
	// already closed connection is a no-op.
	if oldConn != nil {
		_ = oldConn.Close()
	}

	c.Logger.Info("LDAP connection re-established", zap.Uint64("generation", generation))
	return newConn, nil
}

// nextBackoff doubles the suppression window, capped at reconnectMaxBackoff.
func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return reconnectMinBackoff
	}

	next := current * 2
	if next > reconnectMaxBackoff {
		return reconnectMaxBackoff
	}

	return next
}

// isConnectionError reports whether err means the connection is unusable and
// the request should be retried on a fresh one, rather than a response from
// the server that the caller has to handle.
func isConnectionError(conn *ldap.Conn, err error) bool {
	if err == nil {
		return false
	}

	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return true
	}

	// When the server drops the connection while a request is in flight,
	// go-ldap hands the reader's raw error to the waiting caller instead of an
	// *ldap.Error, but it marks the connection as closing on the way out.
	return conn.IsClosing()
}

func dialAndBind(cfg *Config, logger *zap.Logger) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(
		fmt.Sprintf("ldap://%s:%s", cfg.LDAPHost, cfg.LDAPPort),
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
	)
	if err != nil {
		logger.Error("Failed to connect to LDAP server", zap.Error(err))
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Set before binding so that the bind is bounded by it too.
	conn.SetTimeout(requestTimeout)

	if err := conn.Bind(cfg.LDAPBindDN, cfg.LDAPBindPwd); err != nil {
		_ = conn.Close()
		logger.Error("Failed to bind LDAP", zap.Error(err))
		return nil, fmt.Errorf("failed to bind LDAP: %w", err)
	}

	return conn, nil
}

func NewClient(cfg *Config, logger *zap.Logger) (*Client, error) {
	conn, err := dialAndBind(cfg, logger)
	if err != nil {
		return nil, err
	}

	client := &Client{
		conn:        conn,
		Config:      cfg,
		Logger:      logger,
		LDAPUserDN:  fmt.Sprintf("ou=%s,%s", cfg.LDAPUserOUName, cfg.LDAPBaseDN),
		LDAPGroupDN: fmt.Sprintf("ou=%s,%s", cfg.LDAPGroupOUName, cfg.LDAPBaseDN),
	}

	logger.Info("LDAP connection established and bound successfully")
	return client, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.closed = true
	c.mu.Unlock()

	if conn == nil {
		return
	}

	if err := conn.Close(); err != nil {
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

	var sr *ldap.SearchResult
	err := c.withConn(func(conn *ldap.Conn) error {
		var err error
		sr, err = conn.Search(searchRequest)
		return err
	})
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
	err = c.withConn(func(conn *ldap.Conn) error {
		var err error
		sr, err = conn.Search(searchPeopleOURequest)
		return err
	})
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
	err = c.withConn(func(conn *ldap.Conn) error {
		var err error
		sr, err = conn.Search(searchGroupsOURequest)
		return err
	})
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
