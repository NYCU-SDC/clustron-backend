package ldap

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// killConn closes the connection the client is currently holding without
// telling the client, which is what a restarted LDAP server or a dropped idle
// connection looks like from the client's side.
func killConn(t *testing.T, c *Client) {
	t.Helper()

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

func generationOf(c *Client) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.generation
}

func TestClient_WithConn_ReconnectsOnRead(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	killConn(t, client)

	entry, err := client.GetUserInfo(user)
	require.NoError(t, err)
	assert.Equal(t, user, entry.GetAttributeValue("uid"))
	assert.Equal(t, uint64(1), generationOf(client))
}

func TestClient_WithConn_ReconnectsOnWrite(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	killConn(t, client)

	require.NoError(t, client.UpdateUser(user, "newCn", "newSn"))
	assert.Equal(t, uint64(1), generationOf(client))

	entry, err := client.GetUserInfo(user)
	require.NoError(t, err)
	assert.Equal(t, "newCn", entry.GetAttributeValue("cn"))
}

func TestClient_WithConn_ReconnectsOnceUnderConcurrency(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	killConn(t, client)

	const callers = 10
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = client.GetUserInfo(user)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	// Every caller that raced on the dead connection must share the single
	// replacement instead of dialing one of its own.
	assert.Equal(t, uint64(1), generationOf(client))
}

func TestClient_WithConn_DoesNotReconnectAfterClose(t *testing.T) {
	client := newTestClient(t)
	client.Close()

	_, err := client.GetUserInfo(user)
	require.ErrorIs(t, err, ErrConnNotEstablished)
	assert.Equal(t, uint64(0), generationOf(client))
}

func TestClient_WithConn_DoesNotRetryServerErrors(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	// A live connection reporting a logical failure must be left alone: the
	// error belongs to the caller, not to the reconnect path.
	err := client.CreateUser(user, "cn", "sn", pubkey2, "99999")
	require.ErrorIs(t, err, ErrUserExists)
	assert.Equal(t, uint64(0), generationOf(client))
}

// closedPort returns a port nothing is listening on, so that dialing it fails
// immediately with "connection refused" instead of hanging.
func closedPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())

	return port
}

func TestClient_Reconnect_BacksOffWhileServerIsUnreachable(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	reachablePort := client.Config.LDAPPort
	client.Config.LDAPPort = closedPort(t)
	killConn(t, client)

	// The first request finds the connection dead and actually dials.
	_, err := client.GetUserInfo(user)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrReconnectBackoff)

	// Requests arriving inside the backoff window are turned away without
	// dialing, and still report what went wrong.
	start := time.Now()
	_, err = client.GetUserInfo(user)
	require.ErrorIs(t, err, ErrReconnectBackoff)
	assert.Less(t, time.Since(start), reconnectMinBackoff)
	assert.Equal(t, uint64(0), generationOf(client))

	// Once the server is reachable again and the window has passed, the next
	// request recovers on its own.
	client.Config.LDAPPort = reachablePort
	time.Sleep(reconnectMinBackoff)

	entry, err := client.GetUserInfo(user)
	require.NoError(t, err)
	assert.Equal(t, user, entry.GetAttributeValue("uid"))
	assert.Equal(t, uint64(1), generationOf(client))
}

func TestClient_Reconnect_ResetsBackoffAfterRecovery(t *testing.T) {
	client := newTestClient(t)
	setupUser(t, client, user, "cn", "sn", pubkey1, uidNumber)

	reachablePort := client.Config.LDAPPort
	client.Config.LDAPPort = closedPort(t)
	killConn(t, client)

	_, err := client.GetUserInfo(user)
	require.Error(t, err)

	client.Config.LDAPPort = reachablePort
	time.Sleep(reconnectMinBackoff)
	_, err = client.GetUserInfo(user)
	require.NoError(t, err)

	client.reconnectMu.Lock()
	backoff, nextAttempt, lastErr := client.backoff, client.nextAttempt, client.lastDialErr
	client.reconnectMu.Unlock()

	assert.Zero(t, backoff)
	assert.True(t, nextAttempt.IsZero())
	assert.NoError(t, lastErr)
}

func TestNextBackoff(t *testing.T) {
	tests := []struct {
		name     string
		current  time.Duration
		expected time.Duration
	}{
		{
			name:     "starts at the minimum",
			current:  0,
			expected: reconnectMinBackoff,
		},
		{
			name:     "doubles",
			current:  reconnectMinBackoff,
			expected: 2 * reconnectMinBackoff,
		},
		{
			name:     "caps at the maximum",
			current:  reconnectMaxBackoff,
			expected: reconnectMaxBackoff,
		},
		{
			name:     "does not overshoot the maximum",
			current:  reconnectMaxBackoff - time.Second,
			expected: reconnectMaxBackoff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, nextBackoff(tt.current))
		})
	}
}

func TestIsConnectionError(t *testing.T) {
	client := newTestClient(t)

	client.mu.RLock()
	conn := client.conn
	client.mu.RUnlock()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error is not a connection error",
			err:      nil,
			expected: false,
		},
		{
			name:     "network error is a connection error",
			err:      ldap.NewError(ldap.ErrorNetwork, assert.AnError),
			expected: true,
		},
		{
			name:     "wrapped network error is a connection error",
			err:      fmt.Errorf("failed to search user: %w", ldap.NewError(ldap.ErrorNetwork, assert.AnError)),
			expected: true,
		},
		{
			name:     "server side result code is not a connection error",
			err:      ldap.NewError(ldap.LDAPResultNoSuchObject, assert.AnError),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isConnectionError(conn, tt.err))
		})
	}

	// Once the connection is closing, go-ldap reports the reader's raw error
	// rather than an *ldap.Error, so the connection state is what identifies it.
	require.NoError(t, conn.Close())
	assert.True(t, isConnectionError(conn, assert.AnError))
	assert.False(t, isConnectionError(conn, nil))
}
