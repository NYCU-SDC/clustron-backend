package ansible

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/apenella/go-ansible/v2/pkg/adhoc"
	"github.com/apenella/go-ansible/v2/pkg/execute"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Health-check stage names, returned to the client so the UI can show which step failed.
const (
	stageReachable   = "reachable"
	stageHostKey     = "host_key"
	stageLogin       = "login"
	stageAnsiblePing = "ansible_ping"
	stageDone        = "done"
)

// Host-key trust states.
const (
	hostKeyNew     = "new"     // no trusted key supplied; client must confirm the fingerprint
	hostKeyChanged = "changed" // a trusted key was supplied but the live key differs
	hostKeyOK      = "ok"      // live key matches the supplied trusted key
	hostKeySkipped = "skipped" // ssh_config_host path; host key handled by Ansible/OpenSSH
)

const (
	defaultSSHPort        = "22"
	healthCheckDialTimout = 10 * time.Second
	ansiblePingTimeoutSec = 15
)

// HealthCheckParams carries the connection details entered in the "Add server" dialog. No
// server row exists yet when a health check runs, so these mirror the connection subset of
// CreateParams rather than referencing a stored server.
type HealthCheckParams struct {
	AnsibleName    string
	IPAddress      string
	SSHConfigHost  string
	SSHUser        string
	SSHKeyName     string
	TrustedHostKey string
}

// HealthCheckResult is the outcome of a (possibly partial) health check.
type HealthCheckResult struct {
	OK            bool
	Stage         string
	Reachable     bool
	HostKey       string // authorized-key form, e.g. "ssh-ed25519 AAAA..."
	Fingerprint   string // SHA256:...
	HostKeyStatus string
	LoginOK       bool
	AnsiblePingOK bool
	Detail        string
}

// HealthCheck validates that a server is reachable, that its host key is trusted, that the
// provided identity can log in, and that Ansible can run against it.
// Direct-IP nodes get the full Go pre-flight (dial, host-key scan, key login); nodes
// reached through an ssh_config_host alias skip the Go checks.
func (s *Service) HealthCheck(ctx context.Context, params HealthCheckParams) (HealthCheckResult, error) {
	traceCtx, span := s.tracer.Start(ctx, "HealthCheck")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if params.IPAddress == "" {
		// ssh_config_host alias: only the Ansible ping is meaningful here.
		return s.healthCheckAlias(traceCtx, logger, params)
	}
	return s.healthCheckDirectIP(traceCtx, logger, params)
}

func (s *Service) healthCheckDirectIP(ctx context.Context, logger *zap.Logger, params HealthCheckParams) (HealthCheckResult, error) {
	addr := net.JoinHostPort(params.IPAddress, defaultSSHPort)

	// Stage 1: reachability.
	rawConn, err := net.DialTimeout("tcp", addr, healthCheckDialTimout)
	if err != nil {
		return HealthCheckResult{Stage: stageReachable, Reachable: false,
			Detail: fmt.Sprintf("cannot reach %s: %v", addr, err)}, nil
	}

	// Stage 2: scan the live host key via the SSH handshake, without logging in.
	liveKey, err := scanHostKey(rawConn, addr)
	if err != nil {
		return HealthCheckResult{Stage: stageHostKey, Reachable: true,
			Detail: fmt.Sprintf("SSH handshake failed: %v", err)}, nil
	}
	hostKeyLine := marshalHostKey(liveKey)
	fingerprint := ssh.FingerprintSHA256(liveKey)

	if params.TrustedHostKey == "" {
		// First call: nothing to compare against. Ask the user to trust this key.
		return HealthCheckResult{Stage: stageHostKey, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyNew}, nil
	}
	matches, parseErr := sameHostKey(params.TrustedHostKey, liveKey)
	if parseErr != nil {
		return HealthCheckResult{Stage: stageHostKey, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyNew,
			Detail: fmt.Sprintf("could not parse trusted host key: %v", parseErr)}, nil
	}
	if !matches {
		return HealthCheckResult{Stage: stageHostKey, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyChanged}, nil
	}

	// Stage 3: login with the provided identity, pinned to the trusted host key.
	if params.SSHKeyName == "" {
		return HealthCheckResult{Stage: stageLogin, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyOK,
			Detail: "no ssh_key_name provided; cannot test login"}, nil
	}
	if err := testLogin(addr, params.SSHUser, params.SSHKeyName, liveKey); err != nil {
		return HealthCheckResult{Stage: stageLogin, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyOK,
			Detail: fmt.Sprintf("login as %q failed: %v", params.SSHUser, err)}, nil
	}

	// Stage 4: Ansible ping (verifies a usable Python interpreter and become/sudo).
	pingOK, detail := s.ansiblePing(ctx, logger, params, hostKeyLine)
	if !pingOK {
		return HealthCheckResult{Stage: stageAnsiblePing, Reachable: true, HostKey: hostKeyLine,
			Fingerprint: fingerprint, HostKeyStatus: hostKeyOK, LoginOK: true, Detail: detail}, nil
	}

	return HealthCheckResult{OK: true, Stage: stageDone, Reachable: true, HostKey: hostKeyLine,
		Fingerprint: fingerprint, HostKeyStatus: hostKeyOK, LoginOK: true, AnsiblePingOK: true}, nil
}

func (s *Service) healthCheckAlias(ctx context.Context, logger *zap.Logger, params HealthCheckParams) (HealthCheckResult, error) {
	pingOK, detail := s.ansiblePing(ctx, logger, params, "")
	if !pingOK {
		return HealthCheckResult{Stage: stageAnsiblePing, HostKeyStatus: hostKeySkipped, Detail: detail}, nil
	}
	return HealthCheckResult{OK: true, Stage: stageDone, Reachable: true, HostKeyStatus: hostKeySkipped,
		AnsiblePingOK: true}, nil
}

// scanHostKey completes an SSH handshake over an already-dialed TCP connection to capture the
// server's host key, then closes the connection. Authentication is expected to fail (we offer no
// credentials); the host-key callback fires during key exchange, before auth, so the key is
// captured regardless. rawConn is consumed (closed) by this call.
func scanHostKey(rawConn net.Conn, addr string) (ssh.PublicKey, error) {
	defer func() { _ = rawConn.Close() }()
	_ = rawConn.SetDeadline(time.Now().Add(healthCheckDialTimout))

	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "clustron-healthcheck",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return nil
		},
		Timeout: healthCheckDialTimout,
	}
	conn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if conn != nil {
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(ssh.Prohibited, "healthcheck")
			}
		}()
		_ = conn.Close()
	}
	if captured == nil {
		// Handshake failed before the host key was presented (not SSH, KEX mismatch, timeout).
		return nil, err
	}
	return captured, nil
}

// testLogin opens an authenticated SSH connection using the private key at ~/.ssh/<keyName>,
// pinning the host key to the one captured during the scan.
func testLogin(addr, user, keyName string, hostKey ssh.PublicKey) error {
	signer, err := loadSigner(keyName)
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         healthCheckDialTimout,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	// A successful Dial already proves authentication; opening a session additionally proves the
	// account can start a shell/exec, which Ansible will need.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("authenticated but could not open a session: %w", err)
	}
	_ = session.Close()
	return nil
}

// loadSigner reads a private key from the backend's ~/.ssh/<keyName>. This is the same location
// the Ansible inventory references via ansible_ssh_private_key_file, so a key mounted there works
// for both. In the container (running as root) this resolves to /root/.ssh/<keyName>.
func loadSigner(keyName string) (ssh.Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	path := filepath.Join(home, ".ssh", keyName)
	raw, err := os.ReadFile(path) //nolint:gosec // keyName is validated (max=255) and confined to ~/.ssh
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	return signer, nil
}

// ansiblePing runs `ansible -m ping -b` against a single host using an inline inventory. For a
// direct-IP host it writes a temporary known_hosts pinned to hostKeyLine and enforces it at the
// OpenSSH layer; for an alias it lets OpenSSH accept the key on first use (StrictHostKeyChecking
// accept-new) and resolve the connection via ~/.ssh/config.
func (s *Service) ansiblePing(ctx context.Context, logger *zap.Logger, params HealthCheckParams, hostKeyLine string) (bool, string) {
	target := params.IPAddress
	if target == "" {
		target = params.SSHConfigHost
	}

	sshCommonArgs := "-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
	var cleanup func()
	if params.IPAddress != "" && hostKeyLine != "" {
		knownHostsPath, remove, err := writeTempKnownHosts(params.IPAddress, hostKeyLine)
		if err != nil {
			return false, fmt.Sprintf("prepare known_hosts: %v", err)
		}
		cleanup = remove
		sshCommonArgs = fmt.Sprintf("-o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s", knownHostsPath)
	}
	if cleanup != nil {
		defer cleanup()
	}

	options := &adhoc.AnsibleAdhocOptions{
		Inventory:     target + ",", // trailing comma => inline host list
		ModuleName:    "ping",
		Become:        true,
		Connection:    "ssh",
		Timeout:       ansiblePingTimeoutSec,
		SSHCommonArgs: sshCommonArgs,
	}
	if params.SSHUser != "" {
		options.User = params.SSHUser
	}
	if params.IPAddress != "" && params.SSHKeyName != "" {
		if home, err := os.UserHomeDir(); err == nil {
			options.PrivateKey = filepath.Join(home, ".ssh", params.SSHKeyName)
		}
	}

	output := new(bytes.Buffer)
	exec := execute.NewDefaultExecute(
		execute.WithCmd(adhoc.NewAnsibleAdhocCmd(
			adhoc.WithPattern(target),
			adhoc.WithAdhocOptions(options),
		)),
		execute.WithWrite(output),
		execute.WithWriteError(output),
		execute.WithCmdRunDir(ExecuteFolder),
		// Enforce host keys at the OpenSSH layer (via SSHCommonArgs); disable Ansible's own
		// paramiko-level check so it never raises an interactive prompt.
		execute.WithEnvVars(map[string]string{"ANSIBLE_HOST_KEY_CHECKING": "False"}),
	)

	if err := exec.Execute(ctx); err != nil {
		logger.Warn("ansible ping failed", zap.String("target", target), zap.Error(err))
		return false, condensePingOutput(output.String())
	}
	return true, ""
}

// writeTempKnownHosts writes a one-line known_hosts file pinning addr to hostKeyLine and returns
// its path plus a cleanup func.
func writeTempKnownHosts(addr, hostKeyLine string) (string, func(), error) {
	f, err := os.CreateTemp("", "clustron-knownhosts-*")
	if err != nil {
		return "", nil, err
	}
	if _, err := fmt.Fprintf(f, "%s %s\n", addr, hostKeyLine); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// marshalHostKey renders a host key in authorized-key form without the trailing newline.
func marshalHostKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// sameHostKey reports whether trusted (authorized-key form) encodes the same key as live.
func sameHostKey(trusted string, live ssh.PublicKey) (bool, error) {
	tk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trusted))
	if err != nil {
		return false, err
	}
	return bytes.Equal(tk.Marshal(), live.Marshal()), nil
}

// condensePingOutput trims ansible adhoc output to the most useful trailing lines for display.
func condensePingOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return "ansible ping produced no output"
	}
	lines := strings.Split(output, "\n")
	const maxLines = 12
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
