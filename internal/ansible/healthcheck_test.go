package ansible

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap ssh public key: %v", err)
	}
	return sshPub
}

func TestMarshalHostKey_NoTrailingNewline(t *testing.T) {
	line := marshalHostKey(newTestHostKey(t))
	if strings.HasSuffix(line, "\n") || strings.TrimSpace(line) != line {
		t.Fatalf("expected trimmed single line, got %q", line)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("expected ssh-ed25519 prefix, got %q", line)
	}
}

func TestSameHostKey(t *testing.T) {
	key := newTestHostKey(t)
	trusted := marshalHostKey(key)

	match, err := sameHostKey(trusted, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Fatal("expected identical keys to match")
	}

	other := newTestHostKey(t)
	match, err = sameHostKey(trusted, other)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Fatal("expected different keys not to match")
	}

	if _, err := sameHostKey("not-a-key", key); err == nil {
		t.Fatal("expected error for unparseable trusted key")
	}
}

func TestCondensePingOutput(t *testing.T) {
	if got := condensePingOutput("   "); got != "ansible ping produced no output" {
		t.Fatalf("empty output: got %q", got)
	}

	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("line\n")
	}
	got := condensePingOutput(sb.String())
	if n := strings.Count(got, "line"); n > 12 {
		t.Fatalf("expected at most 12 trailing lines, got %d", n)
	}
}
