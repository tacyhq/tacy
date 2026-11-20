package vault

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

var kmsSecrets = map[string]string{"TINFOIL_API_KEY": "tf-canary-0123456789", "EXA_API_KEY": "exa-canary-0123456789",
	"TAVILY_API_KEY": "tvly-canary-0123456789"}

// The key service's secrets (vaultd's release): granted names are taken and lease; until then nothing does.
func TestSetSecrets(t *testing.T) {
	v, err := New(nil, ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := Request{Secret: "EXA_API_KEY", Connector: "web", Host: "api.exa.ai", Task: "t", Action: "a"}
	if _, _, err := v.Lease(lease); err == nil {
		t.Fatal("a lease before the key service's secrets")
	}
	if st := v.SecretsStatus(); len(st.Names) != 0 {
		t.Fatalf("names before: %v", st.Names)
	}
	r, err := v.SetSecrets(kmsSecrets)
	if err != nil || len(r.Names) != 3 {
		t.Fatalf("set: %+v %v", r, err)
	}
	s, _, err := v.Lease(lease)
	if err != nil || string(s) != "exa-canary-0123456789" {
		t.Fatalf("lease: %v", err)
	}
	// A name no connector is granted, the connections' own secret, or an empty value: nothing is taken.
	for name, bad := range map[string]map[string]string{
		"ungranted": {"EXA_API_KEY": "new", "OTHER_KEY": "x"},
		"conn":      {ConnSecret: "x"},
		"empty":     {"EXA_API_KEY": ""},
	} {
		if _, err := v.SetSecrets(bad); err != ErrSecretsRefused {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s, _, _ := v.Lease(lease); string(s) != "exa-canary-0123456789" {
		t.Fatal("a refused set changed a key")
	}
}

// Over the socket only the status goes: no op sets or reads a secret.
func TestSecretsStatusWire(t *testing.T) {
	v, _ := New(nil, ChatGrants(""), nil)
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go v.Serve(l, -1)
	defer l.Close()
	c := &Client{Path: filepath.Join(dir, "v.sock")}
	ctx := context.Background()
	if a := c.Secrets(ctx, &SecretsCall{Op: "status"}); a.Error != "" || a.Secrets == nil || len(a.Secrets.Names) != 0 {
		t.Fatalf("status before: %+v", a)
	}
	v.SetSecrets(kmsSecrets)
	if a := c.Secrets(ctx, &SecretsCall{Op: "status"}); a.Secrets == nil || len(a.Secrets.Names) != 3 {
		t.Fatalf("status after: %+v", a)
	}
	for _, op := range []string{"key", "put", "get"} {
		if a := c.Secrets(ctx, &SecretsCall{Op: op}); a.Error == "" {
			t.Errorf("op %s answered", op)
		}
	}
	_ = os.Remove
}

// -conn-wipe (RELEASE-QUEUE): the old plaintext file and a save's temporaries go; a missing file is fine.
func TestWipeConnFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connections.json")
	os.WriteFile(path, []byte(`{"version":1,"connections":[{"password":"app-password-canary"}]}`), 0o600)
	os.WriteFile(filepath.Join(dir, ".connections-123"), []byte("app-password-canary"), 0o600)
	os.WriteFile(filepath.Join(dir, "other"), []byte("keep"), 0o600)
	n, err := WipeConnFile(path)
	if err != nil || n != 2 {
		t.Fatalf("wiped %d, %v", n, err)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 || es[0].Name() != "other" {
		t.Fatalf("left %v", es)
	}
	if n, err := WipeConnFile(path); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	// Connections stay off: a put is refused.
	v, _ := New(nil, ChatGrants(""), nil)
	if _, _, err := v.ConnPut("s_x", ConnEmail, Sealed{}); err != ErrNoConn {
		t.Fatalf("put with connections off: %v", err)
	}
}
