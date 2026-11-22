package unlock_test

import (
	"bytes"
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/unlock"
	"github.com/tacyhq/tacy/vault"
)

// TestRunCredentialNotInUnlockCache (the v1 design §5.8): unlockd's cache in the host tmpfs (/run/tacy-unlock on the
// VM) holds vaultd's keys across container restarts, never a person's mail login. vaultd boots from unlockd as it
// does on the VM (its keys over the vault socket, its connections state under conn/v1), a task's login (the canary)
// goes through the whole v1 flow (put, lease, end), unlockd restarts from its cache, and then no file in the cache
// directory holds the canary in any form, and the cache wasn't rewritten by the flow.
func TestRunCredentialNotInUnlockCache(t *testing.T) {
	const canary = "canary-unlock-cache-pw-8d2e"
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(nil)
	r.run(u, 30*time.Second)
	dir, _ := os.MkdirTemp("/tmp", "tacy-ulc-")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "vault.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&unlock.Server{U: u, Evidence: r.w.VM.Evidence, Logf: t.Logf}).Serve(l, -1, unlock.RoleVault)
	ctx := context.Background()
	k, err := (&unlock.Client{Path: sock}).Wait(ctx, t.Logf, "conn/v1")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string][]byte {
		m := map[string][]byte{}
		filepath.WalkDir(r.cache.Dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				m[p], _ = os.ReadFile(p)
			}
			return nil
		})
		return m
	}
	before := snapshot()
	if len(before) == 0 {
		t.Fatal("unlockd cached nothing (the scan would prove nothing)")
	}
	// vaultd's boot, as cmd/vaultd fromUnlockd.
	v, err := vault.New(nil, vault.ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetSecrets(k.Secrets); err != nil {
		t.Fatal(err)
	}
	ck, err := k.Key(ctx, "conn/v1")
	if err != nil {
		t.Fatal(err)
	}
	p, keeper, err := vault.SealedConns(ctx, &sealstate.File{Dir: t.TempDir()}, ck, k.App, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(p); err != nil {
		t.Fatal(err)
	}
	// The task's login: put, leased, ended.
	exp := time.Now().Add(time.Hour).UnixMilli()
	kh := vault.KeyHash("start-1")
	box, err := vault.SealRunCred(v.SealKey(), "s_me", vault.ConnEmail, kh, exp, []byte(`{"type":"`+vault.MailLoginType+
		`","provider":"gmail","host":"imap.gmail.com","port":993,"security":"tls","address":"me@gmail.com","username":"me@gmail.com","password":"`+canary+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RunCredPut(vault.RunGrant{Task: "tk_1", Space: "s_me", Connection: vault.ConnEmail, KeyHash: kh, Expires: exp, Sealed: box}); err != nil {
		t.Fatal(err)
	}
	val, _, err := v.Lease(vault.Request{Secret: vault.ConnSecret, Connector: vault.MailConnector, Host: "imap.gmail.com", Task: "tk_1",
		Action: "s1.a0", Space: "s_me", Conn: vault.ConnEmail})
	if err != nil || string(val) != canary {
		t.Fatalf("lease: %v", err)
	}
	clear(val)
	v.RunCredEnd("tk_1")
	if err := keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// unlockd restarts from its cache (the hourly container restart).
	u2 := r.unlocker(nil)
	r.run(u2, 30*time.Second)
	after := snapshot()
	for path, b := range after {
		if bytes.Contains(b, []byte(canary)) || bytes.Contains(b, box.CT) {
			t.Errorf("%s holds the login", filepath.Base(path))
		}
		if old, ok := before[path]; ok && !bytes.Equal(old, b) {
			t.Errorf("%s was rewritten during the mail flow", filepath.Base(path))
		}
	}
}
