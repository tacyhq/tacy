package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"net/http"
	"net/http/httptest"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/leakscan"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/trigger"
	"github.com/tacyhq/tacy/vault"
)

// SealMagic is what every file agentd, gatewayd or vaultd may leave on a disk starts with (the keys plan §3.2, sealstate).
// The quick path leaves none at all.
const sealMagic = "TACYSEAL1"

// TestNothingPlaintextOnDisk (the keys plan §9.1) runs the quick path's state (agentState, the stores main makes) and the
// key push through scenarios carrying canaries (a person's question and the model's answer, an approval's effect,
// a schedule's instructions and memory, the API keys and the relay token), with the working directory, TMPDIR and
// HOME in a fresh directory. Afterwards every file under it must start with TACYSEAL1 and hold no canary in any
// encoding leakscan decodes; in the quick path there must be no file at all.
func TestNothingPlaintextOnDisk(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"cwd", "tmp", "home"} {
		os.MkdirAll(filepath.Join(root, d), 0o700)
	}
	t.Chdir(filepath.Join(root, "cwd"))
	t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
	t.Setenv("HOME", filepath.Join(root, "home"))

	canaries := map[string]string{
		"question":     "canary-question-7c1f4e2a my private medical question",
		"answer":       "canary-answer-9d3b5a17 the model's private answer",
		"effect":       "canary-effect-1a2b3c4d send this to my lawyer",
		"instructions": "canary-instructions-5e6f7a8b summarize my inbox every day",
		"memory":       "canary-memory-0f9e8d7c what the schedule remembered",
	}
	for k, v := range testKeys {
		canaries[k] = v
	}

	kept := newAgentState()

	// 1. A run over EHBP, in a relay envelope, through a server on the quick path's queue: the question in, the
	// answer out.
	a, _, _ := newTestAgent(t, textSSE(canaries["answer"]))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	s.rt.Store = kept.queue
	srv := runServer(t, s, id)
	conn, _ := agentclient.New(srv, testRelaySeed, id.MarshalPublicKey())
	var text string
	if err := conn.Run(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(),
		Messages: []proto.Message{{Role: "user", Content: canaries["question"]}}}, func(e proto.Event) { text += e.Delta }); err != nil ||
		text != canaries["answer"] {
		t.Fatalf("run: %v %q", err, text)
	}

	// 2. Activity records of a run, on the quick path's store.
	signer, _ := activity.DeriveSigner(bytes.Repeat([]byte{7}, 32), "f_chat")
	rec := &activity.Recorder{Signer: signer, Store: kept.activity}
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := rec.Begin(activity.Start{Run: "r1", Space: "s_canary", To: activity.RecipientString(seal.PublicKey()),
		Agent: activity.Agent{ID: canaries["instructions"]}, Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Finish("r1", activity.End{Status: activity.Status{State: "done"}}); err != nil {
		t.Fatal(err)
	}

	// 3. An approval held with its effect, and a schedule's memory, on the quick path's side stores.
	if _, _, err := kept.side.PutApproval(approval.Record{ID: "ap_1", Firm: "f_chat", Space: "s_canary", Task: "t1", Request: "q1",
		Action: "mail.send", Effect: []byte(`{"body":"` + canaries["effect"] + `"}`), EffectHash: "h", ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(), State: approval.StateHeld}); err != nil {
		t.Fatal(err)
	}
	if err := kept.side.PutMemory(trigger.Remembered{Task: "t1", Space: "s_canary", Agent: "a1", Day: "2026-11-20",
		EndedAt: time.Now(), Text: canaries["memory"]}); err != nil {
		t.Fatal(err)
	}
	kept.notify.Set("s_canary", true)

	// 4. The API keys, as vaultd takes them from the key service's release (memory only).
	v, _ := vault.New(nil, vault.ChatGrants(""), nil)
	if _, err := v.SetSecrets(testKeys); err != nil {
		t.Fatal(err)
	}

	var exact [][]byte
	for _, v := range canaries {
		exact = append(exact, []byte(v))
	}
	files, problems := sealedTree(root, exact)
	for _, p := range problems {
		t.Error(p)
	}
	if files != 0 {
		t.Errorf("the quick path left %d files (it keeps everything in memory)", files)
	}
}

// sealedTree checks every file under root: it starts with TACYSEAL1 and holds no exact value in any encoding. It
// returns how many files there are and what's wrong.
func sealedTree(root string, exact [][]byte) (int, []string) {
	files := 0
	var problems []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if !bytes.HasPrefix(b, []byte(sealMagic)) {
			problems = append(problems, fmt.Sprintf("%s doesn't start with %s", p, sealMagic))
		}
		for _, f := range leakscan.ScanWith(b, exact) {
			if f.Pattern == leakscan.ExactSecret {
				problems = append(problems, fmt.Sprintf("%s holds a canary at %d (via %q)", p, f.Offset, f.Via))
			}
		}
		return nil
	})
	return files, problems
}

// The sealed configuration (the keys plan Stage C/D) on sealstate's file backend: the same canaries through the stores
// that are kept (schedules' memory and results, activity, notifications, budgets) and vaultd's connections (an
// email app password), saved by their keepers. Every file is TACYSEAL1 and holds no canary in any encoding.
func TestNothingPlaintextOnDiskSealed(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("TMPDIR", root)
	ctx := context.Background()
	canaries := [][]byte{[]byte("canary-memory-0f9e8d7c"), []byte("canary-result-3c4d5e6f"), []byte("canary-app-password-xyz"),
		[]byte("s_canary_space"), []byte("me@canary.example")}
	b, err := bootState(ctx, newStubKMS(3), &sealstate.File{Dir: filepath.Join(root, "state")}, nil, "f_chat")
	if err != nil {
		t.Fatal(err)
	}
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	to := activity.RecipientString(seal.PublicKey())
	now := time.Now().UTC()
	side := b.kept.side
	side.PutMemory(trigger.Remembered{Space: "s_canary_space", Agent: "a1", Task: "t1", Day: "2026-11-20", EndedAt: now, Text: string(canaries[0])})
	side.PutResult(trigger.Result{Task: "t1", Space: "s_canary_space", Seal: to, Agent: "a1", Version: 1, Trigger: "daily", Day: "2026-11-20",
		ScheduledAt: now, StartedAt: now, EndedAt: now, State: "done", Enc: []byte("e"), CT: canaries[1]})
	b.rec.Begin(activity.Start{Run: "r1", Space: "s_canary_space", To: to, Started: now})
	b.rec.Finish("r1", activity.End{Status: activity.Status{State: "succeeded"}})
	b.kept.notify.Set("s_canary_space", true)
	if err := b.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// vaultd's connections under the conn/v1 key.
	ck, _ := newStubKMS(3).Key(ctx, "conn/v1")
	p, k, err := vault.SealedConns(ctx, &sealstate.File{Dir: filepath.Join(root, "vault")}, ck, "lease-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := vault.New(nil, vault.ChatGrants(""), nil)
	v.EnableConns(p)
	box, _ := vault.SealConn(v.SealKey(), "s_canary_space", vault.ConnEmail, []byte(`{"type":"`+vault.EmailType+
		`","provider":"other","host":"imap.canary.example","port":993,"security":"tls","address":"me@canary.example","username":"me@canary.example","password":"`+
		string(canaries[2])+`"}`))
	pid, _, err := v.ConnPut("s_canary_space", vault.ConnEmail, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ConnCommit(pid); err != nil {
		t.Fatal(err)
	}
	if err := k.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	files, problems := sealedTree(root, canaries)
	for _, p := range problems {
		t.Error(p)
	}
	if files != 4 { // side, activity, notify (budget and safety unchanged), connections
		t.Errorf("only %d sealed files", files)
	}
}

// The CVM's sealed mode (-kms-key, -state relay; vaultd -kms-key) against a real key service and the Worker's
// sealed-state API, through gatewayd's fixed calls: the same canaries (a schedule's memory and result, an activity
// record, a notification switch, an email app password, the API keys from the secrets bundle) leave no file at all
// under the working directory, TMPDIR or HOME, and everything the Worker holds starts with TACYSEAL1 and holds no
// canary in any encoding.
func TestNothingPlaintextOnDiskSealedRelay(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"cwd", "tmp", "home"} {
		os.MkdirAll(filepath.Join(root, d), 0o700)
	}
	t.Chdir(filepath.Join(root, "cwd"))
	t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	ctx := context.Background()
	w := newKMSWorld(t)
	canaries := [][]byte{[]byte("canary-memory-0f9e8d7c"), []byte("canary-result-3c4d5e6f"), []byte(testIMAPPassword),
		[]byte("s_canary_space"), []byte("me@canary.example"), []byte("canary-instructions-5e6f7a8b")}
	for _, v := range testKeys {
		canaries = append(canaries, []byte(v))
	}
	b, _ := w.bootAgent(t, "inst-1")
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	to := activity.RecipientString(seal.PublicKey())
	now := time.Now().UTC()
	side := b.kept.side
	side.PutMemory(trigger.Remembered{Space: "s_canary_space", Agent: "a1", Task: "t1", Day: "2026-11-20", EndedAt: now, Text: string(canaries[0])})
	side.PutResult(trigger.Result{Task: "t1", Space: "s_canary_space", Seal: to, Agent: "a1", Version: 1, Trigger: "daily", Day: "2026-11-20",
		ScheduledAt: now, StartedAt: now, EndedAt: now, State: "done", Enc: []byte("e"), CT: canaries[1]})
	b.rec.Begin(activity.Start{Run: "r1", Space: "s_canary_space", To: to, Agent: activity.Agent{ID: string(canaries[5])}, Started: now})
	b.rec.Finish("r1", activity.End{Status: activity.Status{State: "succeeded"}})
	b.kept.notify.Set("s_canary_space", true)
	if err := b.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	v, keeper, _ := w.bootVault(t, "inst-1")
	if len(v.Names()) != 3 {
		t.Fatalf("vaultd's API keys from the key service: %v", v.Names())
	}
	putTestConn(t, v, "s_canary_space")
	if err := keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if files, problems := sealedTree(root, canaries); files != 0 || len(problems) != 0 {
		t.Errorf("the sealed VM left %d files on the disk: %v", files, problems)
	}
	held := w.state.Blobs()
	if len(held) != 4 { // side, activity, notify (budget and safety unchanged), connections
		t.Errorf("the Worker holds %d states", len(held))
	}
	for k, blob := range held {
		if !bytes.HasPrefix(blob, []byte(sealMagic)) {
			t.Errorf("%s isn't sealed", k)
		}
		for _, f := range leakscan.ScanWith(blob, canaries) {
			if f.Pattern == leakscan.ExactSecret {
				t.Errorf("%s holds a canary at %d (via %q)", k, f.Offset, f.Via)
			}
		}
	}
}

// The check itself finds a plaintext file, a sealed-looking one with a canary inside, and a base64'd canary.
func TestSealedTreeFinds(t *testing.T) {
	dir := t.TempDir()
	c := []byte("canary-0123456789abcdef")
	os.WriteFile(filepath.Join(dir, "plain"), append([]byte("x"), c...), 0o600)
	os.WriteFile(filepath.Join(dir, "magic"), append([]byte(sealMagic), c...), 0o600)
	os.WriteFile(filepath.Join(dir, "b64"), []byte(sealMagic+base64.StdEncoding.EncodeToString(c)), 0o600)
	os.WriteFile(filepath.Join(dir, "ok"), []byte(sealMagic+"ciphertext"), 0o600)
	n, problems := sealedTree(dir, [][]byte{c})
	bad := map[string]bool{}
	for _, p := range problems {
		bad[filepath.Base(strings.Fields(p)[0])] = true
	}
	if n != 4 || len(bad) != 3 || bad["ok"] || !bad["plain"] || !bad["magic"] || !bad["b64"] {
		t.Fatalf("%d files, problems %q", n, problems)
	}
}

// runServer serves /attest and /run for s behind the relay's front door, as main does.
func runServer(t *testing.T, s *server, id *ehbpidentity.Identity) string {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	srv := httptest.NewServer(s.relayed(mux))
	t.Cleanup(srv.Close)
	return srv.URL
}
