package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// hostStub is a platform as the provider runs it: a name and an app id it reports. It gives evidence only; the
// Platform interface has nothing to derive a key from (TestPlatformGivesNoKeys).
type hostStub struct{ app string }

func (p hostStub) Name() string         { return "dstack" }
func (p hostStub) Secret(string) string { return "" }
func (p hostStub) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	info, _ := json.Marshal(map[string]string{"app_id": p.app})
	return json.RawMessage(`"quote"`), info, nil
}

// aBoot is one agentd boot as main makes it on the quick path: its state in memory (newAgentState), its keys from a
// KeySource (bootKeys until the Tacy key service), its own EHBP identity, the working directory, TMPDIR and HOME in
// a fresh directory (the CVM's disk).
type aBoot struct {
	dir    string
	keys   KeySource
	s      *server
	cancel context.CancelFunc
}

func bootOn(t *testing.T, p Platform, keys KeySource, model http.Handler) *aBoot {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"cwd", "tmp", "home"} {
		os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	t.Chdir(filepath.Join(dir, "cwd"))
	t.Setenv("TMPDIR", filepath.Join(dir, "tmp"))
	t.Setenv("HOME", filepath.Join(dir, "home"))
	srv := httptest.NewServer(model)
	t.Cleanup(func() {
		if m, ok := model.(*stepModel); ok {
			m.unblock()
		}
		srv.Close()
	})
	lim := defaultLimits
	g := guard.New(guard.Config{Up: guard.NewPlainUpstream(srv.URL, srv.Client()), Search: &fakeSearch{}, Fetcher: guard.NewFetcher(true),
		Limits: &lim, CacheSecret: "boot-secret", Now: func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }})
	st := newAgentState()
	rt := newRuntime(g, st.queue, lim)
	ids, err := rt.Restore()
	if err != nil || len(ids) != 0 {
		t.Fatalf("a fresh boot restored %v (%v): nothing may carry over", ids, err)
	}
	idKey, err := keys.Key(context.Background(), PurposeTaskIDs)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ehbpidentity.NewIdentity()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &server{platform: p, id: id, agent: g, rt: rt, booted: time.Now(), sched: newScheduler(lim), lim: lim,
		quotes: make(chan struct{}, 4), host: &guard.Host{RT: rt, GW: g, IDKey: idKey}}
	go localBrain(ctx, rt)
	return &aBoot{dir: dir, keys: keys, s: s, cancel: cancel}
}

// TestProviderChangeTwoBoots (the keys plan drill 7.3 and 7.4, locally): the provider changes everything it derives for us
// between two boots (another app id, a fresh empty disk, a new process; and in the drill, its KMS root and OS). The
// second boot must work with nothing from the first: no state read back, no file left on either disk, and a task
// that was running on the first is visibly gone on the second (404, which the app shows as "The agent server
// restarted; this task stopped. Try again.") rather than hanging. Until the Tacy key service, each boot also has its
// own lasting keys (bootKeys); with it, the same keys (twoboot_test.go).
func TestProviderChangeTwoBoots(t *testing.T) {
	ctx := context.Background()
	m1 := newStepModel(t, "block") // the first boot's task is mid-model-call when its VM goes away
	b1 := bootOn(t, hostStub{app: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, newBootKeys(), m1)
	c1 := connTo(t, b1.s, tasksUser)
	tk, err := c1.StartTask(ctx, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("a question asked before the move")}, "")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m1, 1)
	if st := waitTask(t, c1, tk.Task, func(st *agentclient.Task) bool { return st.State == harness.StateRunning }); st.State != harness.StateRunning {
		t.Fatalf("first boot: %+v", st)
	}
	act1, _ := b1.keys.Key(ctx, PurposeActivity)
	ids1, _ := b1.keys.Key(ctx, PurposeTaskIDs)
	b1.cancel() // the VM goes away mid-task (a restart, a stop, a move to another host or app id)

	m2 := newStepModel(t, pText("an answer on the new boot"))
	b2 := bootOn(t, hostStub{app: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, newBootKeys(), m2)
	if b2.dir == b1.dir {
		t.Fatal("the second boot must start on an empty disk")
	}
	c2 := connTo(t, b2.s, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task)) // the tab that started it, asking the new boot

	// The task from before is gone, and says so at once.
	t0 := time.Now()
	_, err = c2.TaskStatus(ctx, tk.Task)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("the first boot's task on the second: %v (want 404)", err)
	}
	if time.Since(t0) > 5*time.Second {
		t.Fatalf("the lost task took %s to show", time.Since(t0))
	}

	// The second boot works on its own.
	tk2, err := c2.StartTask(ctx, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("a question after the move")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if tk2.Task == tk.Task {
		t.Fatal("the new boot gave the old task's id")
	}
	text := ""
	for _, e := range followAll(t, c2, tk2.Task, 0) {
		text += e.ev.Delta
	}
	if text != "an answer on the new boot" {
		t.Fatalf("second boot's answer %q", text)
	}

	// Nothing either boot kept is on a disk (the quick path keeps everything in memory).
	for i, b := range []*aBoot{b1, b2} {
		if n, problems := sealedTree(b.dir, [][]byte{[]byte("a question asked before the move"), []byte("an answer on the new boot")}); n != 0 || len(problems) > 0 {
			t.Errorf("boot %d left %d files: %v", i+1, n, problems)
		}
	}

	// The lasting keys. With the Tacy key service as the KeySource (TestTwoBootsDifferentProviderSameKeys: one key
	// service, two hosts) they are equal across boots; without one (the memory path, local runs) they never are.
	act2, _ := b2.keys.Key(ctx, PurposeActivity)
	ids2, _ := b2.keys.Key(ctx, PurposeTaskIDs)
	if bytes.Equal(act1, act2) || bytes.Equal(ids1, ids2) {
		t.Fatal("two boots without a key service share keys: they'd have come from somewhere that outlives a boot")
	}
}

// TestPlatformGivesNoKeys: the platform (the provider's side) can give agentd evidence and, for local development,
// secrets; nothing it offers derives a key (dstack GetKey is gone, the keys plan §3.5). A method added here that returns
// key material would let the provider's keys back in.
func TestPlatformGivesNoKeys(t *testing.T) {
	ty := reflect.TypeOf((*Platform)(nil)).Elem()
	var names []string
	for i := 0; i < ty.NumMethod(); i++ {
		names = append(names, ty.Method(i).Name)
	}
	if got := strings.Join(names, ","); got != "Evidence,Name,Secret" {
		t.Fatalf("Platform has %s: a new method must not hand out key material (the keys plan §3.5)", got)
	}
	if (&dstack{}).Secret("TINFOIL_API_KEY") != "" {
		t.Fatal("on dstack, secrets come only from the Tacy key service, never from the platform")
	}
}
