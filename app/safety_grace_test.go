package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/safety"
)

// §6.5 (gate2 run 2, through the tunnel): a task an earlier agentd left in the queue is taken up at once by the new
// one, which hasn't had the operator's list delivered yet (heard since it started: never). The kill switch's first
// sweep cancelled it stop_list_stale, seconds before the list landed, so every task that survived an agentd restart
// with an operator key pinned ended cancelled. Now, within firstHeard of the process's start, staleness alone
// doesn't cancel (a stop still does, at once); once the window passes unheard, it does.
func TestKillSwitchFirstHeardGraceForResumedTasks(t *testing.T) {
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	cfg := func() safety.Config {
		return safety.Config{Firm: "f_chat", Operator: operator.Public().(ed25519.PublicKey),
			Admins: []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}, Release: guard.ReleasePolicy("f_chat", ""),
			Dir: dir, PersonalSpaces: true, MaxSilence: safety.DefaultMaxSilence}
	}
	sign := func(kind string, v any, k ed25519.PrivateKey) safety.Envelope {
		b, _ := jsonv2.Marshal(v)
		return safety.Sign(kind, b, k)
	}
	seq := uint64(0)
	heartbeat := func(stop []string) safety.Envelope {
		seq++
		now := time.Now().UTC()
		l := &safety.StopList{Type: safety.StopType, Issuer: safety.IssuerOperator, Seq: seq, IssuedAt: now,
			ExpiresAt: now.Add(5 * time.Minute)}
		for _, sp := range stop {
			l.Stop = append(l.Stop, safety.Target{Firm: "f_chat", Space: sp})
		}
		return sign(safety.KindStop, l, operator)
	}
	// The earlier agentd: a policy and a heartbeat taken (the policy is kept on disk, as across a restart).
	st0, err := safety.NewState(cfg())
	if err != nil {
		t.Fatal(err)
	}
	p := guard.ReleasePolicy("f_chat", "")
	p.Version, p.IssuedAt = 1, time.Now().UTC()
	if errs, _ := st0.Apply([]safety.Envelope{sign(safety.KindPolicy, p, admin), heartbeat(nil)}); errs[0] != nil || errs[1] != nil {
		t.Fatalf("setup: %v", errs)
	}
	const space = "s_resumed"
	var runIn func(t *testing.T, dir string, window time.Duration, during func(st *safety.State)) map[string]time.Duration
	run := func(t *testing.T, window time.Duration, during func(st *safety.State)) map[string]time.Duration {
		return runIn(t, dir, window, during)
	}
	runOn := func(t *testing.T, d string, window time.Duration) map[string]time.Duration {
		return runIn(t, d, window, nil)
	}
	runIn = func(t *testing.T, d string, window time.Duration, during func(st *safety.State)) (cancelled map[string]time.Duration) {
		c := cfg()
		c.Dir = d
		st, err := safety.NewState(c) // the restarted agentd: the policy from disk, the list not heard
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Check(space, false); err == nil {
			t.Fatal("a fresh process with nothing heard must be blocked")
		}
		g := newSafeGateway(nil, st, &safety.Ledger{})
		g.firstHeard = window
		var mu sync.Mutex
		cancelled = map[string]time.Duration{}
		g.cancel = func(id, reason string) {
			mu.Lock()
			if _, ok := cancelled[id]; !ok {
				cancelled[id] = time.Since(g.started)
			}
			mu.Unlock()
		}
		g.tasks["task-resumed"] = &safeTask{space: space} // resumeTasks opens it before the first sweep
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go g.enforce(ctx, 20*time.Millisecond)
		if during != nil {
			during(st)
		}
		time.Sleep(window + 300*time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return cancelled
	}
	t.Run("list delivered within the window: not cancelled", func(t *testing.T) {
		c := run(t, 800*time.Millisecond, func(st *safety.State) {
			time.Sleep(300 * time.Millisecond)
			if errs, _ := st.Apply([]safety.Envelope{heartbeat(nil)}); errs[0] != nil {
				t.Fatal(errs[0])
			}
		})
		if d, ok := c["task-resumed"]; ok {
			t.Fatalf("the resumed task was cancelled %s after the start, before the window ended", d)
		}
	})
	t.Run("never delivered: cancelled once the window ends", func(t *testing.T) {
		c := run(t, 400*time.Millisecond, nil)
		d, ok := c["task-resumed"]
		if !ok || d < 400*time.Millisecond {
			t.Fatalf("cancelled %v at %s, want after the 400 ms window", ok, d)
		}
	})
	t.Run("a stop restored from disk cancels at once, in the window", func(t *testing.T) {
		// The stop is the earlier agentd's (on disk), so this process has heard nothing: still in the window.
		if errs, _ := st0.Apply([]safety.Envelope{heartbeat([]string{space})}); errs[0] != nil {
			t.Fatal(errs[0])
		}
		defer st0.Apply([]safety.Envelope{heartbeat(nil)}) // the next subtests' disk: nothing stopped
		c := run(t, 2*time.Second, nil)
		if d, ok := c["task-resumed"]; !ok || d > 200*time.Millisecond {
			t.Fatalf("a stopped space's task: cancelled %v at %s, want at once", ok, d)
		}
	})
	t.Run("a missing policy cancels at once, in the window", func(t *testing.T) {
		c := runOn(t, t.TempDir(), 2*time.Second) // no policy on this disk
		if d, ok := c["task-resumed"]; !ok || d > 200*time.Millisecond {
			t.Fatalf("no policy: cancelled %v at %s, want at once", ok, d)
		}
	})
	t.Run("calls wait in the window, go on once heard, are refused when it ends", func(t *testing.T) {
		st, err := safety.NewState(cfg())
		if err != nil {
			t.Fatal(err)
		}
		g := newSafeGateway(nil, st, &safety.Ledger{})
		g.firstHeard = 600 * time.Millisecond
		go func() {
			time.Sleep(250 * time.Millisecond)
			st.Apply([]safety.Envelope{heartbeat(nil)})
		}()
		t0 := time.Now()
		g.waitHeardAtStart(context.Background())
		if d := time.Since(t0); d < 200*time.Millisecond || d > 550*time.Millisecond || !st.Heard() {
			t.Fatalf("waited %s (heard %v), want until the delivery at 250 ms", d, st.Heard())
		}
		// Unheard to the end: the call waits out the window, then Check refuses it before the inner gateway (nil
		// here: a call through it would panic).
		st2, _ := safety.NewState(cfg())
		g2 := newSafeGateway(nil, st2, &safety.Ledger{})
		g2.firstHeard = 300 * time.Millisecond
		t1 := time.Now()
		_, err = g2.ModelCall(context.Background(), &harness.TaskInfo{ID: "t", Start: &harness.Start{Space: space}}, &harness.ModelCall{Model: "m"})
		if d := time.Since(t1); err == nil || !strings.Contains(err.Error(), safety.CodeStale) || d < 250*time.Millisecond {
			t.Fatalf("unheard: %v after %s, want stop_list_stale after the window", err, d)
		}
		// A cancelled context ends the wait.
		g3 := newSafeGateway(nil, st2, &safety.Ledger{})
		g3.firstHeard = 5 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		t2 := time.Now()
		g3.waitHeardAtStart(ctx)
		if d := time.Since(t2); d > time.Second {
			t.Fatalf("the wait ignored its context: %s", d)
		}
	})
	t.Run("no operator key: no window", func(t *testing.T) {
		c := cfg()
		c.Operator, c.Dir = nil, t.TempDir()
		st, err := safety.NewState(c)
		if err != nil {
			t.Fatal(err)
		}
		g := newSafeGateway(nil, st, &safety.Ledger{})
		g.firstHeard = time.Minute
		if g.inGrace() {
			t.Fatal("in the window without an operator key")
		}
	})
}
