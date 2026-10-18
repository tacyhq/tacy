package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runner/runnertest"
)

// This tree's side of parity_test.go: the server as main builds it (guard, runtime, in-process brain), on the
// scenario's model, search and web.

type SearchResult = guard.SearchResult
type ImageCandidate = guard.ImageCandidate

// modelTool is the name the model calls an app tool by: the action's (docs/20). Events keep the app name.
func modelTool(app string) string {
	switch app {
	case "fetch_page":
		return "web_fetch"
	case "image_search":
		return "web_images"
	}
	return app
}

// parityModes: the guard in this process; the gateway split's layout: agentd's gateway client talking
// gateway/v0 to a gatewayd server over a real unix socket; and the CVM's layout since v0.4.0: that, with the brain in
// a sandbox that a runnerd starts (runner/v0, its harness socket passed in), in real gVisor when TACY_RUNSC and
// TACY_BRAIN_BIN are set (runnertest), else in the fake sandbox. The events must be the same every way.
var parityModes = []string{"in-process", "gatewayd", "gatewayd+runner"}

func parityServer(t *testing.T, mode string, model *httptest.Server, ps guard.SearchProvider, web http.RoundTripper) *server {
	s, _ := parityServerEnv(t, mode, model, ps, web)
	return s
}

func parityServerEnv(t *testing.T, mode string, model *httptest.Server, ps guard.SearchProvider, web http.RoundTripper) (*server, *runnertest.Env) {
	lim := defaultLimits
	client := &http.Client{Transport: web}
	now := func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	g := guard.New(guard.Config{Up: guard.NewPlainUpstream(model.URL, model.Client()), Search: ps, Fetcher: client, Icons: client,
		Limits: &lim, CacheSecret: "boot-secret", Now: now})
	var gw guard.Gateway = g
	if strings.HasPrefix(mode, "gatewayd") {
		gw = startGatewayd(t, g, now)
	}
	rt := newRuntime(gw, harness.NewMemStore(), lim)
	ctx, cancel := context.WithCancel(context.Background())
	var env *runnertest.Env
	if strings.HasSuffix(mode, "+runner") {
		env = runnertest.Start(t)
		t.Logf("brain sandbox: %s", env.Kind)
		go runBrains(ctx, rt, env.Client)
	} else {
		go localBrain(ctx, rt)
	}
	t.Cleanup(cancel) // before runnertest's cleanup: the brains stop first
	return &server{platform: local{}, agent: gw, rt: rt, sched: newScheduler(lim), lim: lim, quotes: make(chan struct{}, 4)}, env
}

// startGatewayd serves g as gatewayd does, on a unix socket, and returns agentd's client for it.
func startGatewayd(t *testing.T, g *guard.Guard, now func() time.Time) *gateway.Client {
	dir, err := os.MkdirTemp("", "gw") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "gateway.sock")
	l, err := gateway.Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&gateway.Server{G: g}).Serve(l, -1)
	return &gateway.Client{Path: path, Now: now}
}
