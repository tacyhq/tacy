package main

import (
	"context"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// testAgent is what the server tests set about a run: the model (a fake upstream, swappable between runs), the
// search provider. The server they get runs /run as in the VM: this process's runtime and guard, and the brain
// over an in-memory connection (localBrain) instead of the socket.
type testAgent struct {
	mu sync.Mutex
	up guard.Upstream
	fs *fakeSearch
}

func (a *testAgent) use(up guard.Upstream) {
	a.mu.Lock()
	a.up = up
	a.mu.Unlock()
}

func (a *testAgent) cur() guard.Upstream {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.up
}

func (a *testAgent) Meta(ctx context.Context) (*proto.Meta, error) { return a.cur().Meta(ctx) }
func (a *testAgent) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	return a.cur().Stream(ctx, body)
}

func newTestAgent(t *testing.T, responses ...string) (*testAgent, *fakeModel, *fakeSearch) {
	fm := &fakeModel{responses: responses}
	srv := httptest.NewServer(fm)
	t.Cleanup(srv.Close)
	a := &testAgent{up: guard.NewPlainUpstream(srv.URL, srv.Client()), fs: &fakeSearch{}}
	return a, fm, a.fs
}

// newTestServer is a server as main makes it on -platform local without -brain-socket: an in-memory queue and an
// in-process brain.
func newTestServer(t *testing.T, a *testAgent, id *ehbpidentity.Identity, lim Limits) *server {
	g := guard.New(guard.Config{Up: a, Search: a.fs, Fetcher: guard.NewFetcher(true), Limits: &lim,
		CacheSecret: "boot-secret", Now: func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }})
	rt := newRuntime(g, harness.NewMemStore(), lim)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go localBrain(ctx, rt)
	return &server{platform: local{}, id: id, agent: g, rt: rt, token: "tok", booted: time.Now(), sched: newScheduler(lim),
		lim: lim, quotes: make(chan struct{}, 4)}
}
