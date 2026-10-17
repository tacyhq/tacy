package guard

import (
	"cmp"
	"context"
	"net"
	"net/http"
	"time"

	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// The tests moved here from app/ at the switchover (agent_test.go, images_test.go, favicons_test.go,
// limits_test.go) drove app/agent.go's loop through this surface: an Agent with these fields, Run, validate,
// systemPrompt and withUser. They keep it, but a run now goes the way it goes in the VM: the brain (../brain) over
// harness/v1 (an in-memory connection instead of the socket), the runtime engine with an in-memory queue, and this
// guard. Their assertions are app/'s, except where a decided difference shows (each marked "switchover:").

// Agent is the old loop's test surface.
type Agent struct {
	up          Upstream
	newTools    func() *Tools // its search and fetcher become the guard's
	cacheSecret string
	now         func() time.Time
	gates       *toolGates   // per-user and global tool caps (nil: none); shared when tests share it
	runTools    int          // tool calls at once within a run: the runtime's max_inflight, so the brain's parallelism
	icons       *http.Client // site icons; nil: none
}

// Run serves one validated request: a fresh guard, runtime and brain, then Guard.Run (POST /run as a task).
func (a *Agent) Run(ctx context.Context, r *proto.RunRequest, emit func(proto.Event) error) error {
	var search SearchProvider
	var fetcher *http.Client
	if a.newTools != nil {
		tl := a.newTools()
		search, fetcher = tl.search, tl.fetcher
	}
	g := New(Config{Up: a.up, Search: search, Fetcher: fetcher, Icons: a.icons, CacheSecret: a.cacheSecret, Now: a.now})
	g.gates = a.gates
	rt := &harness.Runtime{Guard: g, Store: harness.NewMemStore(),
		Limits: harness.Limits{MaxInflight: cmp.Or(a.runTools, DefaultLimits.RunTools)}}
	bctx, stop := context.WithCancel(context.Background())
	rc, bc := net.Pipe()
	stopped := make(chan struct{})
	go rt.Serve(bctx, rc)
	go func() {
		brain.Run(bctx, bc)
		close(stopped)
	}()
	defer func() { stop(); bc.Close(); <-stopped }()
	return g.Run(ctx, rt, userFrom(ctx), r, emit)
}

// validate is app/agent.go's request check: the guard's StartFor.
func validate(r *proto.RunRequest) error {
	_, _, err := New(Config{}).StartFor(r)
	return err
}

// systemPrompt is app/agent.go's prompt for app tool names: the task's instructions.
func systemPrompt(tools []string, now time.Time) string {
	var actions []string
	for _, t := range tools {
		actions = append(actions, webAction(t))
	}
	return chatInstructions(actions, now)
}

type userKey struct{}

func withUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

func userFrom(ctx context.Context) string {
	u, _ := ctx.Value(userKey{}).(string)
	return u
}
