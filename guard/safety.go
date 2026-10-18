package guard

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

// The guard's side of step 6 (docs/23-safety-controls.md): before a model call or an action runs, the guard checks
// the signed controls it verified itself (Config.Safety): the space isn't stopped, a policy covers it, the model,
// connector and tool are allowed, and, when the stop list is stale, only reads go on (if the policy allows). Fetches
// (pages, images, site icons) go only to hosts the policy allows, checked on every request and redirect.

// ReleasePolicy is the release's ceiling and default policy for the chat agent (safety.ChatRelease) with every
// model this VM runs.
func ReleasePolicy(firm, tinfoilHost string) *safety.Policy {
	return safety.ChatRelease(firm, tinfoilHost, slices.Sorted(maps.Keys(models)), int64(RunTimeout/time.Second))
}

type maxTokensKey struct{}

// WithMaxTokens caps a model call's output at about n tokens (agentd's budget reservation for it): the guard
// counts what streams back and ends the call past the cap, whatever the upstream does. 0: no cap.
func WithMaxTokens(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, maxTokensKey{}, n)
}

// MaxTokensFrom is ctx's output cap (0: none).
func MaxTokensFrom(ctx context.Context) int64 {
	n, _ := ctx.Value(maxTokensKey{}).(int64)
	return n
}

type spaceKey struct{}

func withSpace(ctx context.Context, space string) context.Context {
	return context.WithValue(ctx, spaceKey{}, space)
}

// SpaceFrom is the space ctx's request belongs to ("" when none).
func SpaceFrom(ctx context.Context) string {
	s, _ := ctx.Value(spaceKey{}).(string)
	return s
}

// Effect: whether a request changes something outside (anything not replay-safe: never for today's connectors).
func Effect(req any) bool { return !ReplaySafe(req) }

// checkSafety is the guard's own check of a request; nil Safety: none (tests that predate step 6).
func (g *Guard) checkSafety(space string, req any) error {
	st := g.cfg.Safety
	if st == nil {
		return nil
	}
	e, err := st.Check(space, Effect(req))
	if err != nil {
		return harness.Errf(harness.CodeNotAllowed, "%s", err.Error())
	}
	switch b := req.(type) {
	case *harness.ModelCall:
		if !e.AllowsModel(b.Model) || !e.AllowsConnector("model") {
			return harness.Errf(harness.CodeNotAllowed, "%s: model %s isn't allowed by the policy", safety.CodePolicyDenied, b.Model)
		}
	case *harness.Action:
		if !e.AllowsTool(b.Name) {
			why := "isn't allowed by the policy"
			if e.NeedsApproval(b.Name) {
				why = "needs approval, which isn't available yet"
			}
			return &policyDenial{msg: safety.CodePolicyDenied + ": " + b.Name + " " + why}
		}
	}
	return nil
}

// policyDenial is an action the policy refuses: a normal outcome the model sees (status denied), not a failure.
type policyDenial struct{ msg string }

func (p *policyDenial) Error() string { return p.msg }

func deniedResult(err error) (*harness.ActionResult, bool) {
	var p *policyDenial
	if errors.As(err, &p) {
		return &harness.ActionResult{Status: harness.ActionDenied, Error: p.msg}, true
	}
	return nil, false
}

// ---- fetch hosts ------------------------------------------------------------------------------------------------

type hostFilterKey struct{}

// withHostFilter makes every fetch under ctx (redirects too) check its host with allow.
func withHostFilter(ctx context.Context, allow func(host string) bool) context.Context {
	return context.WithValue(ctx, hostFilterKey{}, allow)
}

// fetchFilter is the live policy check for a space's fetches (a narrower policy applies at once).
func (g *Guard) fetchFilter(space string) func(string) bool {
	st := g.cfg.Safety
	return func(host string) bool {
		e, err := st.Check(space, false)
		return err == nil && e.AllowsFetch(host)
	}
}

var errHostPolicy = errors.New("host refused by the policy")

// policyTransport refuses a request whose host the context's filter doesn't allow, before any connection.
type policyTransport struct{ base http.RoundTripper }

func (p policyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if allow, ok := r.Context().Value(hostFilterKey{}).(func(string) bool); ok && !allow(strings.ToLower(r.URL.Hostname())) {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, errHostPolicy
	}
	return p.base.RoundTrip(r)
}

// withPolicyTransport is c with its requests checked against the context's host filter.
func withPolicyTransport(c *http.Client) *http.Client {
	if c == nil {
		return nil
	}
	if _, ok := c.Transport.(policyTransport); ok {
		return c
	}
	cc := *c
	base := cc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cc.Transport = policyTransport{base}
	return &cc
}

// ToolAction is the action a chat tool name runs ("" for none).
func ToolAction(tool string) string { return webAction(tool) }

// AllTools are the chat's tool names (a request without tools gets them all).
func AllTools() []string { return slices.Clone(allTools) }

// leaseError says why the vault refused a key when a safety control did ("<code>: …", which agentd shows people
// with the code); any other refusal is fallback (the vault's rule stays in its record).
func leaseError(err error, fallback string) error {
	switch {
	case errors.Is(err, vault.ErrRateLimited):
		return errors.New(safety.CodeRateLimited + ": a key's lease rate is used up for now; try again in a minute")
	case errors.Is(err, vault.ErrStopped):
		return errors.New(safety.CodeStopped + ": the vault refuses keys for this space (stopped)")
	case errors.Is(err, vault.ErrStale):
		return errors.New(safety.CodeStale + ": the vault has no fresh stop list")
	case errors.Is(err, vault.ErrPolicyMissing):
		return errors.New(safety.CodePolicyMissing + ": the vault has no signed policy for this space")
	case errors.Is(err, vault.ErrPolicy):
		return errors.New(safety.CodePolicyDenied + ": the policy doesn't allow this key's connector or host")
	}
	return errors.New(fallback)
}
