package guard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/vault"
)

// Facts for the activity record: leases by name and decision (never the value), fetches by host and size, and
// policy refusals counted without a connection.
func TestFactsLeasesAndHosts(t *testing.T) {
	f := &Facts{}
	ctx := WithFacts(context.Background(), f)
	ok := RecordLeases(func(context.Context, string, string, string) (*vault.Secret, error) {
		return vault.NewSecret([]byte("sk-live-value"), "lease-1"), nil
	})
	no := RecordLeases(func(context.Context, string, string, string) (*vault.Secret, error) { return nil, vault.ErrRateLimited })
	if s, err := ok(ctx, "TAVILY_API_KEY", "web", "api.tavily.com"); err != nil || string(s.Bytes()) != "sk-live-value" {
		t.Fatal(err)
	}
	if _, err := no(ctx, "TAVILY_API_KEY", "web", "api.tavily.com"); !errors.Is(err, vault.ErrRateLimited) {
		t.Fatal(err)
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 1000)) }))
	defer page.Close()
	c := recordingClient(withPolicyTransport(NewFetcher(true)))
	res, err := c.Do(mustReq(t, withHostFilter(ctx, func(string) bool { return true }), page.URL+"/a"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if _, err := c.Do(mustReq(t, withHostFilter(ctx, func(string) bool { return false }), page.URL+"/b")); err == nil {
		t.Fatal("the policy didn't refuse")
	}
	d := f.Data()
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "sk-live-value") || strings.Contains(string(b), "/a") {
		t.Fatalf("facts hold a value or a path: %s", b)
	}
	if len(d.Leases) != 2 || d.Leases[0].Decision != "released" || d.Leases[0].Lease != "lease-1" || d.Leases[1].Decision != "denied" ||
		d.Leases[1].Reason != "rate_limited" {
		t.Fatalf("leases: %+v", d.Leases)
	}
	if len(d.Hosts) != 1 || d.Hosts[0].Host != "127.0.0.1" || d.Hosts[0].Requests != 1 || d.Hosts[0].Refused != 1 || d.Hosts[0].BytesIn != 1000 {
		t.Fatalf("hosts: %+v", d.Hosts)
	}
	// Merged on agentd's side, and nil collectors are no-ops.
	g := &Facts{}
	g.Merge(d)
	g.Merge(d)
	if gd := g.Data(); gd.Hosts[0].Requests != 2 || len(gd.Leases) != 4 {
		t.Fatalf("merge: %+v", gd)
	}
	var none *Facts
	none.Merge(d)
	none.host("x", 1, 0, 0, 0)
	if none.Ptr() != nil || (&Facts{}).Ptr() != nil {
		t.Fatal("empty facts aren't nil")
	}
}

func mustReq(t *testing.T, ctx context.Context, u string) *http.Request {
	r, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
