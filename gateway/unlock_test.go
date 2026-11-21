package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split/splitdev"
)

func devAdmin(d *splitdev.Dev) kms.AdminKeys {
	return kms.AdminKeys{Keys: []ed25519.PublicKey{d.AdminPub}, Threshold: 1}
}

func devPolicy(t *testing.T, urls ...string) (*splitdev.Dev, []byte) {
	t.Helper()
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i, u := range urls {
		d.Policy.Holders[i].URL = u
	}
	b, err := d.SignPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return d, b
}

// gatewayd's holder URLs come from the newest policy for the pinned KMS id, on our domain only.
func TestHolderURLs(t *testing.T) {
	d, b := devPolicy(t, "https://keys-cf.tacy.io", "https://keys-v.tacy.io/")
	urls, seq, err := HolderURLs(b, d.IDPub, devAdmin(d), "tacy.io", false)
	if err != nil || !slices.Equal(urls["cloudflare"], []string{"https://keys-cf.tacy.io"}) || !slices.Equal(urls["vercel"], []string{"https://keys-v.tacy.io"}) ||
		seq != d.Policy.Seq {
		t.Fatalf("%v %d %v", urls, seq, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := HolderURLs(b, other, devAdmin(d), "tacy.io", false); err == nil {
		t.Fatal("a policy for another KMS id")
	}
	otherAdmin, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := HolderURLs(b, d.IDPub, kms.AdminKeys{Keys: []ed25519.PublicKey{otherAdmin}, Threshold: 1}, "tacy.io", false); err == nil {
		t.Fatal("a policy not signed by the pinned admin keys")
	}
	for _, bad := range [][]string{{"https://keys.evil.example", "https://keys-v.tacy.io"}, {"https://keys-cf.tacy.io?x=1", "https://keys-v.tacy.io"},
		{"https://u@keys-cf.tacy.io", "https://keys-v.tacy.io"}, {"https://tacy.io.evil.example", "https://keys-v.tacy.io"}} {
		d, b := devPolicy(t, bad...)
		if _, _, err := HolderURLs(b, d.IDPub, devAdmin(d), "tacy.io", false); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if _, _, err := HolderURLs(b, d.IDPub, devAdmin(d), "", false); err == nil {
		t.Fatal("no domain pinned, in production mode")
	}
}

// A holder call names a holder; gatewayd sends it to that holder's URL from the policy, and nowhere else.
func TestUnlockTarget(t *testing.T) {
	var hits []string
	holder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer holder.Close()
	d, _ := devPolicy(t, "https://keys-cf.tacy.io", "https://keys-v.tacy.io")
	f, err := NewFixed(nil, "https://chat.tacy.test", true)
	if err != nil {
		t.Fatal(err)
	}
	u := f.NewUnlockHosts(d.IDPub, devAdmin(d), "")
	policies := 0
	u.Fetch = func(context.Context) ([]byte, error) {
		policies++
		return nil, errors.New("the Worker didn't answer") // an unknown holder reads the policy again: none here
	}
	// Route holder URLs to the test server through the table directly (HolderURLs is tested above).
	u.urls, u.at = map[string][]string{"cloudflare": {holder.URL}}, time.Now()
	a := f.Fixed(context.Background(), &FixedCall{Target: TargetUnlock, Holder: "cloudflare", Method: "GET", Path: "/v1/challenge"})
	if a.Error != "" || a.Status != 200 || len(hits) != 1 || hits[0] != "GET /v1/challenge" {
		t.Fatalf("%+v %v", a, hits)
	}
	for _, c := range []*FixedCall{
		{Target: TargetUnlock, Holder: "vercel", Method: "GET", Path: "/v1/challenge"},            // not in the table: refetch fails
		{Target: TargetUnlock, Holder: "cloudflare", Method: "POST", Path: "/v1/policy"},          // not a VM route
		{Target: TargetUnlock, Holder: "cloudflare", Method: "GET", Path: "/v1/challenge?host=x"}, // a query
		{Target: TargetUnlock, Holder: "Cloud Flare", Method: "GET", Path: "/v1/challenge"},       // not a holder id
		{Target: TargetState, Method: "GET", Path: "/api/vm/unlock-policy", Holder: "cloudflare"}, // a holder on the state target
		{Target: TargetState, Method: "POST", Path: "/api/vm/state/side"},                         // sealed state is GET/PUT
	} {
		if a := f.Fixed(context.Background(), c); a.Error == "" {
			t.Errorf("%+v went through", c)
		}
	}
	if len(hits) != 1 || policies == 0 {
		t.Fatalf("hits %v, policy fetches %d", hits, policies)
	}
	if !strings.HasPrefix(UnlockOp, "unlock/") {
		t.Fatal(UnlockOp)
	}
}

// -unlock-domain may name several domains (comma-separated), and each holder's alt_urls are on the list after its
// url, each checked against them: the production policy lists a second domain per holder (keys-cf.tacy.dev,
// <project>.vercel.app), and a staging policy names workers.dev and vercel.app hosts.
func TestHolderURLsDomainsAndAlternates(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d.Policy.Holders[0].URL, d.Policy.Holders[0].AltURLs = "https://keys-cf.tacy.io", []string{"https://keys-cf.tacy.dev/"}
	d.Policy.Holders[1].URL, d.Policy.Holders[1].AltURLs = "https://keys-v.tacy.io", []string{"https://tacy-holder.vercel.app"}
	b, err := d.SignPolicy()
	if err != nil {
		t.Fatal(err)
	}
	urls, _, err := HolderURLs(b, d.IDPub, devAdmin(d), "tacy.io, .TACY.dev,vercel.app", false)
	if err != nil || !slices.Equal(urls["cloudflare"], []string{"https://keys-cf.tacy.io", "https://keys-cf.tacy.dev"}) ||
		!slices.Equal(urls["vercel"], []string{"https://keys-v.tacy.io", "https://tacy-holder.vercel.app"}) {
		t.Fatalf("%v %v", urls, err)
	}
	// An alternate URL off the pinned domains refuses the policy, as the url itself would.
	if _, _, err := HolderURLs(b, d.IDPub, devAdmin(d), "tacy.io,tacy.dev", false); err == nil || !strings.Contains(err.Error(), "vercel.app") {
		t.Fatalf("an alternate URL on an unpinned domain: %v", err)
	}
	// A domain list of commas only pins nothing: refused as no domain.
	if _, _, err := HolderURLs(b, d.IDPub, devAdmin(d), " , ", false); err == nil {
		t.Fatal("an empty domain list")
	}
}

// A holder call goes to the holder's url, and to its alternates in order only when the one before didn't answer;
// a refusal (any HTTP answer) is final.
func TestUnlockTargetAlternates(t *testing.T) {
	var hits []string
	alt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, "alt "+r.URL.Path)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer alt.Close()
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, "refusing "+r.URL.Path)
		http.Error(w, `{"error":"no"}`, http.StatusForbidden)
	}))
	defer refusing.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close() // nothing listens there now
	d, _ := devPolicy(t, "https://keys-cf.tacy.io", "https://keys-v.tacy.io")
	f, err := NewFixed(nil, "https://chat.tacy.test", true)
	if err != nil {
		t.Fatal(err)
	}
	u := f.NewUnlockHosts(d.IDPub, devAdmin(d), "")
	u.Fetch = func(context.Context) ([]byte, error) { return nil, errors.New("no Worker") }
	u.urls, u.at = map[string][]string{"cloudflare": {downURL, alt.URL}, "vercel": {refusing.URL, alt.URL}}, time.Now()
	a := f.Fixed(context.Background(), &FixedCall{Target: TargetUnlock, Holder: "cloudflare", Method: "GET", Path: "/v1/challenge"})
	if a.Error != "" || a.Status != 200 || !slices.Equal(hits, []string{"alt /v1/challenge"}) {
		t.Fatalf("down url, then the alternate: %+v %v", a, hits)
	}
	hits = nil
	a = f.Fixed(context.Background(), &FixedCall{Target: TargetUnlock, Holder: "vercel", Method: "GET", Path: "/v1/challenge"})
	if a.Status != http.StatusForbidden || !slices.Equal(hits, []string{"refusing /v1/challenge"}) {
		t.Fatalf("a refusal is final: %+v %v", a, hits)
	}
	hits = nil
	u.urls["cloudflare"] = []string{downURL}
	if a := f.Fixed(context.Background(), &FixedCall{Target: TargetUnlock, Holder: "cloudflare", Method: "GET", Path: "/v1/challenge"}); a.Error != "unreachable" || len(hits) != 0 {
		t.Fatalf("every URL down: %+v %v", a, hits)
	}
}
