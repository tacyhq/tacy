package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeMetadata is Google's metadata server for one instance; it counts requests.
func fakeMetadata(t *testing.T, id, zone string, flavor bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing header", 403)
			return
		}
		if flavor {
			w.Header().Set("Metadata-Flavor", "Google")
		}
		switch r.URL.Path {
		case "/instance/id":
			w.Write([]byte(id))
		case "/instance/zone":
			w.Write([]byte(zone))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s, &n
}

func dmiFile(t *testing.T, product string) string {
	p := filepath.Join(t.TempDir(), "product_name")
	if err := os.WriteFile(p, []byte(product+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// On Google Compute Engine (DMI) gatewayd answers the hints call from the metadata server, once per boot; anywhere
// else (Phala's DMI, or no DMI file) it answers no_target and sends nothing.
func TestGCEHintsOnlyOnGoogle(t *testing.T) {
	ctx := context.Background()
	md, n := fakeMetadata(t, "4567890123456789012", "projects/635557987033/zones/us-central1-a", true)
	call := &FixedCall{Target: TargetGCE, Method: "GET", Path: GCEPath}

	f := &Fixed{GCE: &GCEMeta{DMIPath: dmiFile(t, GCEProduct), Base: md.URL + "/instance/", Client: md.Client()}}
	for range 3 {
		a := f.Fixed(ctx, call)
		var h GCEHints
		if a.Error != "" || a.Status != 200 || json.Unmarshal(a.Body, &h) != nil ||
			h != (GCEHints{InstanceID: "4567890123456789012", Zone: "us-central1-a"}) {
			t.Fatalf("on Google: %+v %s", a, a.Body)
		}
	}
	if n.Load() != 2 {
		t.Fatalf("the metadata server was asked %d times (want 2: id and zone, once)", n.Load())
	}

	for name, dmi := range map[string]string{"phala": dmiFile(t, "Standard PC (Q35 + ICH9, 2009)"), "no file": filepath.Join(t.TempDir(), "none")} {
		n.Store(0)
		f := &Fixed{GCE: &GCEMeta{DMIPath: dmi, Base: md.URL + "/instance/", Client: md.Client()}}
		if a := f.Fixed(ctx, call); a.Error != "no_target" || n.Load() != 0 {
			t.Fatalf("%s: %+v, %d requests", name, a, n.Load())
		}
	}
	if a := (&Fixed{}).Fixed(ctx, call); a.Error != "no_target" {
		t.Fatalf("no GCE: %+v", a)
	}
}

// Answers that aren't the metadata server's, or hints of the wrong form, give no hints.
func TestGCEHintsRefused(t *testing.T) {
	ctx := context.Background()
	call := &FixedCall{Target: TargetGCE, Method: "GET", Path: GCEPath}
	for name, c := range map[string]struct {
		id, zone string
		flavor   bool
	}{
		"no Metadata-Flavor": {"123", "projects/1/zones/us-central1-a", false},
		"id not a number":    {"12a", "projects/1/zones/us-central1-a", true},
		"bad zone":           {"123", "projects/1/zones/../../x", true},
		"id too long":        {strings.Repeat("1", 21), "projects/1/zones/us-central1-a", true},
	} {
		md, _ := fakeMetadata(t, c.id, c.zone, c.flavor)
		f := &Fixed{GCE: &GCEMeta{DMIPath: dmiFile(t, GCEProduct), Base: md.URL + "/instance/", Client: md.Client()}}
		if a := f.Fixed(ctx, call); a.Error != "unreachable" {
			t.Fatalf("%s: %+v", name, a)
		}
	}
	// Only GET /instance, nothing else of the target.
	for _, bad := range []*FixedCall{
		{Target: TargetGCE, Method: "POST", Path: GCEPath},
		{Target: TargetGCE, Method: "GET", Path: "/instance/id"},
		{Target: TargetGCE, Method: "GET", Path: GCEPath + "?recursive=true"},
		{Target: TargetGCE, Method: "GET", Path: GCEPath, Host: 1},
		{Target: TargetGCE, Method: "GET", Path: GCEPath, Holder: "cloudflare"},
		{Target: TargetGCE, Method: "GET", Path: GCEPath, Header: map[string]string{"Content-Type": "x"}},
	} {
		if CheckFixed(bad) == nil {
			t.Fatalf("%+v passed", bad)
		}
	}
}

// agentd's and unlockd's sockets may ask for the hints; vaultd's ops socket may not.
func TestGCESockets(t *testing.T) {
	call := &FixedCall{Target: TargetGCE, Method: "GET", Path: GCEPath}
	if !AgentCalls(call) || !UnlockCalls(call) || VaultCalls(call) {
		t.Fatalf("agent %v unlock %v vault %v", AgentCalls(call), UnlockCalls(call), VaultCalls(call))
	}
}

type fixedFunc func(*FixedCall) *FixedAnswer

func (f fixedFunc) Fixed(_ context.Context, c *FixedCall) *FixedAnswer { return f(c) }

// The hinter adds the two fields before the info's closing brace only when the guest agent says Google, leaving the
// rest byte for byte; any other info goes as it is, with no call.
func TestGCEHinterAugment(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	d := fixedFunc(func(c *FixedCall) *FixedAnswer {
		calls.Add(1)
		if c.Target != TargetGCE || c.Path != GCEPath {
			t.Fatalf("call %+v", c)
		}
		return &FixedAnswer{Status: 200, Body: []byte(`{"gce_instance_id":"42","gce_zone":"us-east4-c"}`)}
	})
	g := &GCEHinter{D: d}
	google := `{"app_id":"x","tcb_info":"{\"rtmr3\":\"ab\"}","cloud_vendor":"Google","cloud_product":"Google Compute Engine"}` + "\n"
	got := g.Augment(ctx, json.RawMessage(google))
	want := strings.TrimSuffix(google, "\n")
	want = want[:len(want)-1] + `,"gce_instance_id":"42","gce_zone":"us-east4-c"}`
	if string(got) != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	var v map[string]any
	if json.Unmarshal(got, &v) != nil || v["gce_instance_id"] != "42" || v["gce_zone"] != "us-east4-c" || v["tcb_info"] != `{"rtmr3":"ab"}` {
		t.Fatalf("not the info plus the hints: %s", got)
	}
	g.Augment(ctx, json.RawMessage(google))
	if calls.Load() != 1 {
		t.Fatalf("gatewayd asked %d times (want once per boot)", calls.Load())
	}
	for _, info := range []string{
		`{"app_id":"x","cloud_vendor":""}`,                // Phala
		`{"app_id":"x"}`,                                  // no vendor
		`{"cloud_vendor":"Google","gce_instance_id":"7"}`, // already there
		`not json`,
	} {
		calls.Store(0)
		if got := g.Augment(ctx, json.RawMessage(info)); string(got) != info || calls.Load() != 0 {
			t.Fatalf("%s: %s (%d calls)", info, got, calls.Load())
		}
	}
	// gatewayd without hints (no_target, or a bad answer): the info as it is.
	for _, a := range []*FixedAnswer{{Error: "no_target"}, {Status: 200, Body: []byte(`{"gce_instance_id":"x1","gce_zone":"us-east4-c"}`)}} {
		g := &GCEHinter{D: fixedFunc(func(*FixedCall) *FixedAnswer { return a })}
		if got := g.Augment(ctx, json.RawMessage(google)); string(got) != google {
			t.Fatalf("%+v: %s", a, got)
		}
	}
	var nilHinter *GCEHinter
	if got := nilHinter.Augment(ctx, json.RawMessage(google)); string(got) != google {
		t.Fatal("a nil hinter changed the info")
	}
}
