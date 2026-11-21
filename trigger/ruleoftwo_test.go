package trigger

import (
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/tacyhq/tacy/safety"
)

// TestRuleOfTwoInstall (R1, the v1 design §5.6): a definition that lists a mail tool with a web tool is refused
// mail_and_web; in v1 any mail tool is refused mail_background_later (a mail kind in allow counts as listed);
// nothing is stored. A definition installed before v1 still loads (its runs leave mail out, guard.RuleOfTwo).
func TestRuleOfTwoInstall(t *testing.T) {
	w := newWorld(t)
	for name, c := range map[string]struct {
		tools []string
		allow map[string]string
		want  error
	}{
		"mail and search":   {[]string{"mail.search", "web.search"}, nil, ErrMailAndWeb},
		"mail and fetch":    {[]string{"mail.read", "web.fetch"}, nil, ErrMailAndWeb},
		"mail and images":   {[]string{"mail.folders", "web.images"}, nil, ErrMailAndWeb},
		"allow mail, web":   {[]string{"web.fetch"}, map[string]string{"mail.read": safety.PermAlways}, ErrMailAndWeb},
		"mail only":         {[]string{"mail.search", "mail.read"}, nil, ErrMailBackgroundLater},
		"mail and document": {[]string{"mail.search", "document.create"}, nil, ErrMailBackgroundLater},
	} {
		d := w.def(1)
		d.Tools, d.Allow = c.tools, c.allow
		if _, err := w.install(d, w.authorK, w.sponsorK); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if w.e.Get(d.Agent) != nil {
			t.Fatalf("%s: installed", name)
		}
	}
	d := w.def(1)
	d.Tools = []string{"web.search", "web.fetch"}
	if _, err := w.install(d, w.authorK, w.sponsorK); err != nil {
		t.Fatalf("web only: %v", err)
	}
	// One stored by an older release (mail and web) still loads; R2 keeps its runs off the web.
	old := w.def(2)
	old.Tools = []string{"mail.search", "web.search"}
	env, _ := SignDefinition(old, w.authorK, w.sponsorK)
	b, _ := json.Marshal(env)
	if err := w.store.SaveDefinition(old.Agent, 2, b); err != nil {
		t.Fatal(err)
	}
	e := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock, Trusted: w.e.cfg.Trusted})
	if n, err := e.Load(); err != nil || n != 1 || e.Get(old.Agent).Def.Version != 2 {
		t.Fatalf("load: %d %v", n, err)
	}
}
