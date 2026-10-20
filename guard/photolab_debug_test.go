package guard

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// TestPhotoLabCandidates prints a fast image search's candidates and why each is refused (lab only).
func TestPhotoLabCandidates(t *testing.T) {
	names := os.Getenv("PHOTOLAB_NAMES")
	if names == "" || os.Getenv("TAVILY_API_KEY") == "" {
		t.Skip("lab only")
	}
	tv := newTavily(StaticKeys(os.Getenv))
	for _, n := range strings.Split(names, ";") {
		var cs []ImageCandidate
		var err error
		if os.Getenv("PHOTOLAB_SLOW") != "" {
			cs, err = tv.Images(context.Background(), n, lookupCandidates)
		} else {
			cs, err = tv.ImagesFast(context.Background(), n, fastCandidates)
		}
		t.Logf("== %q: %d candidates, err %v", n, len(cs), err)
		for _, c := range rankCandidates(n, cs) {
			t.Logf("   %-8s %-70.70q %.90s  (page %.60s)", pictureRefused(n, c), c.Title, c.URL, c.Source)
		}
	}
}

// TestPhotoLabLookup runs one lookup per name through a lab task and prints what came of it (lab only).
func TestPhotoLabLookup(t *testing.T) {
	names := os.Getenv("PHOTOLAB_LOOKUP")
	if names == "" {
		t.Skip("lab only")
	}
	keys := StaticKeys(os.Getenv)
	lim := DefaultLimits
	g := New(Config{Search: newExa(keys, newTavily(keys)), Fetcher: NewFetcher(false), Icons: NewFetcher(false), Limits: &lim, Now: time.Now})
	sess := g.Open("dbg", TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.images": "always"}}, func(proto.Event) error { return nil })
	defer sess.Close()
	tk := g.task(&harness.TaskInfo{ID: "dbg"})
	for _, n := range strings.Split(names, ";") {
		if u := os.Getenv("PHOTOLAB_URLS"); u != "" {
			for _, x := range strings.Split(u, " ") {
				t1 := time.Now()
				_, w, h, err := g.downloadCardPictureCtx(tk, tk.ctx, x)
				t.Logf("   download %.80s: %dx%d %v in %.1f s (refused %q)", x, w, h, err, time.Since(t1).Seconds(), imageURLRefused(x))
			}
		}
		t0 := time.Now()
		pics := g.runLookup(tk, taskItem{name: n, call: "c1"})
		tk.cards.mu.Lock()
		st := tk.cards.st
		tk.cards.mu.Unlock()
		t.Logf("== %q: %d pictures in %.1f s; tried %d failed %d reasons %v", n, len(pics), time.Since(t0).Seconds(), st.tried, st.failed, st.reasons)
		for i, p := range pics {
			t.Logf("   %dx%d %q %s", p.w, p.h, p.c.Title, p.c.URL)
			if d := os.Getenv("PHOTOLAB_OUT"); d != "" && i == 0 {
				os.MkdirAll(d, 0o755)
				os.WriteFile(d+"/"+strings.ReplaceAll(itemKey(n), " ", "-")+".jpg", p.jp, 0o644)
			}
		}
	}
}
