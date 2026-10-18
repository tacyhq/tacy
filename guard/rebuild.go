package guard

import (
	"encoding/json/v2"

	"github.com/tacyhq/tacy/harness"
)

// rebuild restores the task's per-task state from its journal (decided: no separate store). It
// runs once per task in this process, before the guard does anything for it, so every finished entry it finds
// was done by an earlier runtime process: after a restart, citation and quote numbers continue where they stopped, the image slots
// stay taken, the sites whose icons were shown aren't fetched again, and steps keep counting. Entries are
// untrusted only as far as the guard's own outputs are (it wrote them); anything unreadable is skipped.
func (t *task) rebuild(ti *harness.TaskInfo) {
	if ti.Journal == nil {
		return
	}
	recs, err := ti.Journal()
	if err != nil || len(recs) == 0 {
		return
	}
	steps, cites, images, quotes := 0, 0, 0, 0
	var sites []string
	for _, r := range recs {
		switch r.Kind {
		case harness.TypeModelCall:
			// A finished model call reached the gateway (a step people saw), whatever its outcome, unless it was over
			// the task's model-call limit. Unfinished ones aren't counted: one may be the request being served now.
			if r.Done && (r.Err == nil || r.Err.Code != harness.CodeLimit) {
				steps++
			}
		case harness.TypeAction:
			if !r.Done || r.Err != nil {
				continue
			}
			var req harness.Action
			var res harness.ActionResult
			if json.Unmarshal(r.Req, &req) != nil || json.Unmarshal(r.Body, &res) != nil || res.Status != harness.ActionDone {
				continue
			}
			n, used, urls := journaledOutput(req.Name, res.Output)
			cites, images, quotes = max(cites, n), images+used, max(quotes, journaledQuotes(res.Output))
			sites = append(sites, urls...)
		}
	}
	t.mu.Lock()
	t.step = max(t.step, steps)
	t.mu.Unlock()
	t.numbering.Lock()
	t.tools.cites = max(t.tools.cites, cites)
	t.tools.quotes = max(t.tools.quotes, quotes)
	t.numbering.Unlock()
	t.tools.reserveImages(images)
	t.icons.markSeen(sites...)
}

// journaledOutput reads a web connector action's journaled output (what the model saw, tools.go's shapes): the
// highest citation number in it, the image slots it took and the source URLs whose sites' icons were fetched.
func journaledOutput(action string, out []byte) (cite, images int, urls []string) {
	switch action {
	case "web.search":
		var o struct {
			Results []struct {
				N   int    `json:"n"`
				URL string `json:"url"`
			} `json:"results"`
		}
		if json.Unmarshal(out, &o) == nil {
			for _, r := range o.Results {
				cite = max(cite, r.N)
				urls = append(urls, r.URL)
			}
		}
	case "web.fetch":
		var o struct {
			N   int    `json:"n"`
			URL string `json:"url"`
		}
		if json.Unmarshal(out, &o) == nil {
			cite, urls = o.N, []string{o.URL}
		}
	case "web.images":
		var o struct {
			Shown  int `json:"shown"`
			Images []struct {
				Source string `json:"source"`
			} `json:"images"`
		}
		if json.Unmarshal(out, &o) == nil {
			images = max(0, o.Shown)
			for _, im := range o.Images {
				urls = append(urls, im.Source)
			}
		}
	}
	return cite, images, urls
}

// journaledQuotes is the highest quote number in a journaled output the reader made ("read": {"quotes": [...]}).
func journaledQuotes(out []byte) int {
	var o struct {
		Read *struct {
			Quotes []struct {
				ID int `json:"id"`
			} `json:"quotes"`
		} `json:"read"`
	}
	n := 0
	if json.Unmarshal(out, &o) == nil && o.Read != nil {
		for _, q := range o.Read.Quotes {
			n = max(n, q.ID)
		}
	}
	return n
}

// markSeen counts these URLs' sites as seen without fetching their icons: they were shown before a restart.
func (s *siteIcons) markSeen(urls ...string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range urls {
		if key, _, ok := iconKey(raw); ok && len(s.seen) < maxIconHosts {
			s.seen[key] = true
		}
	}
}
