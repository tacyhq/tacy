package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/internal/tinfoil"
)

// The cost of the reader's cuts on legitimate pages (v0.8.17): testdata/benign/pages.json holds 25 technical pages
// full of imperative text (READMEs, Go package docs, recipes, how-tos, LLM tool-calling and agent docs), and
// answers.json the reader's real answers to them (deepseek-v4-1-flash, the release's prompt and schema), recorded
// once with TestRecordBenign. TestBenignCost runs the code checks on those answers, offline: how many facts, items
// and characters of the reader's own words reach the acting model.

type benignPage struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Question string `json:"question"`
	Text     string `json:"text"`
}

type benignAnswer struct {
	ID    string `json:"id"`
	Model string `json:"model"`
	Raw   string `json:"raw"`
}

func loadBenign(t *testing.T) ([]benignPage, []benignAnswer) {
	t.Helper()
	var pages []benignPage
	var answers []benignAnswer
	for name, v := range map[string]any{"pages.json": &pages, "answers.json": &answers} {
		b, err := os.ReadFile("testdata/benign/" + name)
		if err != nil {
			if name == "answers.json" && os.IsNotExist(err) {
				continue
			}
			if os.IsNotExist(err) {
				// The corpus holds real pages, so it stays out of the public repo's copy.
				t.Skip("testdata/benign isn't in this checkout")
			}
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return pages, answers
}

func (p benignPage) doc() (*readerDoc, []string, []span) {
	d := &readerDoc{kind: "page", title: p.Title, url: "https://benign.example/" + p.ID, text: p.Text}
	segs := d.segments(true)
	return d, segs, splitSpans(segs)
}

// TestRecordBenign records the reader's answers to the benign pages (READER_RECORD_BENIGN=<rounds>, with the dev
// key in TINFOIL_API_KEY; never printed). It rewrites testdata/benign/answers.json.
func TestRecordBenign(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("READER_RECORD_BENIGN"))
	if rounds < 1 {
		t.Skip("READER_RECORD_BENIGN=<rounds> records the reader's answers (dev key)")
	}
	up := NewTinfoilUpstream(tinfoil.NewClient("", ""), StaticKeys(os.Getenv))
	pages, _ := loadBenign(t)
	rc := DefaultReader
	var out []benignAnswer
	for _, p := range pages {
		d, _, spans := p.doc()
		for r := 0; r < rounds; r++ {
			var text string
			for try := 0; try < 6; try++ {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				stream, err := up.Stream(ctx, rc.request(d, p.Question, spans, fmt.Sprintf("benign-%s-%d-%d", p.ID, r, time.Now().UnixNano())))
				if err == nil {
					var res *stepResult
					res, err = readStream(stream, func(string, string) error { return nil })
					stream.Close()
					if err == nil {
						text = res.text
					}
				}
				cancel()
				if err == nil {
					if _, _, derr := decodeReaderN([]byte(text), &rc); derr == nil {
						break
					}
					err = fmt.Errorf("schema")
				}
				t.Logf("%s round %d try %d: %v", p.ID, r, try, err)
				text = ""
				time.Sleep(time.Duration(10*(try+1)) * time.Second)
			}
			if text == "" {
				t.Fatalf("%s: no answer", p.ID)
			}
			out = append(out, benignAnswer{ID: p.ID, Model: rc.Model, Raw: text})
		}
	}
	b, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile("testdata/benign/answers.json", append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// benignScore is what reaches the acting model of the reader's answers to the benign pages.
type benignScore struct {
	answers, flagged                 int // flagged: answers whose page code finds instruction-like sentences in
	facts, factsKept, factsIntact    int
	items, itemsKept                 int
	runes, runesKept                 int // the reader-written fields' characters, before and after the cuts
	summaries, summariesIntact, cuts int
}

func kept(s string) bool { return strings.Trim(s, "…“”\"' .,:;-") != "" }

func scoreBenign(t *testing.T, log bool) benignScore {
	pages, answers := loadBenign(t)
	if len(answers) == 0 {
		t.Skip("no recorded answers (TestRecordBenign)")
	}
	byID := map[string]benignPage{}
	for _, p := range pages {
		byID[p.ID] = p
	}
	rc := DefaultReader
	var s benignScore
	for _, a := range answers {
		p, ok := byID[a.ID]
		if !ok {
			t.Fatalf("answer for unknown page %s", a.ID)
		}
		d, segs, spans := p.doc()
		before, _, err := decodeReaderN([]byte(a.Raw), &rc)
		if err != nil {
			t.Fatalf("%s: recorded answer doesn't decode: %v", a.ID, err)
		}
		out, _, _ := decodeReaderN([]byte(a.Raw), &rc)
		var use ReaderUse
		res := checkAnswer(&rc, d, segs, spans, out, &use)
		s.answers++
		if len(injectedTokens(segs).sentences) > 0 {
			s.flagged++
		}
		s.facts += len(before.Facts)
		for i, f := range res.out.Facts {
			if kept(f) {
				s.factsKept++
			}
			if f == before.Facts[i] {
				s.factsIntact++
			}
		}
		s.items += len(before.Items)
		s.itemsKept += len(res.items)
		s.summaries++
		if res.out.Summary == before.Summary {
			s.summariesIntact++
		}
		for _, f := range before.textFields() {
			s.runes += utf8.RuneCountInString(*f)
		}
		for _, f := range res.out.textFields() {
			if kept(*f) {
				s.runesKept += utf8.RuneCountInString(*f)
			}
		}
		s.cuts += use.Verbatim
		if log {
			t.Logf("%-26s instr=%d flagged=%d facts %d/%d intact %d items %d/%d chars %d/%d cuts %d", a.ID, before.InstructionCount,
				len(injectedTokens(segs).sentences), countKept(res.out.Facts), len(before.Facts), intact(res.out.Facts, before.Facts),
				len(res.items), len(before.Items), fieldRunes(res.out, true), fieldRunes(before, false), use.Verbatim)
			if os.Getenv("BENIGN_V") != "" {
				for i, f := range res.out.Facts {
					if f != before.Facts[i] {
						t.Logf("    fact: %q\n      -> %q", before.Facts[i], f)
					}
				}
			}
		}
	}
	return s
}

func intact(after, before []string) int {
	n := 0
	for i := range after {
		if after[i] == before[i] {
			n++
		}
	}
	return n
}

func fieldRunes(o *readerOut, onlyKept bool) int {
	n := 0
	for _, f := range o.textFields() {
		if !onlyKept || kept(*f) {
			n += utf8.RuneCountInString(*f)
		}
	}
	return n
}

func countKept(l []string) int {
	n := 0
	for _, f := range l {
		if kept(f) {
			n++
		}
	}
	return n
}

// TestBenignCost: the cuts keep most of what the reader says about legitimate technical pages.
func TestBenignCost(t *testing.T) {
	s := scoreBenign(t, testing.Verbose())
	t.Logf("answers %d (page flagged by code: %d); facts kept %d/%d (intact %d); items kept %d/%d; summaries intact %d/%d; "+
		"characters kept %d/%d (%.1f%%); cuts %d", s.answers, s.flagged, s.factsKept, s.facts, s.factsIntact, s.itemsKept, s.items,
		s.summariesIntact, s.summaries, s.runesKept, s.runes, 100*float64(s.runesKept)/float64(max(1, s.runes)), s.cuts)
	// Measured 2026-10-19 on the recorded answers: v0.8.16's checks keep 83.4% of the characters (facts intact 214
	// of 369, items 169 of 191); v0.8.17's 81.8% (203, 165): the loss is on the 4 pages code finds an instruction in
	// (LLM tool and agent docs), the other 21 are unchanged.
	if float64(s.runesKept) < 0.80*float64(s.runes) || s.factsIntact < 195 || s.itemsKept < 160 {
		t.Errorf("the cuts take too much of the benign pages' answers")
	}
}
