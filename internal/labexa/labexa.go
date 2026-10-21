// Package labexa is the labs' and tests' only way to Exa (2026-10-20, after about $20 of Exa credit went in one
// day on lab rounds and e2e checks): an http.RoundTripper for api.exa.ai that replays a search it has seen and
// caps what live searches may spend. Lab and test code only (app/researchlab_test.go and the lab commands): gatewayd
// and agentd never import it, so production requests are unchanged.
//
//   - Replay by default: every Exa request and its 200 response are kept in a cache outside the repo
//     (EXA_LAB_CACHE, default ~/.tacy-lab/exa-cache), keyed by the exact request (method, address, body); a request
//     seen before is answered from there and costs nothing. Older lab caches (a --cache dir's exa/) are read too, in
//     the same format, and a hit there is copied in. EXA_LAB_LIVE=1 skips the cache (the response is still kept).
//   - A hard cap: every live search's real cost (the response's costDollars.total; an estimate only when Exa sends
//     none) goes into one ledger for all labs on this machine (EXA_LAB_LEDGER, default ~/.tacy-lab/exa-spend.json),
//     by UTC day, under a file lock so overlapping runs add up. A live search is refused once today's total would
//     pass EXA_LAB_DAILY_CAP (default $4) or this run's would pass EXA_LAB_RUN_CAP (default $1). The refusal is an
//     error wrapping ErrCap, OnCap hears it once, and Stats says so: the lab stops instead of grading empty results.
//
// The key (EXA_API_KEY in the repo's .env: the dev/lab key, not production's) stays in the request header: it is
// never part of the cache key, never written, never printed.
package labexa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Host is the API host this transport handles; anything else passes through untouched.
const Host = "api.exa.ai"

// Response headers on what the transport returns (never sent anywhere): whether the search was replayed or went
// live, and its real cost in dollars (0 for a replay).
const (
	HeaderSource = "X-Lab-Exa"
	HeaderCost   = "X-Lab-Exa-Cost"
)

// ErrCap is what a live search gets once a cap is reached. It says NoFallback: the guard's search fallback
// (guard/searchfallback.go) never takes a cap for Exa failing and sends the search to Tavily instead.
var ErrCap error = capError{}

type capError struct{}

func (capError) Error() string    { return "exa lab cap reached" }
func (capError) NoFallback() bool { return true }

// estimate is what a live search is reserved at before its real cost is known, and what it is charged when Exa's
// response has no costDollars: above a "fast" search's $0.007 (10 results, highlights included; measured from
// costDollars on 70 lab searches, 2026-10-20).
const estimate = 0.01

// Options configures a Transport. FromEnv fills it from the environment.
type Options struct {
	CacheDir string   // where searches are kept; "" none (every search live)
	ReadDirs []string // older caches in the same format, read only
	Ledger   string   // the shared spend ledger; "" none (no daily cap)
	DailyCap float64  // $ a UTC day across all lab runs on this machine
	RunCap   float64  // $ this run (this Transport)
	Live     bool     // skip the cache: every search goes live (and is kept)
	Label    string   // who spends, in the ledger ("research lab", "photolab")
	OnCap    func(error)
	Now      func() time.Time
}

// FromEnv is the lab default: ~/.tacy-lab/exa-cache, ~/.tacy-lab/exa-spend.json, $4 a day, $1 a run, replay on,
// each overridable (EXA_LAB_CACHE, EXA_LAB_LEDGER, EXA_LAB_DAILY_CAP, EXA_LAB_RUN_CAP, EXA_LAB_LIVE=1).
func FromEnv(label string) Options {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".tacy-lab")
	o := Options{CacheDir: filepath.Join(dir, "exa-cache"), Ledger: filepath.Join(dir, "exa-spend.json"), DailyCap: 4, RunCap: 1, Label: label}
	if v := os.Getenv("EXA_LAB_CACHE"); v != "" {
		o.CacheDir = v
	}
	if v := os.Getenv("EXA_LAB_LEDGER"); v != "" {
		o.Ledger = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("EXA_LAB_DAILY_CAP"), 64); err == nil && v >= 0 {
		o.DailyCap = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("EXA_LAB_RUN_CAP"), 64); err == nil && v >= 0 {
		o.RunCap = v
	}
	o.Live = os.Getenv("EXA_LAB_LIVE") == "1"
	return o
}

// Transport replays and caps Exa searches (see the package comment).
type Transport struct {
	base http.RoundTripper
	o    Options

	mu       sync.Mutex
	live     int
	replayed int
	refused  int
	runUSD   float64 // real cost of this run's live searches, plus reservations in flight
	capErr   error
}

// New wraps base (nil: http.DefaultTransport).
func New(base http.RoundTripper, o Options) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Transport{base: base, o: o}
}

// Stats is a run's Exa use: searches live and replayed, their real cost, and the day's total in the ledger.
type Stats struct {
	Live     int     `json:"live"`
	Replayed int     `json:"replayed"`
	Refused  int     `json:"refused,omitempty"` // live searches the caps refused
	RunUSD   float64 `json:"run_usd"`
	TodayUSD float64 `json:"today_usd"`
	Day      string  `json:"day"`
	DailyCap float64 `json:"daily_cap"`
	RunCap   float64 `json:"run_cap"`
	Capped   string  `json:"capped,omitempty"` // the cap's message when one was hit
}

// Stats reads the ledger for today's total.
func (t *Transport) Stats() Stats {
	t.mu.Lock()
	s := Stats{Live: t.live, Replayed: t.replayed, Refused: t.refused, RunUSD: t.runUSD, DailyCap: t.o.DailyCap, RunCap: t.o.RunCap}
	if t.capErr != nil {
		s.Capped = t.capErr.Error()
	}
	t.mu.Unlock()
	s.Day = day(t.o.Now())
	if t.o.Ledger != "" {
		if l, err := readLedger(t.o.Ledger); err == nil && l.Days[s.Day] != nil {
			s.TodayUSD = l.Days[s.Day].USD
		}
	}
	return s
}

// String is the line a lab prints: "Exa $0.014 real (2 live, 5 replayed); today $0.35 of $4.00".
func (s Stats) String() string {
	line := fmt.Sprintf("Exa $%.3f real (%d live, %d replayed); today $%.3f of $%.2f (run cap $%.2f)", s.RunUSD, s.Live, s.Replayed, s.TodayUSD, s.DailyCap, s.RunCap)
	if s.Capped != "" {
		line += "; STOPPED: " + s.Capped
	}
	return line
}

// Key is a request's cache key: the method, the address and the body (the key is in a header, never part of it).
// The same format as the research lab's cache before this package, so those caches still replay.
func Key(method, url string, body []byte) string {
	h := sha256.Sum256(append([]byte(method+" "+url+"\n"), body...))
	return hex.EncodeToString(h[:12])
}

// entry is one kept response (the research lab's labEntry format).
type entry struct {
	At     string            `json:"at"`
	MS     int64             `json:"ms"`
	Status int               `json:"status,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Body   string            `json:"body"`
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != Host || r.Body == nil {
		return t.base.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	key := Key(r.Method, r.URL.String(), body)
	if !t.o.Live {
		if e, ok := t.lookup(key); ok {
			t.mu.Lock()
			t.replayed++
			t.mu.Unlock()
			return response(r, e, "replayed", 0), nil
		}
	}
	if err := t.reserve(); err != nil {
		return nil, err
	}
	t0 := time.Now()
	res, err := t.base.RoundTrip(r)
	if err != nil {
		t.settle(0, false)
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	res.Body.Close()
	if rerr != nil {
		t.settle(estimate, true) // it may have been served and billed
		return nil, rerr
	}
	cost, known := 0.0, true // Exa bills a successful search only
	if res.StatusCode == 200 {
		cost, known = costOf(b)
		if !known {
			cost = estimate
		}
	}
	t.settle(cost, !known)
	if res.StatusCode == 200 && t.o.CacheDir != "" {
		hd := map[string]string{}
		if v := res.Header.Get("Content-Type"); v != "" {
			hd["Content-Type"] = v
		}
		writeEntry(filepath.Join(t.o.CacheDir, key+".json"), entry{At: time.Now().UTC().Format(time.RFC3339), MS: time.Since(t0).Milliseconds(),
			Status: 200, Header: hd, Body: string(b)})
	}
	res.Body = io.NopCloser(bytes.NewReader(b))
	res.ContentLength = int64(len(b))
	res.Header.Set(HeaderSource, "live")
	res.Header.Set(HeaderCost, strconv.FormatFloat(cost, 'f', -1, 64))
	return res, nil
}

func (t *Transport) lookup(key string) (*entry, bool) {
	if t.o.CacheDir != "" {
		if e, ok := readEntry(filepath.Join(t.o.CacheDir, key+".json")); ok {
			return e, true
		}
	}
	for _, d := range t.o.ReadDirs {
		if e, ok := readEntry(filepath.Join(d, key+".json")); ok {
			if t.o.CacheDir != "" {
				writeEntry(filepath.Join(t.o.CacheDir, key+".json"), *e)
			}
			return e, true
		}
	}
	return nil, false
}

func response(r *http.Request, e *entry, source string, cost float64) *http.Response {
	hd := http.Header{}
	for k, v := range e.Header {
		hd.Set(k, v)
	}
	hd.Set(HeaderSource, source)
	hd.Set(HeaderCost, strconv.FormatFloat(cost, 'f', -1, 64))
	st := e.Status
	if st == 0 {
		st = 200
	}
	return &http.Response{StatusCode: st, Status: strconv.Itoa(st) + " " + http.StatusText(st), Header: hd,
		Body: io.NopCloser(strings.NewReader(e.Body)), ContentLength: int64(len(e.Body)), Request: r, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1}
}

// costOf is costDollars.total from an Exa response.
func costOf(b []byte) (float64, bool) {
	var v struct {
		CostDollars *struct {
			Total *float64 `json:"total"`
		} `json:"costDollars"`
	}
	if json.Unmarshal(b, &v) != nil || v.CostDollars == nil || v.CostDollars.Total == nil {
		return 0, false
	}
	return *v.CostDollars.Total, true
}

// reserve books an estimate against both caps before a live search, or refuses it.
func (t *Transport) reserve() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.capErr != nil {
		t.refused++
		return t.capErr
	}
	if t.runUSD+estimate > t.o.RunCap+1e-9 {
		return t.capped(fmt.Errorf("%w: this run's live Exa spend is $%.3f of its $%.2f cap (EXA_LAB_RUN_CAP); searches already in the cache still replay", ErrCap, t.runUSD, t.o.RunCap))
	}
	if t.o.Ledger != "" {
		var today float64
		err := updateLedger(t.o.Ledger, func(l *ledger) error {
			d := l.day(day(t.o.Now()))
			today = d.USD
			if d.USD+estimate > t.o.DailyCap+1e-9 {
				return ErrCap
			}
			d.USD += estimate // the reservation, corrected by settle
			d.Searches++
			d.By[t.o.Label] += estimate
			return nil
		})
		if errors.Is(err, ErrCap) {
			return t.capped(fmt.Errorf("%w: today's live Exa spend (UTC %s, all labs on this machine) is $%.3f of the $%.2f daily cap (EXA_LAB_DAILY_CAP); searches already in the cache still replay",
				ErrCap, day(t.o.Now()), today, t.o.DailyCap))
		}
		if err != nil {
			return fmt.Errorf("%w: the spend ledger can't be updated (%v), so no live search", ErrCap, err)
		}
	}
	t.runUSD += estimate
	t.live++
	return nil
}

func (t *Transport) capped(err error) error {
	t.capErr = err
	t.refused++
	if t.o.OnCap != nil {
		go t.o.OnCap(err)
	}
	return err
}

// settle replaces a search's reservation with its real cost.
func (t *Transport) settle(cost float64, estimated bool) {
	t.mu.Lock()
	t.runUSD += cost - estimate
	t.mu.Unlock()
	if t.o.Ledger == "" {
		return
	}
	updateLedger(t.o.Ledger, func(l *ledger) error {
		d := l.day(day(t.o.Now()))
		d.USD += cost - estimate
		d.By[t.o.Label] += cost - estimate
		if estimated {
			d.Estimated++
		}
		return nil
	})
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// ---- the ledger -------------------------------------------------------------------------------------------------

type ledger struct {
	Days map[string]*dayTotal `json:"days"`
}

type dayTotal struct {
	USD       float64            `json:"usd"`
	Searches  int                `json:"live_searches"`
	Estimated int                `json:"estimated,omitempty"` // searches charged at the estimate (no costDollars)
	By        map[string]float64 `json:"by"`
}

func (l *ledger) day(k string) *dayTotal {
	if l.Days == nil {
		l.Days = map[string]*dayTotal{}
	}
	d := l.Days[k]
	if d == nil {
		d = &dayTotal{}
		l.Days[k] = d
	}
	if d.By == nil {
		d.By = map[string]float64{}
	}
	return d
}

func readLedger(path string) (*ledger, error) {
	l := &ledger{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return l, nil
	}
	if err := json.Unmarshal(b, l); err != nil {
		return nil, fmt.Errorf("ledger %s: %v", path, err)
	}
	return l, nil
}

// procMu serialises this process's ledger updates (the file lock does it across processes).
var procMu sync.Mutex

// updateLedger reads, changes and writes the ledger under an exclusive lock (path + ".lock"), the write atomic
// (a temp file renamed). f's error aborts the write.
func updateLedger(path string, f func(*ledger) error) error {
	procMu.Lock()
	defer procMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	l, err := readLedger(path)
	if err != nil {
		return err
	}
	if err := f(l); err != nil {
		return err
	}
	for k := range l.Days { // keep 60 days
		if k < day(time.Now().AddDate(0, 0, -60)) {
			delete(l.Days, k)
		}
	}
	b, _ := json.MarshalIndent(l, "", " ")
	tmp, err := os.CreateTemp(filepath.Dir(path), ".exa-spend-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), path)
}

// ---- the cache files --------------------------------------------------------------------------------------------

func readEntry(path string) (*entry, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil || e.Body == "" || (e.Status != 0 && e.Status != 200) {
		return nil, false
	}
	return &e, true
}

func writeEntry(path string, e entry) {
	b, _ := json.Marshal(e)
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".entry-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	tmp.Close()
	if werr != nil {
		os.Remove(tmp.Name())
		return
	}
	os.Rename(tmp.Name(), path)
}

// Today is today's live Exa spend in the ledger (0 when it can't be read).
func Today(path string) float64 {
	l, err := readLedger(path)
	if err != nil {
		return 0
	}
	if d := l.Days[day(time.Now())]; d != nil {
		return d.USD
	}
	return 0
}
