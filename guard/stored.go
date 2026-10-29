package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/storedfiles"
)

// The person's stored files in a task (since v0.17.0, the stored-files design's
// "VM read path"). A run the person starts names the files they picked (proto.RunRequest.StoredFiles: each object's key,
// unwrapped in their browser for this request, and an hour's presigned GET the chat's Worker minted); a schedule's
// definition names them without URLs, with a read grant (trigger.Definition.Files, FilesGrant), and its runs ask the
// Worker for URLs (storedfiles.URLSource). They become the task's files after its attached ones, read through
// files_read like them: the acting model never gets their text, only the quarantined reader's fields.
//
// A stored file is opened the first time a files.read needs it (that file named, or the next parts in order), not at
// the start: a run with 200 files picked fetches and decrypts only those it reads. Opening fetches its ciphertext
// from R2 (gatewayd, the only process with a network; host and path checked against the ref, policy's files.fetch and
// its fetch hosts checked live), checks every chunk as the browser does (storedfiles.Decrypt), and keeps the text
// in this task's memory, never on disk; it goes when the task closes (Guard.close drops the task). The fetch's host
// and bytes go into the activity record like any fetch (recordingClient).
//
// Limits: storedfiles.Check at the start (200 files, 200 MB stored, one owner); what a task fetches, at most
// storedfiles.MaxRunBytes (its Budget); the text it holds, at most maxStoredText across its stored files (the
// attached files' own cap, maxReviewBytes): a file that doesn't fit whole is read from its start to what fits (a
// range read of its first chunks), and says so; once the task holds that much, no more files are opened.

// storedFetchAction is the guard's own action that fetches a stored file (never a brain's tool): what the signed
// policy's files connector must list for stored files to be read (the chat's policy since v5).
const storedFetchAction = "files.fetch"

// maxStoredText is the most text of stored files one task holds (UTF-8 bytes): the cap on attached files' text too.
const maxStoredText = maxReviewBytes

// StoredConfig is how this guard reads stored files.
type StoredConfig struct {
	Fetcher *storedfiles.Fetcher // the files bucket (nil: none)
	URLs    storedfiles.URLSource
}

// NewStoredConfig is the release's: the files bucket on R2 and the chat's Worker for read URLs, each through a client
// that connects only to public addresses on 443 (publicOnly, checked on the resolved IP) and never follows a redirect.
func NewStoredConfig() *StoredConfig {
	client := func() *http.Client {
		c := storedfiles.DefaultClient()
		t := c.Transport.(*http.Transport)
		t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: publicOnly}).DialContext
		return c
	}
	return &StoredConfig{Fetcher: &storedfiles.Fetcher{Client: client()}, URLs: &storedfiles.WorkerURLs{Client: client()}}
}

// wrapped is c with its HTTP clients counting every request for the activity record and, when safety is on, refused
// before connecting to a host the task's live policy doesn't allow (withHostFilter).
func (c *StoredConfig) wrapped(safetyOn bool) *StoredConfig {
	wrap := func(h *http.Client) *http.Client {
		if h == nil {
			h = storedfiles.DefaultClient()
		}
		if safetyOn {
			h = withPolicyTransport(h)
		}
		return recordingClient(h)
	}
	out := &StoredConfig{}
	if c.Fetcher != nil {
		f := *c.Fetcher
		f.Client = wrap(f.Client)
		out.Fetcher = &f
	}
	switch u := c.URLs.(type) {
	case *storedfiles.WorkerURLs:
		w := *u
		w.Client = wrap(w.Client)
		out.URLs = &w
	default:
		out.URLs = c.URLs
	}
	return out
}

// HasFiles: the task has files of either kind.
func (o *TaskOptions) HasFiles() bool { return len(o.Files) > 0 || len(o.Stored) > 0 }

// StoredKeysOff is opts as the queue keeps it while the task runs: each stored file's key and read URL, and the
// grant, left out (the files' names and sizes stay, so its list and coverage stay right after a restart).
func StoredKeysOff(opts TaskOptions) TaskOptions {
	if len(opts.Stored) == 0 && opts.FilesGrant == "" {
		return opts
	}
	st := make([]proto.StoredFile, len(opts.Stored))
	for i, f := range opts.Stored {
		f.Key, f.URL = nil, ""
		st[i] = f
	}
	opts.Stored, opts.FilesGrant = st, ""
	return opts
}

// storedState is what a task knows of its stored files beyond filesState's: the fetch budget, the read URLs a
// schedule run got, and parts a restart's journal says were read in files not opened again yet.
type storedState struct {
	openMu  sync.Mutex // one open at a time per task
	budget  storedfiles.Budget
	held    int64             // text bytes held (guarded by filesState.mu)
	urls    map[string]string // a schedule run's read URLs, by object (guarded by openMu)
	urlsErr string
	// restored: a files.read result from the journal for a file not open yet (rebuild): applied when it opens.
	restored map[int][]fileSectionOut
}

// storedName is how a stored file is named to the model and the person: its name, and where its text came from.
func storedName(f proto.StoredFile) string {
	if f.Extracted {
		return f.Name + " (text extracted from it)"
	}
	return f.Name
}

// nextToOpen is the stored file a files.read for file (1-based; 0 any) with room for limit parts should open first,
// or -1: the file asked for when it isn't open; with none asked, the first unopened one while the open files' unread
// parts are fewer than limit.
func (s *filesState) nextToOpen(file, limit int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if file > 0 {
		if file <= len(s.files) && s.files[file-1].needsOpen() {
			return file - 1
		}
		return -1
	}
	unread := 0
	for fi := range s.files {
		f := &s.files[fi]
		if f.needsOpen() {
			if unread < limit {
				return fi
			}
			return -1
		}
		for _, st := range f.state {
			if !st.ok && !st.pending && st.tries < maxSectionTries {
				unread++
			}
		}
	}
	return -1
}

// needsOpen: a stored file not opened and not refused.
func (f *reviewFile) needsOpen() bool { return f.stored != nil && !f.opened && f.openErr == "" }

// unopened is how many stored files are still to open.
func (s *filesState) unopened() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i := range s.files {
		if s.files[i].needsOpen() {
			n++
		}
	}
	return n
}

// openFor opens the stored files a files.read for (file, limit) needs, one at a time.
func (g *Guard) openFor(ctx context.Context, t *task, file, limit int) {
	for range len(t.files.files) {
		fi := t.files.nextToOpen(file, limit)
		if fi < 0 || ctx.Err() != nil {
			return
		}
		g.openStored(ctx, t, fi)
	}
}

// openStored opens stored file fi (0-based): fetched, checked and decrypted, or refused with the reason (which the
// model and the person see in files_list and files_read).
func (g *Guard) openStored(ctx context.Context, t *task, fi int) {
	s := &t.files
	s.stored.openMu.Lock()
	defer s.stored.openMu.Unlock()
	s.mu.Lock()
	f := &s.files[fi]
	if !f.needsOpen() {
		s.mu.Unlock()
		return
	}
	ref, left := *f.stored, maxStoredText-s.stored.held
	s.mu.Unlock()
	text, truncated, err := g.fetchStored(ctx, t, &ref, left)
	if ctx.Err() != nil { // cancelled: not refused, it may open later (a restart's files.read)
		return
	}
	s.mu.Lock()
	if err != nil {
		f.openErr = storedError(err)
		s.mu.Unlock()
		return
	}
	f.text, f.truncated, f.opened = text, truncated, true
	f.secs = splitSections(text, t.def.PartRunes)
	f.state = make([]secState, len(f.secs))
	s.stored.held += int64(len(text))
	for _, so := range s.stored.restored[fi] { // what a restart's journal says was read of it
		if so.Part >= 1 && so.Part <= len(f.state) {
			st := &f.state[so.Part-1]
			if so.Read != nil {
				st.ok, st.injected = true, max(st.injected, so.Read.InstructionCount)
			} else {
				st.tries++
			}
		}
	}
	delete(s.stored.restored, fi)
	s.mu.Unlock()
	s.addPassages(text)
}

// fetchStored reads up to left bytes of ref's text, checked as the policy and the run's limits say.
func (g *Guard) fetchStored(ctx context.Context, t *task, ref *proto.StoredFile, left int64) (string, bool, error) {
	c := g.cfg.Stored
	if c == nil || c.Fetcher == nil {
		return "", false, errors.New("this VM can't read stored files")
	}
	if left <= 0 {
		return "", false, fmt.Errorf("this task already holds %d MB of file text, as much as it can", maxStoredText>>20)
	}
	if err := g.checkSafety(t.opts.Space, &harness.Action{Name: storedFetchAction}); err != nil {
		return "", false, errors.New("reading stored files isn't allowed by the policy")
	}
	if st := g.cfg.Safety; st != nil { // every request's host, checked live (a narrower policy applies at once)
		space := t.opts.Space
		ctx = withHostFilter(ctx, func(host string) bool {
			e, err := st.Check(space, false)
			return err == nil && e.AllowsConnectorFetch("files", host)
		})
	}
	raw := ref.URL
	if raw == "" {
		var err error
		if raw, err = g.storedURL(ctx, t, ref.Object); err != nil {
			return "", false, err
		}
	}
	read, err := c.Fetcher.Reader(ref, raw, &t.files.stored.budget)
	if err != nil {
		return "", false, err
	}
	return storedfiles.OpenText(ctx, ref, read, left)
}

// storedURL is a schedule run's read URL for object: asked of the chat's Worker once for all the task's stored files
// without one (the grant names them all), then kept for the task (an hour's URLs; a run's cap is less). openMu held.
func (g *Guard) storedURL(ctx context.Context, t *task, object string) (string, error) {
	s := &t.files.stored
	if s.urls == nil && s.urlsErr == "" {
		c := g.cfg.Stored
		switch {
		case t.opts.FilesGrant == "":
			s.urlsErr = "no read URL and no grant to ask for one"
		case c.URLs == nil:
			s.urlsErr = "this VM can't ask for read URLs"
		default:
			var objects []string
			owner := ""
			for _, f := range t.opts.Stored {
				if f.URL == "" {
					objects = append(objects, f.Object)
					owner = f.Owner
				}
			}
			urls, err := c.URLs.URLs(ctx, t.opts.FilesGrant, owner, objects)
			if err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				s.urlsErr = err.Error()
			} else {
				s.urls = urls
			}
		}
	}
	if s.urlsErr != "" {
		return "", errors.New(s.urlsErr)
	}
	if u := s.urls[object]; u != "" {
		return u, nil
	}
	return "", errors.New("no read URL for the file")
}

// storedError is why a stored file couldn't be opened, in plain words (nothing of the file's bytes or its URL).
func storedError(err error) string {
	switch {
	case errors.Is(err, storedfiles.ErrNotText):
		return "not a text file Tacy can read yet"
	case errors.Is(err, storedfiles.ErrEmpty):
		return "the file is empty"
	case errors.Is(err, storedfiles.ErrChunk), errors.Is(err, storedfiles.ErrLength), errors.Is(err, storedfiles.ErrPadding):
		return "the stored file failed its integrity check (changed, swapped or damaged), so nothing of it was read"
	case errors.Is(err, storedfiles.ErrScope):
		return "its read address isn't this file's, so nothing was fetched"
	case errors.Is(err, storedfiles.ErrBudget):
		return err.Error()
	case errors.Is(err, errHostPolicy):
		return "the files host isn't allowed by the policy"
	}
	msg := strings.TrimPrefix(err.Error(), "storedfiles: ")
	if !utf8.ValidString(msg) || len(msg) > 200 {
		msg = "it couldn't be fetched"
	}
	return msg
}

// storedRead is files.list's note for a stored file: why it isn't open, or that it was cut.
func (f *reviewFile) storedNote() string {
	switch {
	case f.stored == nil:
		return ""
	case f.openErr != "":
		return "couldn't be opened: " + f.openErr
	case !f.opened:
		return "stored file, opened when first read"
	case f.truncated:
		return fmt.Sprintf("only its first %s characters were read (the file is longer than a task can hold)", thousands(utf8.RuneCountInString(f.text)))
	}
	return ""
}

// storedIntake checks a request's stored files for agent d, which has attached more files: storedfiles.Check (each
// ref, one owner, 200 files, 200 MB), and a review's cap on files (it reads every part of every one).
func storedIntake(d AgentDef, attached int, st []proto.StoredFile) error {
	if len(st) == 0 {
		return nil
	}
	if err := storedfiles.Check(st, true); err != nil {
		return err
	}
	if d.NoEgress && attached+len(st) > maxReviewFiles {
		return fmt.Errorf("%s takes at most %d files", d.ID, maxReviewFiles)
	}
	return nil
}

// storedList is the stored files' lines in the brief's list of files (after fileList's, numbered on from them): name
// and size only, since their text isn't open yet.
func storedList(attached int, st []proto.StoredFile) string {
	var b strings.Builder
	for i, f := range st {
		fmt.Fprintf(&b, "\n%d. %s: %s bytes, a stored file (opened when first read)", attached+i+1, storedName(f), thousands(int(f.Size)))
	}
	return b.String()
}

// quotesOf is the quote numbers of a reader's view (nil: none).
func quotesOf(v *readView) []int {
	if v == nil {
		return nil
	}
	ids := make([]int, 0, len(v.Quotes))
	for _, q := range v.Quotes {
		ids = append(ids, q.ID)
	}
	return ids
}

// StoredPolicyError is agentd's refusal of a task with stored files under a policy without files.fetch.
func StoredPolicyError(e *safety.Effective) error {
	if e.AllowsTool("files.read") && e.AllowsTool(storedFetchAction) {
		return nil
	}
	return &safety.Error{Code: safety.CodePolicyDenied, Msg: "reading stored files isn't allowed by the policy (it has no files.fetch)"}
}
