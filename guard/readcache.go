package guard

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strconv"
	"sync"
)

// readCache keeps the reader's checked answers for one task, in memory only: the same item read again in the task
// (a page fetched twice, the same search twice) reuses the answer instead of another reader call. It lives in the
// task (guard.go), so it never crosses tasks or people, and it goes when the task does. Only answers that were
// shown are kept: a refused, failed or timed-out read runs again.
type readCache struct {
	mu sync.Mutex
	m  map[[32]byte]*readerResult
}

// maxCachedReads bounds one task's cache (a task reads a few dozen items at most).
const maxCachedReads = 64

// get returns a copy of the answer for key (its quotes get the task's next numbers again), or nil.
func (c *readCache) get(key [32]byte) *readerResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.m[key]
	if r == nil {
		return nil
	}
	return r.clone()
}

func (c *readCache) put(key [32]byte, r *readerResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[[32]byte]*readerResult{}
	}
	if len(c.m) < maxCachedReads {
		c.m[key] = r.clone()
	}
}

// clone copies what view changes (the quotes' task numbers); the decoded fields are only read from here on.
func (r *readerResult) clone() *readerResult {
	return &readerResult{out: r.out, quotes: slices.Clone(r.quotes), err: r.err}
}

// key identifies an item as read: the reader's settings, the question (context the answer depends on), the
// address and every byte of the content the reader gets.
func (d *readerDoc) key(rc *ReaderConfig, question string) [32]byte {
	h := sha256.New()
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	facts, quotes, spans := rc.caps()
	put(rc.Model)
	put(rc.Effort)
	put(strconv.FormatBool(rc.Spans) + "/" + strconv.Itoa(facts) + "/" + strconv.Itoa(quotes) + "/" + strconv.Itoa(spans))
	put(question)
	put(d.kind)
	put(d.url)
	put(d.title)
	put(d.text)
	for _, r := range d.results {
		put(r.Title)
		put(r.Snippet)
	}
	var k [32]byte
	h.Sum(k[:0])
	return k
}
