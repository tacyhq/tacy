package activity

import (
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// OpenRun is a run whose start record was written and whose end wasn't yet: kept on disk, so a process that
// starts after a crash writes its end (interrupted).
type OpenRun struct {
	Run      string    `json:"run"`
	Space    string    `json:"space"`
	To       string    `json:"to"`
	StartSeq uint64    `json:"start_seq"`
	Started  time.Time `json:"started"`
}

// Store keeps the chains' heads, the sealed records (until they're pruned) and the open runs. The real one is
// SQLite on the VM's encrypted disk (OpenStore); MemStore is for local development and tests.
type Store interface {
	// Head is a chain's last sequence number and hash (0 and "" for a new chain).
	Head(chain string) (Link, error)
	// Append stores record r as the chain's next one: it fails unless the head is still `after` (one writer).
	// open is recorded with it (a start record), and closed (an end record): one transaction.
	Append(chain string, after Link, next Link, r Sealed, at time.Time, open *OpenRun, closed string) error
	// Records are a chain's records after seq, oldest first, at most limit.
	Records(chain string, after uint64, limit int) ([]Sealed, error)
	// OpenRuns are the runs with a start record and no end, oldest first.
	OpenRuns() ([]OpenRun, error)
	// Prune drops records older than before; heads and open runs stay.
	Prune(before time.Time) error
}

var errHeadMoved = errors.New("activity: chain head moved")

// MemStore is a Store in memory.
type MemStore struct {
	mu    sync.Mutex
	heads map[string]Link
	recs  map[string][]memRec
	open  map[string]OpenRun
}

type memRec struct {
	seq uint64
	at  time.Time
	r   Sealed
}

// NewMemStore makes an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{heads: map[string]Link{}, recs: map[string][]memRec{}, open: map[string]OpenRun{}}
}

func (m *MemStore) Head(chain string) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.heads[chain], nil
}

func (m *MemStore) Append(chain string, after, next Link, r Sealed, at time.Time, open *OpenRun, closed string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.heads[chain] != after {
		return errHeadMoved
	}
	m.heads[chain] = next
	m.recs[chain] = append(m.recs[chain], memRec{next.Seq, at, r})
	if open != nil {
		m.open[open.Run] = *open
	}
	if closed != "" {
		delete(m.open, closed)
	}
	return nil
}

func (m *MemStore) Records(chain string, after uint64, limit int) ([]Sealed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Sealed
	for _, r := range m.recs[chain] {
		if r.seq > after && len(out) < limit {
			out = append(out, r.r)
		}
	}
	return out, nil
}

func (m *MemStore) OpenRuns() ([]OpenRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OpenRun
	for _, o := range m.open {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, nil
}

func (m *MemStore) Prune(before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for c, rs := range m.recs {
		kept := rs[:0]
		for _, r := range rs {
			if !r.at.Before(before) {
				kept = append(kept, r)
			}
		}
		m.recs[c] = kept
	}
	return nil
}

// Remove drops record seq of chain (tests: a host that deletes a record).
func (m *MemStore) Remove(chain string, seq uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := m.recs[chain]
	for i, r := range rs {
		if r.seq == seq {
			m.recs[chain] = append(rs[:i:i], rs[i+1:]...)
			return
		}
	}
}

const schema = `
CREATE TABLE IF NOT EXISTS heads (
	chain TEXT PRIMARY KEY,
	seq   INTEGER NOT NULL,
	hash  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
	chain  TEXT NOT NULL,
	seq    INTEGER NOT NULL,
	at     INTEGER NOT NULL,
	record BLOB NOT NULL,
	PRIMARY KEY (chain, seq)
);
CREATE INDEX IF NOT EXISTS records_at ON records(at);
CREATE TABLE IF NOT EXISTS open_runs (
	run  TEXT PRIMARY KEY,
	data BLOB NOT NULL,
	at   INTEGER NOT NULL
);
`

// SQLStore is a Store in one SQLite file (WAL, synchronous FULL: a record written is on disk before the run goes
// on; secure_delete: pruned records are zeroed).
type SQLStore struct {
	db *sql.DB
}

// OpenStore opens (or creates) the store at path (directory 0700, file 0600).
func OpenStore(path string) (*SQLStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "secure_delete(ON)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("activity: %w", err)
	}
	return &SQLStore{db: db}, nil
}

// Close closes the database.
func (s *SQLStore) Close() error { return s.db.Close() }

func (s *SQLStore) Head(chain string) (Link, error) {
	var l Link
	err := s.db.QueryRow("SELECT seq, hash FROM heads WHERE chain = ?", chain).Scan(&l.Seq, &l.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return Link{}, nil
	}
	return l, err
}

func (s *SQLStore) Append(chain string, after, next Link, r Sealed, at time.Time, open *OpenRun, closed string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur Link
	err = tx.QueryRow("SELECT seq, hash FROM heads WHERE chain = ?", chain).Scan(&cur.Seq, &cur.Hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if cur != after {
		return errHeadMoved
	}
	rec, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO heads (chain, seq, hash) VALUES (?, ?, ?) ON CONFLICT(chain) DO UPDATE SET seq = excluded.seq, hash = excluded.hash",
		chain, next.Seq, next.Hash); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO records (chain, seq, at, record) VALUES (?, ?, ?, ?)", chain, next.Seq, at.Unix(), rec); err != nil {
		return err
	}
	if open != nil {
		b, _ := json.Marshal(open)
		if _, err := tx.Exec("INSERT INTO open_runs (run, data, at) VALUES (?, ?, ?)", open.Run, b, open.Started.UnixNano()); err != nil {
			return err
		}
	}
	if closed != "" {
		if _, err := tx.Exec("DELETE FROM open_runs WHERE run = ?", closed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) Records(chain string, after uint64, limit int) ([]Sealed, error) {
	rows, err := s.db.Query("SELECT record FROM records WHERE chain = ? AND seq > ? ORDER BY seq LIMIT ?", chain, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sealed
	for rows.Next() {
		var b []byte
		var r Sealed
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) OpenRuns() ([]OpenRun, error) {
	rows, err := s.db.Query("SELECT data FROM open_runs ORDER BY at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenRun
	for rows.Next() {
		var b []byte
		var o OpenRun
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if json.Unmarshal(b, &o) == nil {
			out = append(out, o)
		}
	}
	return out, rows.Err()
}

func (s *SQLStore) Prune(before time.Time) error {
	_, err := s.db.Exec("DELETE FROM records WHERE at < ?", before.Unix())
	return err
}
