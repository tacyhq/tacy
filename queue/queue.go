// Package queue is the runtime's queue in SQLite: the harness.Store the agent VM runs on. One database file
// per space on the VM's encrypted disk, the runtime its only writer: tasks (start, the person's options, attempts,
// outcome), steering, the journal (the outbox: every model call, action and exec by task and request id, recorded
// before it runs) and the brain's checkpoints. A runtime restart reads them back (harness.Runtime.Restore).
//
// Durability: WAL with synchronous=FULL, so a request recorded as begun stays recorded across a power cut (the
// guard's "never twice" rests on it). secure_delete zeroes what Forget removes. Pure Go (modernc.org/sqlite, no
// cgo), so the build stays reproducible.
package queue

import (
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/tacyhq/tacy/harness"
)

const schema = `
CREATE TABLE IF NOT EXISTS tasks (
	seq     INTEGER PRIMARY KEY AUTOINCREMENT,
	id      TEXT NOT NULL UNIQUE,
	start   BLOB NOT NULL,
	options BLOB,
	attempt INTEGER NOT NULL DEFAULT 0,
	ended   INTEGER NOT NULL DEFAULT 0,
	outcome TEXT
);
CREATE TABLE IF NOT EXISTS steers (
	task TEXT NOT NULL,
	n    INTEGER NOT NULL,
	text TEXT NOT NULL,
	PRIMARY KEY (task, n)
);
CREATE TABLE IF NOT EXISTS journal (
	seq  INTEGER PRIMARY KEY AUTOINCREMENT,
	task TEXT NOT NULL,
	id   TEXT NOT NULL,
	kind TEXT NOT NULL,
	hash BLOB NOT NULL,
	req  BLOB,
	done INTEGER NOT NULL DEFAULT 0,
	body BLOB,
	err  BLOB,
	UNIQUE (task, id)
);
CREATE TABLE IF NOT EXISTS checkpoints (
	task          TEXT PRIMARY KEY,
	seq           INTEGER NOT NULL,
	steer_applied INTEGER NOT NULL,
	state         BLOB NOT NULL
);
`

// Store is a harness.Store in one SQLite file.
type Store struct {
	db *sql.DB
}

var _ harness.Store = (*Store)(nil)

// Open opens (or creates) the queue at path. The directory is made 0700 and the file 0600.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "secure_delete(ON)", "foreign_keys(ON)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer, one connection: every method is one transaction, in order
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// nullable stores nil as NULL (and reads it back as nil).
func nullable(v []byte) any {
	if v == nil {
		return nil
	}
	return []byte(v)
}

func (s *Store) AddTask(id string, start, opts jsontext.Value) error {
	_, err := s.db.Exec(`INSERT INTO tasks (id, start, options) VALUES (?, ?, ?)`, id, []byte(start), nullable(opts))
	return err
}

func (s *Store) SetAttempt(id string, n int) error {
	_, err := s.db.Exec(`UPDATE tasks SET attempt = ? WHERE id = ?`, n, id)
	return err
}

func (s *Store) AddSteer(id string, st harness.Steer) error {
	_, err := s.db.Exec(`INSERT INTO steers (task, n, text) VALUES (?, ?, ?)`, id, st.N, st.Text)
	return err
}

func (s *Store) EndTask(id string, o harness.Outcome) error {
	_, err := s.db.Exec(`UPDATE tasks SET ended = 1, outcome = ? WHERE id = ?`, o.State, id)
	return err
}

func (s *Store) OpenTasks() ([]harness.StoredTask, error) {
	rows, err := s.db.Query(`SELECT id, start, options, attempt FROM tasks WHERE ended = 0 ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	var out []harness.StoredTask
	for rows.Next() {
		var t harness.StoredTask
		var start, opts []byte
		if err := rows.Scan(&t.ID, &start, &opts, &t.Attempt); err != nil {
			rows.Close()
			return nil, err
		}
		t.Start, t.Options = start, opts
		out = append(out, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		srows, err := s.db.Query(`SELECT n, text FROM steers WHERE task = ? ORDER BY n`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for srows.Next() {
			var st harness.Steer
			if err := srows.Scan(&st.N, &st.Text); err != nil {
				srows.Close()
				return nil, err
			}
			out[i].Steers = append(out[i].Steers, st)
		}
		srows.Close()
		if err := srows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) DeleteTask(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM tasks WHERE id = ?`, `DELETE FROM steers WHERE task = ?`,
		`DELETE FROM journal WHERE task = ?`, `DELETE FROM checkpoints WHERE task = ?`} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Begin(task, id, kind string, hash [32]byte, req jsontext.Value) (harness.Record, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return harness.Record{}, false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO journal (task, id, kind, hash, req) VALUES (?, ?, ?, ?, ?) ON CONFLICT (task, id) DO NOTHING`,
		task, id, kind, hash[:], nullable(req))
	if err != nil {
		return harness.Record{}, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		if err := tx.Commit(); err != nil {
			return harness.Record{}, false, err
		}
		return harness.Record{ID: id, Kind: kind, Hash: hash, Req: req.Clone()}, true, nil
	}
	rec, err := scanRecord(tx.QueryRow(`SELECT id, kind, hash, req, done, body, err FROM journal WHERE task = ? AND id = ?`, task, id))
	if err != nil {
		return harness.Record{}, false, err
	}
	return rec, false, tx.Commit()
}

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner) (harness.Record, error) {
	var r harness.Record
	var hash, req, body, errb []byte
	var done int
	if err := row.Scan(&r.ID, &r.Kind, &hash, &req, &done, &body, &errb); err != nil {
		return r, err
	}
	if len(hash) != 32 {
		return r, errors.New("queue: bad hash in the journal")
	}
	copy(r.Hash[:], hash)
	r.Req, r.Done, r.Body = req, done == 1, body
	if errb != nil {
		r.Err = &harness.Error{}
		if err := json.Unmarshal(errb, r.Err); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (s *Store) Finish(task, id string, body jsontext.Value, e *harness.Error) error {
	var errb []byte
	if e != nil {
		var err error
		if errb, err = json.Marshal(e); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`UPDATE journal SET done = 1, body = ?, err = ? WHERE task = ? AND id = ?`, nullable(body), nullable(errb), task, id)
	return err
}

func (s *Store) Journal(task string) ([]harness.Record, error) {
	rows, err := s.db.Query(`SELECT id, kind, hash, req, done, body, err FROM journal WHERE task = ? ORDER BY seq`, task)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []harness.Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveCheckpoint(task string, cp *harness.Checkpoint) error {
	_, err := s.db.Exec(`INSERT INTO checkpoints (task, seq, steer_applied, state) VALUES (?, ?, ?, ?)
		ON CONFLICT (task) DO UPDATE SET seq = excluded.seq, steer_applied = excluded.steer_applied, state = excluded.state`,
		task, cp.Seq, cp.SteerApplied, []byte(cp.State))
	return err
}

func (s *Store) Checkpoint(task string) (*harness.Checkpoint, error) {
	var cp harness.Checkpoint
	var state []byte
	err := s.db.QueryRow(`SELECT seq, steer_applied, state FROM checkpoints WHERE task = ?`, task).Scan(&cp.Seq, &cp.SteerApplied, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cp.State = state
	return &cp, nil
}
