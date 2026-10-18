// Package queue is the runtime's queue in SQLite: the harness.Store the agent VM runs on. One database file
// per space on the VM's encrypted disk, the runtime its only writer: tasks (start, the person's options, attempts,
// lifecycle state, outcome), steering, the journal (the outbox: every model call, action and exec by task and
// request id, recorded before it runs, held ones marked), the brain's checkpoints and the events people follow
// (docs/27 section 2). A runtime restart reads them back (harness.Runtime.Restore).
//
// The schema is versioned (PRAGMA user_version) and only ever migrated forward, in one transaction per step, so a
// VM updated in place keeps its queue: version 1 is the first release's tables, version 2 adds the task model,
// version 3 the task's taint.
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
	"time"

	_ "modernc.org/sqlite"

	"github.com/tacyhq/tacy/harness"
)

// migrations are the schema's versions in order: migrations[i] takes the database from version i to i+1. Never
// edit one that has shipped; add the next.
var migrations = []string{
	// 1: the first release (the task model's first slices).
	`CREATE TABLE IF NOT EXISTS tasks (
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
	);`,
	// 2: the task model (docs/27 slice 1): lifecycle state, brain failures, times, held requests, events.
	`ALTER TABLE tasks ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE tasks ADD COLUMN state TEXT NOT NULL DEFAULT 'queued';
	ALTER TABLE tasks ADD COLUMN sub TEXT NOT NULL DEFAULT '';
	ALTER TABLE tasks ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE tasks ADD COLUMN ended_at INTEGER;
	ALTER TABLE journal ADD COLUMN held TEXT;
	CREATE INDEX tasks_ended ON tasks (ended, ended_at);
	CREATE TABLE events (
		task TEXT NOT NULL,
		seq  INTEGER NOT NULL,
		data BLOB NOT NULL,
		PRIMARY KEY (task, seq)
	);`,
	// 3: per-task taint (docs/27 slice 2): the request whose result first brought untrusted content in.
	`ALTER TABLE tasks ADD COLUMN taint TEXT NOT NULL DEFAULT '';`,
}

// SchemaVersion is the version Open migrates to.
var SchemaVersion = len(migrations)

// migrate brings the database to SchemaVersion, one step per transaction. A database newer than this code is
// refused (a rollback after a migration needs the newer release back, not a guess).
func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("schema version %d is newer than this release's %d", v, len(migrations))
	}
	for ; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

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
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue: %w", err)
	}
	if err := tidyAfterOlder(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue: %w", err)
	}
	return &Store{db: db}, nil
}

// tidyAfterOlder repairs what a release before the versioned schema (v0.6.0 and older, the rollback target) leaves
// when it runs on a migrated file: it ignores user_version and uses only the version 1 columns, so it works, but it
// ends tasks without their state and end time and deletes tasks without their events. Here those tasks get both
// (so retention prunes them), and orphaned events go. Idempotent; a no-op on a file only this release wrote.
func tidyAfterOlder(db *sql.DB) error {
	if _, err := db.Exec(`UPDATE tasks SET state = CASE outcome WHEN ? THEN ? WHEN ? THEN ? ELSE ? END, sub = '', ended_at = ?
		WHERE ended = 1 AND ended_at IS NULL`,
		harness.OutcomeSucceeded, harness.StateDone, harness.OutcomeCancelled, harness.StateCancelled, harness.StateFailed, ms(time.Now())); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM events WHERE task NOT IN (SELECT id FROM tasks)`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

// nullable stores nil as NULL (and reads it back as nil).
func nullable(v []byte) any {
	if v == nil {
		return nil
	}
	return []byte(v)
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMs(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64).UTC()
}

func (s *Store) AddTask(id string, start, opts jsontext.Value) error {
	_, err := s.db.Exec(`INSERT INTO tasks (id, start, options, created_at) VALUES (?, ?, ?, ?)`, id, []byte(start), nullable(opts),
		ms(time.Now()))
	return err
}

func (s *Store) SetAttempt(id string, attempt, failures int) error {
	_, err := s.db.Exec(`UPDATE tasks SET attempt = ?, failures = ? WHERE id = ?`, attempt, failures, id)
	return err
}

func (s *Store) SetState(id, state, sub string) error {
	_, err := s.db.Exec(`UPDATE tasks SET state = ?, sub = ? WHERE id = ? AND ended = 0`, state, sub, id)
	return err
}

func (s *Store) SetTaint(id, by string) error {
	_, err := s.db.Exec(`UPDATE tasks SET taint = ? WHERE id = ? AND taint = ''`, by, id)
	return err
}

func (s *Store) AddSteer(id string, st harness.Steer) error {
	_, err := s.db.Exec(`INSERT INTO steers (task, n, text) VALUES (?, ?, ?)`, id, st.N, st.Text)
	return err
}

func (s *Store) EndTask(id string, o harness.Outcome) error {
	_, err := s.db.Exec(`UPDATE tasks SET ended = 1, outcome = ?, state = ?, sub = '', ended_at = ? WHERE id = ? AND ended = 0`,
		o.State, harness.EndState(o.State), ms(time.Now()), id)
	return err
}

const taskCols = `id, start, options, attempt, failures, state, sub, created_at, ended_at, outcome, taint`

func scanTask(row scanner) (harness.StoredTask, error) {
	var t harness.StoredTask
	var start, opts []byte
	var created int64
	var ended sql.NullInt64
	var outcome sql.NullString
	if err := row.Scan(&t.ID, &start, &opts, &t.Attempt, &t.Failures, &t.State, &t.Sub, &created, &ended, &outcome, &t.Taint); err != nil {
		return t, err
	}
	t.Start, t.Options, t.Outcome = start, opts, outcome.String
	t.Created, t.Ended = time.UnixMilli(created).UTC(), fromMs(ended)
	return t, nil
}

func (s *Store) OpenTasks() ([]harness.StoredTask, error) {
	rows, err := s.db.Query(`SELECT ` + taskCols + ` FROM tasks WHERE ended = 0 ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	var out []harness.StoredTask
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
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

func (s *Store) Task(id string) (*harness.StoredTask, error) {
	t, err := scanTask(s.db.QueryRow(`SELECT `+taskCols+` FROM tasks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) EndedBefore(before time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM tasks WHERE ended = 1 AND ended_at < ? ORDER BY seq`, ms(before))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTask(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM tasks WHERE id = ?`, `DELETE FROM steers WHERE task = ?`,
		`DELETE FROM journal WHERE task = ?`, `DELETE FROM checkpoints WHERE task = ?`, `DELETE FROM events WHERE task = ?`} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddEvents(task string, evs []harness.StoredEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range evs {
		if _, err := tx.Exec(`INSERT INTO events (task, seq, data) VALUES (?, ?, ?)`, task, e.Seq, e.Data); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Events(task string, after, limit int) ([]harness.StoredEvent, error) {
	rows, err := s.db.Query(`SELECT seq, data FROM events WHERE task = ? AND seq > ? ORDER BY seq LIMIT ?`, task, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []harness.StoredEvent
	for rows.Next() {
		var e harness.StoredEvent
		if err := rows.Scan(&e.Seq, &e.Data); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Hold(task, id, sub string) error {
	_, err := s.db.Exec(`UPDATE journal SET held = ? WHERE task = ? AND id = ? AND done = 0`, sub, task, id)
	return err
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
	rec, err := scanRecord(tx.QueryRow(`SELECT `+recCols+` FROM journal WHERE task = ? AND id = ?`, task, id))
	if err != nil {
		return harness.Record{}, false, err
	}
	return rec, false, tx.Commit()
}

type scanner interface{ Scan(...any) error }

const recCols = `id, kind, hash, req, done, held, body, err`

func scanRecord(row scanner) (harness.Record, error) {
	var r harness.Record
	var hash, req, body, errb []byte
	var done int
	var held sql.NullString
	if err := row.Scan(&r.ID, &r.Kind, &hash, &req, &done, &held, &body, &errb); err != nil {
		return r, err
	}
	r.Held = held.String
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
	rows, err := s.db.Query(`SELECT `+recCols+` FROM journal WHERE task = ? ORDER BY seq`, task)
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
