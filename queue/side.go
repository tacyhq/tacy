package queue

import (
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// Side is the second SQLite file next to the queue (docs/27 section 2): held approvals and their
// effects (the outbox: held → approved → sending → sent | failed | unknown), agent definitions, schedule slots
// fired, event deliveries seen and the clock's high-water mark. Its own file, not a migration of the queue's: a
// release before this one refuses a queue newer than its schema, so a rollback must find the queue file at the
// version it knows; it simply never opens this one. Same durability settings as the queue.
type Side struct {
	db *sql.DB
}

var (
	_ approval.Store      = (*Side)(nil)
	_ trigger.Store       = (*Side)(nil)
	_ trigger.HolderStore = (*Side)(nil)
	_ trigger.ResultStore = (*Side)(nil)
	_ trigger.MemoryStore = (*Side)(nil)
)

// sideMigrations are the side file's schema versions (PRAGMA user_version), forward only.
var sideMigrations = []string{
	// 1: approvals and their effects; definitions, fired slots, seen deliveries, the clock's high-water mark.
	`CREATE TABLE approvals (
		seq         INTEGER PRIMARY KEY AUTOINCREMENT,
		id          TEXT NOT NULL UNIQUE,
		firm        TEXT NOT NULL,
		space       TEXT NOT NULL,
		task        TEXT NOT NULL,
		request     TEXT NOT NULL,
		action      TEXT NOT NULL,
		effect      BLOB NOT NULL,
		effect_hash TEXT NOT NULL,
		approvers   BLOB NOT NULL,
		expires_at  INTEGER NOT NULL,
		created_at  INTEGER NOT NULL,
		state       TEXT NOT NULL,
		decision    BLOB
	);
	CREATE INDEX approvals_task ON approvals (task);
	CREATE INDEX approvals_state ON approvals (state);
	CREATE TABLE definitions (
		agent   TEXT PRIMARY KEY,
		version INTEGER NOT NULL,
		env     BLOB NOT NULL
	);
	CREATE TABLE fired (
		trigger TEXT PRIMARY KEY,
		slot    INTEGER NOT NULL
	);
	CREATE TABLE seen (
		trigger  TEXT NOT NULL,
		delivery TEXT NOT NULL,
		until    INTEGER NOT NULL,
		PRIMARY KEY (trigger, delivery)
	);
	CREATE TABLE clock (
		one        INTEGER PRIMARY KEY CHECK (one = 1),
		high_water INTEGER NOT NULL
	);`,
	// 2 (v0.12.0, schedules for personal spaces): a definition's state (active, stopped, removed: the version floor
	// stays), the identities that proved they hold a space, and scheduled runs' sealed results.
	`ALTER TABLE definitions ADD COLUMN state TEXT NOT NULL DEFAULT 'active';
	CREATE TABLE holders (
		space    TEXT NOT NULL,
		identity TEXT NOT NULL,
		key      TEXT NOT NULL,
		seal     TEXT NOT NULL,
		at       INTEGER NOT NULL,
		PRIMARY KEY (space, identity)
	);
	CREATE TABLE results (
		seq          INTEGER PRIMARY KEY AUTOINCREMENT,
		task         TEXT NOT NULL UNIQUE,
		space        TEXT NOT NULL,
		seal         TEXT NOT NULL,
		agent        TEXT NOT NULL,
		version      INTEGER NOT NULL,
		trigger      TEXT NOT NULL,
		day          TEXT NOT NULL,
		scheduled_at INTEGER NOT NULL,
		started_at   INTEGER NOT NULL,
		ended_at     INTEGER NOT NULL,
		state        TEXT NOT NULL,
		code         TEXT NOT NULL,
		enc          BLOB NOT NULL,
		ct           BLOB NOT NULL
	);
	CREATE INDEX results_space ON results (space, seal, seq);
	CREATE INDEX results_ended ON results (ended_at);`,
}

// sideExtras are additive changes made without raising the schema version (v0.15.0 on), so that the release before
// them still opens the file after a rollback: OpenSide refuses a user_version newer than its own, and v0.12.0-v0.14.0
// know 2 (a rollback to one of them would stop agentd at its start). Each is idempotent and one an older release
// ignores: a column with a default that it never names (it names its columns in every insert and select), a table it
// never reads. Rows it writes meanwhile get the default (a result not quiet); a person's daily schedule, its fired
// slots and results are untouched either way.
//
// Schedule upgrades (v0.15.0): a result's quiet mark (a run that found nothing changed and told nobody), and
// schedules' memory across runs (trigger/memory.go: the newest 7 runs per schedule, 30 days).
var sideExtras = []struct {
	missing string // a query that counts 0 while the change isn't made
	change  string
}{
	{`SELECT count(*) FROM pragma_table_info('results') WHERE name = 'quiet'`,
		`ALTER TABLE results ADD COLUMN quiet INTEGER NOT NULL DEFAULT 0`},
	{`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'memory'`,
		`CREATE TABLE memory (
		seq      INTEGER PRIMARY KEY AUTOINCREMENT,
		task     TEXT NOT NULL UNIQUE,
		space    TEXT NOT NULL,
		agent    TEXT NOT NULL,
		day      TEXT NOT NULL,
		ended_at INTEGER NOT NULL,
		quiet    INTEGER NOT NULL,
		body     BLOB NOT NULL
	);
	CREATE INDEX memory_agent ON memory (space, agent, ended_at);
	CREATE INDEX memory_ended ON memory (ended_at);`},
	// v0.16.0: each personal space's pinned seal key (runauth.PinStore). Ids and public keys only.
	{`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'space_seals'`,
		`CREATE TABLE space_seals (
		space TEXT PRIMARY KEY,
		seal  TEXT NOT NULL,
		at    INTEGER NOT NULL
	);`},
}

// seedPins pins each personal space that has none yet to the seal key of its earliest holder record (the schedules
// installed before pins existed, or while a release without them ran after a rollback): the key that space's holder
// proved first, rather than whichever key asks next. Idempotent.
func seedPins(db *sql.DB) error {
	_, err := db.Exec(`INSERT INTO space_seals (space, seal, at)
		SELECT h.space, h.seal, h.at FROM holders h
		WHERE h.at = (SELECT min(at) FROM holders WHERE space = h.space) ORDER BY h.space, h.identity
		ON CONFLICT (space) DO NOTHING`)
	return err
}

// applyExtras makes the sideExtras not made yet, each in its own transaction.
func applyExtras(db *sql.DB) error {
	for i, x := range sideExtras {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		var n int
		if err = tx.QueryRow(x.missing).Scan(&n); err == nil && n == 0 {
			_, err = tx.Exec(x.change)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("queue side: extra %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// OpenSide opens (or creates) the side file at path: directory 0700, file 0600.
func OpenSide(path string) (*Side, error) {
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
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		db.Close()
		return nil, err
	}
	if v > len(sideMigrations) {
		db.Close()
		return nil, fmt.Errorf("queue side: schema version %d is newer than this release's %d", v, len(sideMigrations))
	}
	for ; v < len(sideMigrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err := tx.Exec(sideMigrations[v]); err == nil {
			_, err = tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
		}
		if err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("queue side: migration %d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := applyExtras(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := seedPins(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue side: seal pins: %w", err)
	}
	if err := purgeRemoved(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue side: removed definitions: %w", err)
	}
	return &Side{db: db}, nil
}

func (s *Side) Close() error { return s.db.Close() }

// ---- approvals ------------------------------------------------------------------------------------------------

func (s *Side) PutApproval(r approval.Record) (approval.Record, bool, error) {
	approvers, err := json.Marshal(r.Approvers)
	if err != nil {
		return approval.Record{}, false, err
	}
	res, err := s.db.Exec(`INSERT INTO approvals (id, firm, space, task, request, action, effect, effect_hash, approvers,
		expires_at, created_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
		r.ID, r.Firm, r.Space, r.Task, r.Request, r.Action, r.Effect, r.EffectHash, approvers, ms(r.ExpiresAt), ms(r.CreatedAt),
		approval.StateHeld)
	if err != nil {
		return approval.Record{}, false, err
	}
	n, _ := res.RowsAffected()
	got, err := s.Approval(r.ID)
	if err != nil || got == nil {
		return approval.Record{}, false, errors.Join(err, errors.New("queue side: approval not stored"))
	}
	return *got, n == 1, nil
}

const approvalCols = `id, firm, space, task, request, action, effect, effect_hash, approvers, expires_at, created_at, state, decision`

func scanApproval(row scanner) (approval.Record, error) {
	var r approval.Record
	var approvers []byte
	var exp, created int64
	if err := row.Scan(&r.ID, &r.Firm, &r.Space, &r.Task, &r.Request, &r.Action, &r.Effect, &r.EffectHash, &approvers, &exp,
		&created, &r.State, &r.Decision); err != nil {
		return r, err
	}
	if err := json.Unmarshal(approvers, &r.Approvers); err != nil {
		return r, err
	}
	r.ExpiresAt, r.CreatedAt = time.UnixMilli(exp).UTC(), time.UnixMilli(created).UTC()
	return r, nil
}

func (s *Side) Approval(id string) (*approval.Record, error) {
	r, err := scanApproval(s.db.QueryRow(`SELECT `+approvalCols+` FROM approvals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Side) MoveApproval(id, from, to string, decision []byte) error {
	if !approval.Allowed(from, to) {
		return approval.ErrState
	}
	res, err := s.db.Exec(`UPDATE approvals SET state = ?, decision = COALESCE(?, decision) WHERE id = ? AND state = ?`, to,
		nullable(decision), id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return approval.ErrState
	}
	return nil
}

func (s *Side) Approvals(states ...string) ([]approval.Record, error) {
	if len(states) == 0 {
		return nil, nil
	}
	q, args := `SELECT `+approvalCols+` FROM approvals WHERE state IN (?`, []any{states[0]}
	for _, st := range states[1:] {
		q += `, ?`
		args = append(args, st)
	}
	rows, err := s.db.Query(q+`) ORDER BY seq`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []approval.Record
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Side) DeleteApprovals(task string) error {
	_, err := s.db.Exec(`DELETE FROM approvals WHERE task = ?`, task)
	return err
}

// ---- triggers -------------------------------------------------------------------------------------------------

func (s *Side) SaveDefinition(agent string, version uint64, env []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var v int64
	var old []byte
	var state string
	switch err := tx.QueryRow(`SELECT version, env, state FROM definitions WHERE agent = ?`, agent).Scan(&v, &old, &state); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	case uint64(v) > version || uint64(v) == version && (string(old) != string(env) || state != trigger.StateActive):
		return trigger.ErrStale
	}
	if _, err := tx.Exec(`INSERT INTO definitions (agent, version, env, state) VALUES (?, ?, ?, ?)
		ON CONFLICT (agent) DO UPDATE SET version = excluded.version, env = excluded.env, state = excluded.state`,
		agent, int64(version), env, trigger.StateActive); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Side) Definitions() ([]trigger.Stored, error) {
	rows, err := s.db.Query(`SELECT env, state FROM definitions WHERE state != ? ORDER BY agent`, trigger.StateRemoved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []trigger.Stored
	for rows.Next() {
		var d trigger.Stored
		if err := rows.Scan(&d.Env, &d.State); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// removedEnv is a removed definition's envelope: none (the column can't be NULL). Its agent id, version and state
// stay, the version floor that refuses a replay of an older definition (SaveDefinition); its instructions don't.
var removedEnv = []byte{}

func (s *Side) SetState(agent string, version uint64, state string) error {
	res, err := s.db.Exec(`UPDATE definitions SET state = ?, env = CASE WHEN ? = ? THEN ? ELSE env END WHERE agent = ? AND version = ?`,
		state, state, trigger.StateRemoved, removedEnv, agent, int64(version))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return trigger.ErrStale
	}
	if state == trigger.StateRemoved {
		s.truncateWAL()
	}
	return nil
}

// purgeRemoved empties the envelopes of definitions removed before removals did (v0.12.0-v0.15.0, or while one of
// them ran after a rollback). Idempotent.
func purgeRemoved(db *sql.DB) error {
	res, err := db.Exec(`UPDATE definitions SET env = ? WHERE state = ? AND length(env) > 0`, removedEnv, trigger.StateRemoved)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return nil
}

// truncateWAL empties the write-ahead log after a purge, as the queue's (Store.truncateWAL).
func (s *Side) truncateWAL() {
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
}

// ---- personal spaces: pinned seal keys (runauth.PinStore) ----------------------------------------------------

var _ runauth.PinStore = (*Side)(nil)

func (s *Side) PinSeal(space, seal string, at time.Time) (string, error) {
	if _, err := s.db.Exec(`INSERT INTO space_seals (space, seal, at) VALUES (?, ?, ?) ON CONFLICT (space) DO NOTHING`,
		space, seal, ms(at)); err != nil {
		return "", err
	}
	var pinned string
	err := s.db.QueryRow(`SELECT seal FROM space_seals WHERE space = ?`, space).Scan(&pinned)
	return pinned, err
}

func (s *Side) RepinSeal(space, old, seal string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pinned string
	switch err := tx.QueryRow(`SELECT seal FROM space_seals WHERE space = ?`, space).Scan(&pinned); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO space_seals (space, seal, at) VALUES (?, ?, ?)`, space, seal, ms(at)); err != nil {
			return err
		}
	case err != nil:
		return err
	case pinned != old:
		return runauth.ErrSealPinned
	default:
		if _, err := tx.Exec(`UPDATE space_seals SET seal = ?, at = ? WHERE space = ?`, seal, ms(at), space); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- personal spaces: holders and results ---------------------------------------------------------------------

func (s *Side) PutHolder(h trigger.Holder) error {
	_, err := s.db.Exec(`INSERT INTO holders (space, identity, key, seal, at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (space, identity) DO UPDATE SET key = excluded.key, seal = excluded.seal, at = excluded.at`,
		h.Space, h.Identity, h.Key, h.Seal, ms(h.At))
	return err
}

func (s *Side) Holder(space, id string) (*trigger.Holder, error) {
	h := trigger.Holder{Space: space, Identity: id}
	var at int64
	err := s.db.QueryRow(`SELECT key, seal, at FROM holders WHERE space = ? AND identity = ?`, space, id).Scan(&h.Key, &h.Seal, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	h.At = time.UnixMilli(at).UTC()
	return &h, nil
}

func (s *Side) PutResult(r trigger.Result) (int64, error) {
	if _, err := s.db.Exec(`INSERT INTO results (task, space, seal, agent, version, trigger, day, scheduled_at, started_at,
		ended_at, state, code, enc, ct, quiet) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (task) DO NOTHING`,
		r.Task, r.Space, r.Seal, r.Agent, int64(r.Version), r.Trigger, r.Day, ms(r.ScheduledAt), ms(r.StartedAt), ms(r.EndedAt),
		r.State, r.Code, r.Enc, r.CT, r.Quiet); err != nil {
		return 0, err
	}
	var seq int64
	err := s.db.QueryRow(`SELECT seq FROM results WHERE task = ?`, r.Task).Scan(&seq)
	return seq, err
}

const resultCols = `seq, task, space, seal, agent, version, trigger, day, scheduled_at, started_at, ended_at, state, code, quiet`

func scanResult(row scanner, extra ...any) (trigger.Result, error) {
	var r trigger.Result
	var v, sch, st, en int64
	if err := row.Scan(append([]any{&r.Seq, &r.Task, &r.Space, &r.Seal, &r.Agent, &v, &r.Trigger, &r.Day, &sch, &st, &en,
		&r.State, &r.Code, &r.Quiet}, extra...)...); err != nil {
		return r, err
	}
	r.Version = uint64(v)
	r.ScheduledAt, r.StartedAt, r.EndedAt = time.UnixMilli(sch).UTC(), time.UnixMilli(st).UTC(), time.UnixMilli(en).UTC()
	return r, nil
}

func (s *Side) Results(space, seal string, after int64, limit int) ([]trigger.Result, error) {
	rows, err := s.db.Query(`SELECT `+resultCols+`, length(ct) FROM results WHERE space = ? AND seal = ? AND seq > ?
		ORDER BY seq LIMIT ?`, space, seal, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []trigger.Result
	for rows.Next() {
		var n int
		r, err := scanResult(rows, &n)
		if err != nil {
			return nil, err
		}
		r.CT = make([]byte, 0, n) // the size, without the bytes
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Side) GetResult(space, seal, task string) (*trigger.Result, error) {
	var enc, ct []byte
	r, err := scanResult(s.db.QueryRow(`SELECT `+resultCols+`, enc, ct FROM results WHERE space = ? AND seal = ? AND task = ?`,
		space, seal, task), &enc, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Enc, r.CT = enc, ct
	return &r, nil
}

func (s *Side) DeleteResults(space, seal string, tasks []string) (int, error) {
	n := 0
	for _, t := range tasks {
		res, err := s.db.Exec(`DELETE FROM results WHERE space = ? AND seal = ? AND task = ?`, space, seal, t)
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, nil
}

func (s *Side) DeleteAgentResults(space, agent string) (int, error) {
	res, err := s.db.Exec(`DELETE FROM results WHERE space = ? AND agent = ?`, space, agent)
	if err != nil {
		return 0, err
	}
	k, _ := res.RowsAffected()
	return int(k), nil
}

func (s *Side) PruneResults(t time.Time) error {
	_, err := s.db.Exec(`DELETE FROM results WHERE ended_at < ?`, ms(t))
	return err
}

// memoryBody is a memory row's body: what the run found (trigger.Remembered's text and sources).
type memoryBody struct {
	Text    string                     `json:"text,omitzero"`
	Sources []trigger.RememberedSource `json:"sources,omitzero"`
}

func (s *Side) PutMemory(m trigger.Remembered) error {
	m = m.Capped()
	body, err := json.Marshal(memoryBody{Text: m.Text, Sources: m.Sources})
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO memory (task, space, agent, day, ended_at, quiet, body) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (task) DO NOTHING`, m.Task, m.Space, m.Agent, m.Day, ms(m.EndedAt), m.Quiet, body); err != nil {
		return err
	}
	// Only the newest MemoryRuns of the schedule stay.
	if _, err := tx.Exec(`DELETE FROM memory WHERE space = ? AND agent = ? AND seq NOT IN (SELECT seq FROM memory
		WHERE space = ? AND agent = ? ORDER BY ended_at DESC, seq DESC LIMIT ?)`, m.Space, m.Agent, m.Space, m.Agent, trigger.MemoryRuns); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Side) Memories(space, agent string, since time.Time) ([]trigger.Remembered, error) {
	rows, err := s.db.Query(`SELECT task, day, ended_at, quiet, body FROM memory WHERE space = ? AND agent = ? AND ended_at > ?
		ORDER BY ended_at DESC, seq DESC LIMIT ?`, space, agent, ms(since), trigger.MemoryRuns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []trigger.Remembered
	for rows.Next() {
		m := trigger.Remembered{Space: space, Agent: agent}
		var ended int64
		var body []byte
		if err := rows.Scan(&m.Task, &m.Day, &ended, &m.Quiet, &body); err != nil {
			return nil, err
		}
		var b memoryBody
		if err := json.Unmarshal(body, &b); err != nil {
			return nil, err
		}
		m.EndedAt, m.Text, m.Sources = time.UnixMilli(ended).UTC(), b.Text, b.Sources
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Side) DeleteMemory(space, agent string) (int, error) {
	res, err := s.db.Exec(`DELETE FROM memory WHERE space = ? AND agent = ?`, space, agent)
	if err != nil {
		return 0, err
	}
	k, _ := res.RowsAffected()
	return int(k), nil
}

func (s *Side) PruneMemoryExcept(keep func(space, agent string) bool) (int, error) {
	rows, err := s.db.Query(`SELECT DISTINCT space, agent FROM memory`)
	if err != nil {
		return 0, err
	}
	var gone [][2]string
	for rows.Next() {
		var space, agent string
		if err := rows.Scan(&space, &agent); err != nil {
			rows.Close()
			return 0, err
		}
		if !keep(space, agent) {
			gone = append(gone, [2]string{space, agent})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, g := range gone {
		k, err := s.DeleteMemory(g[0], g[1])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s *Side) PruneMemory(t time.Time) error {
	_, err := s.db.Exec(`DELETE FROM memory WHERE ended_at < ?`, ms(t))
	return err
}

func (s *Side) LastFired(trigger string) (int64, bool, error) {
	var slot int64
	err := s.db.QueryRow(`SELECT slot FROM fired WHERE trigger = ?`, trigger).Scan(&slot)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return slot, err == nil, err
}

func (s *Side) SetFired(trigger string, slot int64) error {
	_, err := s.db.Exec(`INSERT INTO fired (trigger, slot) VALUES (?, ?)
		ON CONFLICT (trigger) DO UPDATE SET slot = excluded.slot WHERE excluded.slot > fired.slot`, trigger, slot)
	return err
}

func (s *Side) See(trigger, delivery string, until time.Time) (bool, error) {
	res, err := s.db.Exec(`INSERT INTO seen (trigger, delivery, until) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, trigger, delivery,
		ms(until))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Side) Seen(trigger, delivery string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM seen WHERE trigger = ? AND delivery = ?`, trigger, delivery).Scan(&n)
	return n > 0, err
}

func (s *Side) PruneSeen(t time.Time) error {
	_, err := s.db.Exec(`DELETE FROM seen WHERE until < ?`, ms(t))
	return err
}

func (s *Side) HighWater() (time.Time, error) {
	var v int64
	err := s.db.QueryRow(`SELECT high_water FROM clock WHERE one = 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(v).UTC(), nil
}

func (s *Side) SetHighWater(t time.Time) error {
	_, err := s.db.Exec(`INSERT INTO clock (one, high_water) VALUES (1, ?)
		ON CONFLICT (one) DO UPDATE SET high_water = excluded.high_water WHERE excluded.high_water > clock.high_water`, ms(t))
	return err
}
