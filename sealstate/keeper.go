package sealstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Source is one piece of state kept as a snapshot: Version changes whenever its content does (a counter, or
// SQLite's total_changes()), Snapshot is its whole content.
type Source interface {
	Version() uint64
	Snapshot() ([]byte, error)
}

// Keeper saves each named Source's snapshot, sealed, at most Every after it changed (debounced: a burst of writes is
// one save) and on Flush (SIGTERM). Lasting state lives in memory; what survives a restart is the last save.
type Keeper struct {
	Store *Store
	Every time.Duration // default 1 s
	Logf  func(string, ...any)
	// OnFatal is called once when the Store stops (ErrFailed: another instance has the state, or the lease is
	// gone); the process must stop serving. nil: log.Fatalf.
	OnFatal func(error)

	// saving is held for a whole Flush or SaveNow, so two saves of one name never overlap.
	saving    sync.Mutex
	fatalOnce sync.Once
	mu        sync.Mutex
	srcs      map[string]Source
	saved     map[string]uint64 // the Version saved last
	order     []string
}

// Add keeps src as name, its current Version taken as already saved (it was just loaded, or is empty).
func (k *Keeper) Add(name string, src Source) error {
	if !ValidName(name) {
		return ErrName
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.srcs == nil {
		k.srcs, k.saved = map[string]Source{}, map[string]uint64{}
	}
	if _, ok := k.srcs[name]; ok {
		return fmt.Errorf("sealstate: %s added twice", name)
	}
	k.srcs[name] = src
	k.saved[name] = src.Version()
	k.order = append(k.order, name)
	return nil
}

// Flush saves every source that changed since its last save. It returns the first error (the others are tried).
func (k *Keeper) Flush(ctx context.Context) error {
	k.saving.Lock()
	defer k.saving.Unlock()
	k.mu.Lock()
	names := append([]string(nil), k.order...)
	k.mu.Unlock()
	var errs []error
	for _, name := range names {
		if err := k.save(ctx, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// SaveNow saves name's source now if it changed since its last save, and returns once the save is done (a change
// that must be lasting before what follows it runs: an event's delivery before its task, V1-DESIGN §6.3). It waits
// for a Flush in progress. An ErrFailed here stops the Keeper as Run's would.
func (k *Keeper) SaveNow(ctx context.Context, name string) error {
	k.saving.Lock()
	defer k.saving.Unlock()
	k.mu.Lock()
	_, ok := k.srcs[name]
	k.mu.Unlock()
	if !ok {
		return fmt.Errorf("sealstate: %s isn't kept", name)
	}
	err := k.save(ctx, name)
	if errors.Is(err, ErrFailed) {
		k.fatal(err)
	}
	return err
}

// save saves name's source if it changed (k.saving held).
func (k *Keeper) save(ctx context.Context, name string) error {
	k.mu.Lock()
	src, last := k.srcs[name], k.saved[name]
	k.mu.Unlock()
	v := src.Version()
	if v == last {
		return nil
	}
	b, err := src.Snapshot()
	if err == nil {
		err = k.Store.Save(ctx, name, b)
		clear(b)
	}
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.saved[name] = v
	k.mu.Unlock()
	return nil
}

// Run flushes every Every until ctx ends, then once more.
func (k *Keeper) Run(ctx context.Context) {
	every := k.Every
	if every <= 0 {
		every = time.Second
	}
	logf := k.Logf
	if logf == nil {
		logf = log.Printf
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			if err := k.Flush(fctx); err != nil {
				logf("sealstate: final save: %v", err)
			}
			cancel()
			return
		case <-t.C:
			if err := k.Flush(ctx); err != nil {
				logf("sealstate: save: %v", err) // names and errors only, never content
				if errors.Is(err, ErrFailed) {
					k.fatal(err)
					return
				}
			}
		}
	}
}

func (k *Keeper) fatal(err error) {
	k.fatalOnce.Do(func() {
		if k.OnFatal != nil {
			k.OnFatal(err)
			return
		}
		log.Fatalf("sealstate: %v", err)
	})
}

// ---- SQLite in memory -------------------------------------------------------------------------------------------

// OpenMemoryDB opens an SQLite database in this process's memory, on one connection that never closes (the
// database is gone with it), with secure_delete on (a snapshot carries no deleted rows). snapshot, if not empty, is
// what SnapshotDB returned before: the database starts as it was.
//
// A snapshot is SQLite's own serialization of the database (sqlite3_serialize): nothing touches a file, not even a
// tmpfs (the keys plan §3.2 had VACUUM INTO tmpfs; serializing keeps it in memory).
func OpenMemoryDB(snapshot []byte) (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	if len(snapshot) > 0 {
		err = rawConn(db, func(c any) error {
			d, ok := c.(interface{ Deserialize([]byte) error })
			if !ok {
				return errors.New("sealstate: this SQLite driver can't deserialize")
			}
			return d.Deserialize(append([]byte(nil), snapshot...))
		})
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(`PRAGMA secure_delete = ON`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// SnapshotDB serializes an in-memory database (one from OpenMemoryDB).
func SnapshotDB(db *sql.DB) ([]byte, error) {
	var out []byte
	err := rawConn(db, func(c any) error {
		s, ok := c.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return errors.New("sealstate: this SQLite driver can't serialize")
		}
		b, err := s.Serialize()
		out = b
		return err
	})
	return out, err
}

// DBVersion is a Version for an in-memory database: the rows its one connection changed since it opened.
func DBVersion(db *sql.DB) uint64 {
	var n int64
	if db.QueryRow(`SELECT total_changes()`).Scan(&n) != nil {
		return 0
	}
	return uint64(n)
}

func rawConn(db *sql.DB, f func(any) error) error {
	c, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Raw(f)
}
