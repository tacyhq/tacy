package queue

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The task queue across container restarts (V1-DESIGN §6.2): dstack's guest-agent watchdog restarts the containers
// about hourly without a reboot, and with the queue in agentd's memory every open task died with it. OpenTmpfs keeps
// the queue (this package's SQLite file) in a host tmpfs instead: verifier.TasksDir, made by setup for agentd's uid
// (0700) and mounted into agentd alone (verifier.TasksRules). That is TD memory, gone at every real boot, like
// unlockd's keyring cache (unlock.Cache): nothing reaches a disk, so no provider's key protects it ("Keys:
// never a provider's"; internal/nowrite_test.go names this as the one exception for tasks). OpenTmpfs refuses a
// directory statfs doesn't call tmpfs, or one another uid could read.
//
// The queue's boot: a random id made when this queue was made in this kernel boot, kept beside it. A restarted agentd
// gets the same id back (its tasks are still there); a real boot, or a queue only in memory, gets a new one. The
// starter of a task keeps the id it saw, so a status call for a task this queue doesn't know can say the task was
// lost to a restart (task_unknown_after_restart), not that it never was.

//
// The queue's heartbeat (review 2, M3): the marker also holds when an agentd last had the queue open (alive=, ms
// since the epoch), rewritten every HeartbeatEvery while it runs (Beat). A queue whose last heartbeat is more than
// StaleAfter before this process started was left by an agentd that stopped long ago: a container restart (dstack's
// watchdog) takes seconds, so a gap that long means another release held the VM in between (a rollback to one without
// -tasks-dir, then a roll forward in the same boot), and the person may have asked again meanwhile. Such a queue is
// wiped like one from another kernel boot, with a new queue boot: every task in it answers task_unknown_after_restart
// ("interrupted, run it again?"), none resumes. A marker without a heartbeat (written before it) counts as stale.

// The heartbeat's timing.
const (
	HeartbeatEvery = 30 * time.Second
	StaleAfter     = 5 * time.Minute
)

// Tmpfs is where the task queue lives in a host tmpfs.
type Tmpfs struct {
	Dir string
	// IsMemory says whether Dir is memory (nil: statfs says tmpfs; tests replace it).
	IsMemory func(dir string) (bool, error)
	// BootID is the kernel's boot id (nil: /proc/sys/kernel/random/boot_id).
	BootID func() (string, error)
	// Started is when this process started (zero: now), what the last heartbeat is compared with; Now the clock
	// (nil: time.Now).
	Started time.Time
	Now     func() time.Time
}

func (t Tmpfs) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// writeMarker writes the marker (atomically: a temporary file renamed over it) with this moment as the heartbeat.
func (t Tmpfs) writeMarker(kernel, boot string) error {
	marker := filepath.Join(t.Dir, tmpfsMarker)
	tmp := marker + ".tmp"
	line := "kernel=" + kernel + " queue=" + boot + " alive=" + strconv.FormatInt(t.now().UnixMilli(), 10) + "\n"
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return fmt.Errorf("queue: %w", err)
	}
	if err := os.Rename(tmp, marker); err != nil {
		return fmt.Errorf("queue: %w", err)
	}
	return nil
}

// Beat records that this process still has queue boot open (its heartbeat); call it every HeartbeatEvery. It checks
// the directory is still memory first, as OpenTmpfs does.
func (t Tmpfs) Beat(boot string) error {
	isMem := t.IsMemory
	if isMem == nil {
		isMem = isTmpfs
	}
	if ok, err := isMem(t.Dir); err != nil || !ok {
		return fmt.Errorf("%w (%s)", ErrNotMemory, t.Dir)
	}
	bootID := t.BootID
	if bootID == nil {
		bootID = kernelBootID
	}
	kernel, err := bootID()
	if err != nil {
		return fmt.Errorf("queue: boot id: %w", err)
	}
	return t.writeMarker(kernel, boot)
}

// The files in a Tmpfs directory.
const (
	tmpfsQueue  = "queue.db"
	tmpfsMarker = "boot"
)

// ErrNotMemory is OpenTmpfs's refusal of a directory that isn't a tmpfs.
var ErrNotMemory = errors.New("queue: the task queue's directory isn't memory (tmpfs): tasks never go to a disk")

// NewBoot is a fresh queue boot id (a queue only in memory takes one per process).
func NewBoot() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "qb_" + hex.EncodeToString(b)
}

// OpenTmpfs opens (or makes) the task queue in t.Dir after checking the directory is memory and this uid's alone,
// and returns it with the queue's boot. A queue left by another kernel boot (which a tmpfs can't hold; a marker that
// doesn't match) is deleted first: its tasks are not taken up; so is one whose last heartbeat is stale (StaleAfter).
func OpenTmpfs(t Tmpfs) (*Store, string, error) {
	if t.Dir == "" {
		return nil, "", errors.New("queue: no task queue directory")
	}
	fi, err := os.Lstat(t.Dir)
	if err != nil {
		return nil, "", fmt.Errorf("queue: %w", err)
	}
	if !fi.IsDir() {
		return nil, "", fmt.Errorf("queue: %s isn't a directory", t.Dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, "", fmt.Errorf("queue: %s is open to other users (%v): it must be 0700", t.Dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, "", fmt.Errorf("queue: %s isn't this uid's", t.Dir)
	}
	isMem := t.IsMemory
	if isMem == nil {
		isMem = isTmpfs
	}
	if ok, err := isMem(t.Dir); err != nil {
		return nil, "", fmt.Errorf("queue: %w", err)
	} else if !ok {
		return nil, "", fmt.Errorf("%w (%s)", ErrNotMemory, t.Dir)
	}
	bootID := t.BootID
	if bootID == nil {
		bootID = kernelBootID
	}
	kernel, err := bootID()
	if err != nil {
		return nil, "", fmt.Errorf("queue: boot id: %w", err)
	}
	marker := filepath.Join(t.Dir, tmpfsMarker)
	boot := ""
	if b, err := os.ReadFile(marker); err == nil {
		f := map[string]string{}
		for _, kv := range strings.Fields(string(b)) {
			k, v, _ := strings.Cut(kv, "=")
			f[k] = v
		}
		started := t.Started
		if started.IsZero() {
			started = t.now()
		}
		alive, err := strconv.ParseInt(f["alive"], 10, 64)
		fresh := err == nil && started.Sub(time.UnixMilli(alive)) <= StaleAfter
		if f["kernel"] == kernel && strings.HasPrefix(f["queue"], "qb_") && fresh {
			boot = f["queue"]
		}
	}
	if boot == "" { // a new queue for this boot: nothing an earlier one left is taken up
		for _, name := range []string{tmpfsQueue, tmpfsQueue + "-wal", tmpfsQueue + "-shm"} {
			if err := os.Remove(filepath.Join(t.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, "", fmt.Errorf("queue: %w", err)
			}
		}
		boot = NewBoot()
	}
	if err := t.writeMarker(kernel, boot); err != nil { // this process's first heartbeat
		return nil, "", err
	}
	s, err := Open(filepath.Join(t.Dir, tmpfsQueue))
	if err != nil {
		return nil, "", err
	}
	return s, boot, nil
}

// kernelBootID is /proc/sys/kernel/random/boot_id.
func kernelBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
