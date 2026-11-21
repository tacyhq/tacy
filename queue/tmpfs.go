package queue

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// Tmpfs is where the task queue lives in a host tmpfs.
type Tmpfs struct {
	Dir string
	// IsMemory says whether Dir is memory (nil: statfs says tmpfs; tests replace it).
	IsMemory func(dir string) (bool, error)
	// BootID is the kernel's boot id (nil: /proc/sys/kernel/random/boot_id).
	BootID func() (string, error)
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
// doesn't match) is deleted first: its tasks are not taken up.
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
		if f["kernel"] == kernel && strings.HasPrefix(f["queue"], "qb_") {
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
		tmp := marker + ".tmp"
		if err := os.WriteFile(tmp, []byte("kernel="+kernel+" queue="+boot+"\n"), 0o600); err != nil {
			return nil, "", fmt.Errorf("queue: %w", err)
		}
		if err := os.Rename(tmp, marker); err != nil {
			return nil, "", fmt.Errorf("queue: %w", err)
		}
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
