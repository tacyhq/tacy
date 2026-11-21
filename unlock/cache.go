package unlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The keyring across container restarts (the keys plan §11.2): dstack's guest-agent watchdog restarts the containers
// about hourly without a reboot. unlockd keeps its keyring in a host tmpfs (verifier.UnlockCacheDir, made by the
// memory-root pre-launch script for unlockd's uid, mounted into unlockd only): TD memory, gone at the next boot. A
// restarted unlockd serves it again without asking the holders; a real boot (a new kernel boot id, an empty /run)
// unlocks again. Nothing here is on a disk: Cache refuses a directory that isn't tmpfs.

// cacheFile is the keyring's file in the cache directory.
const cacheFile = "keyring.json"

// Cache is the keyring's home in a host tmpfs.
type Cache struct {
	Dir string
	// IsMemory says whether Dir is memory (nil: statfs says tmpfs; tests replace it).
	IsMemory func(dir string) (bool, error)
	// BootID is the kernel's boot id (nil: /proc/sys/kernel/random/boot_id).
	BootID func() (string, error)
}

func (c *Cache) check() error {
	if c == nil || c.Dir == "" {
		return errors.New("unlock: no cache directory")
	}
	isMem := c.IsMemory
	if isMem == nil {
		isMem = isTmpfs
	}
	ok, err := isMem(c.Dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("unlock: %s isn't memory (tmpfs): the keys never go there", c.Dir)
	}
	return nil
}

// Boot is the kernel's boot id.
func (c *Cache) Boot() (string, error) {
	if c != nil && c.BootID != nil {
		return c.BootID()
	}
	return KernelBootID()
}

// KernelBootID is /proc/sys/kernel/random/boot_id.
func KernelBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Save keeps k in the cache (0600, written whole then renamed).
func (c *Cache) Save(k *Keyring) error {
	if err := c.check(); err != nil {
		return err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	defer clear(b)
	tmp := filepath.Join(c.Dir, "."+cacheFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.Dir, cacheFile))
}

// Load is the cached keyring of this boot, for kmsID (nil, nil when there is none for this boot: unlock again).
func (c *Cache) Load(kmsID string) (*Keyring, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(c.Dir, cacheFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(b)
	var k Keyring
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, nil // a torn or foreign file: unlock again (Save replaces it)
	}
	boot, err := c.Boot()
	if err != nil {
		return nil, err
	}
	if k.Boot == "" || k.Boot != boot || k.KMSID != kmsID || len(k.Keys) == 0 {
		k.Wipe()
		return nil, nil
	}
	return &k, nil
}

// MemoryRootMarker is what the memory-root pre-launch script writes in the cache directory once Docker's and
// containerd's data roots are tmpfs: "boot=<id> docker=<dir> containerd=<dir> fs=tmpfs".
const MemoryRootMarker = "memory-root"

// CheckMemoryRoot says the measured pre-launch script put the image stores in TD memory in this boot (defense in
// depth: the holders already refuse a compose without that script, verifier.MemoryRoot).
func (c *Cache) CheckMemoryRoot() error {
	if err := c.check(); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(c.Dir, MemoryRootMarker))
	if err != nil {
		return fmt.Errorf("unlock: no memory-root marker (the images may be on the provider's disk): %w", err)
	}
	boot, err := c.Boot()
	if err != nil {
		return err
	}
	f := map[string]string{}
	for _, kv := range strings.Fields(string(b)) {
		k, v, _ := strings.Cut(kv, "=")
		f[k] = v
	}
	if f["fs"] != "tmpfs" || f["boot"] != boot || f["docker"] == "" {
		return errors.New("unlock: the memory-root marker isn't this boot's, or not tmpfs")
	}
	return nil
}
