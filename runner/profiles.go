package runner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tacyhq/tacy/sandbox"
)

// Config is how runnerd runs runsc.
type Config struct {
	Runsc    string // runsc (its gvisor-bin/ next to it)
	Dir      string // runnerd's own directory (a tmpfs): runsc's state, bundles, the brain's root
	Platform string // "systrap" on the CVM
	Rootless bool   // runnerd isn't root (the CVM): --rootless, no cgroups of its own
	// CgroupParent (root only, not rootless): per-sandbox memory, CPU and pids cgroups under it.
	CgroupParent string
}

// BrainLimits bound the brain's sandbox. Rootless (the CVM), memory and processes are bounded by runnerd's
// container (compose: mem_limit, pids_limit), which holds only the brain today; MemoryBytes applies with cgroups.
var BrainLimits = sandbox.Limits{MemoryBytes: 512 << 20, Pids: 256, NoFile: 256}

// BrainRunsc prepares the brain's profile: a root holding only the brain binary (copied from bin into dir and
// checked against sum, its pin; sum "" skips the check, tests only), the brain as the sandbox's first process with
// its harness socket as fd 3, no /work or /tmp, no network, no host sockets, the Sentry without direct host file
// access.
func BrainRunsc(cfg Config, bin, sum string) (*sandbox.Runsc, error) {
	root := filepath.Join(cfg.Dir, "brain-root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, err
	}
	dst := filepath.Join(root, "brain")
	if err := copyFile(bin, dst); err != nil {
		return nil, err
	}
	if sum != "" {
		if err := sandbox.CheckSHA256(dst, sum); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(root, 0o555); err != nil {
		return nil, err
	}
	r, err := runsc(cfg, "brain")
	if err != nil {
		return nil, err
	}
	r.RootFS = root
	r.Init = []string{"/brain", "--fd", "3"}
	r.Env = []string{"GOMEMLIMIT=384MiB"}
	r.Limits = BrainLimits
	r.NoWork, r.NoDirectFS, r.Hostname = true, true, "brain"
	return r, nil
}

// HandsRunsc is the hands' profile (not in the release yet: when an agent first needs exec): rootfs is
// a pinned image's files (busybox and Python), the default limits.
func HandsRunsc(cfg Config, rootfs string) (*sandbox.Runsc, error) {
	r, err := runsc(cfg, "hands")
	if err != nil {
		return nil, err
	}
	r.RootFS, r.Limits = rootfs, sandbox.DefaultLimits
	return r, nil
}

func runsc(cfg Config, name string) (*sandbox.Runsc, error) {
	state, bundles := filepath.Join(cfg.Dir, "state"), filepath.Join(cfg.Dir, "bundles-"+name)
	for _, d := range []string{state, bundles} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	r := &sandbox.Runsc{Path: cfg.Runsc, StateDir: state, BundleDir: bundles, Platform: cfg.Platform, Rootless: cfg.Rootless}
	if !cfg.Rootless && cfg.CgroupParent != "" {
		r.CgroupParent = "/" + strings.Trim(cfg.CgroupParent, "/")
	}
	return r, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o555)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}
