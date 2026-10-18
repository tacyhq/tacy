package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// DelegateCgroups prepares the cgroup v2 subtree the sandboxes' cgroups go under, from inside the runner's own
// container (cgroup namespace: its root is the container's cgroup). Docker mounts it read-only; with CAP_SYS_ADMIN
// the runner remounts it read-write. cgroup v2 allows controllers only in cgroups without processes, so the
// runner's processes move to a leaf ("runner") first, then memory, cpu and pids are enabled for parent's children.
func DelegateCgroups(parent string) error {
	parent = strings.Trim(parent, "/")
	if parent == "" || strings.Contains(parent, "..") || parent == "runner" {
		return fmt.Errorf("sandbox: bad cgroup parent %q", parent)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("sandbox: no cgroup v2: %w", err)
	}
	if err := syscall.Access(cgroupRoot, 2 /* W_OK */); err != nil {
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_RELATIME)
		if err := syscall.Mount("", cgroupRoot, "", flags, ""); err != nil {
			return fmt.Errorf("sandbox: remount %s read-write: %w", cgroupRoot, err)
		}
	}
	leaf := filepath.Join(cgroupRoot, "runner")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return err
	}
	procs, err := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.procs"))
	if err != nil {
		return err
	}
	for _, pid := range strings.Fields(string(procs)) {
		// A process may have exited meanwhile; the ones left are checked below.
		os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(pid), 0)
	}
	if left, _ := os.ReadFile(filepath.Join(cgroupRoot, "cgroup.procs")); len(strings.TrimSpace(string(left))) > 0 {
		return errors.New("sandbox: processes left in the root cgroup")
	}
	ctl := "+cpu +memory +pids"
	if err := os.WriteFile(filepath.Join(cgroupRoot, "cgroup.subtree_control"), []byte(ctl), 0); err != nil {
		return fmt.Errorf("sandbox: enable controllers: %w", err)
	}
	dir := filepath.Join(cgroupRoot, parent)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(ctl), 0); err != nil {
		return fmt.Errorf("sandbox: enable controllers under %s: %w", parent, err)
	}
	return nil
}
