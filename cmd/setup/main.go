// setup is the agent VM's one-shot start step: it runs as root before the four processes, with no network, and
// gives each its directories (owner, group, mode) on the volumes they share. It replaces the build container's
// chown, chmod and rm lines from before the OCI images (the images have no shell). Every path and owner comes from
// the compose's arguments, so a reviewer reads them in compose.yaml, not in the image.
//
//	setup -dir /run/tacy/agent=10003:10001:0770     the directory (a volume) gets this owner, group and mode
//	      -tree /state/agentd=10003:10003:0700      created if missing; everything in it gets the owner and group
//	      -remove /state/queue.db                   removed if it exists (a regular file only)
//
// Symlinks are never followed: a -dir or -tree path must be a real directory, a -tree's entries are changed with
// lchown, and -remove refuses anything but a regular file. So a process that owns a tree can't make setup touch a
// file outside it. Each action is one log line; any failure exits 1, and the processes wait for a clean exit.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tacyhq/tacy/internal/procinfo"
)

// spec is path=uid:gid:mode (mode in octal).
type spec struct {
	path     string
	uid, gid int
	mode     fs.FileMode
}

func parseSpec(s string) (spec, error) {
	p, owner, ok := strings.Cut(s, "=")
	parts := strings.Split(owner, ":")
	if !ok || len(parts) != 3 || !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return spec{}, fmt.Errorf("%q isn't /abs/path=uid:gid:mode", s)
	}
	uid, err1 := strconv.Atoi(parts[0])
	gid, err2 := strconv.Atoi(parts[1])
	mode, err3 := strconv.ParseUint(parts[2], 8, 32)
	if err1 != nil || err2 != nil || err3 != nil || uid < 0 || gid < 0 || mode&^0o777 != 0 {
		return spec{}, fmt.Errorf("%q: bad uid, gid or mode", s)
	}
	return spec{p, uid, gid, fs.FileMode(mode)}, nil
}

type specs []spec

func (s *specs) String() string { return fmt.Sprint(*s) }
func (s *specs) Set(v string) error {
	x, err := parseSpec(v)
	if err == nil {
		*s = append(*s, x)
	}
	return err
}

type paths []string

func (p *paths) String() string { return strings.Join(*p, ",") }
func (p *paths) Set(v string) error {
	if !filepath.IsAbs(v) || filepath.Clean(v) != v || v == "/" {
		return fmt.Errorf("%q isn't a clean absolute path", v)
	}
	*p = append(*p, v)
	return nil
}

// realDir: path is a directory, not a symlink to one.
func realDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s isn't a directory (mode %v)", path, fi.Mode())
	}
	return nil
}

// dir sets a directory's owner, group and mode.
func dir(s spec) error {
	if err := realDir(s.path); err != nil {
		return err
	}
	if err := os.Lchown(s.path, s.uid, s.gid); err != nil {
		return err
	}
	return os.Chmod(s.path, s.mode) // a real directory (checked above), so no symlink to follow
}

// tree creates the directory if it's missing, gives it and everything in it the owner and group (lchown, no
// symlink followed), and sets the directory's own mode.
func tree(s spec) error {
	if err := os.Mkdir(s.path, s.mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := realDir(s.path); err != nil {
		return err
	}
	n := 0
	err := filepath.WalkDir(s.path, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		return os.Lchown(p, s.uid, s.gid)
	})
	if err != nil {
		return err
	}
	log.Printf("setup: %s: %d entries owned by %d:%d", s.path, n, s.uid, s.gid)
	return os.Chmod(s.path, s.mode)
}

// remove deletes a regular file if it exists.
func remove(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file (mode %v): not removed", path, fi.Mode())
	}
	log.Printf("setup: removing %s", path)
	return os.Remove(path)
}

func run(dirs, trees specs, removes paths) error {
	for _, p := range removes {
		if err := remove(p); err != nil {
			return err
		}
	}
	for _, s := range dirs {
		if err := dir(s); err != nil {
			return err
		}
		log.Printf("setup: %s %d:%d %04o", s.path, s.uid, s.gid, s.mode)
	}
	for _, s := range trees {
		if err := tree(s); err != nil {
			return err
		}
		log.Printf("setup: %s %d:%d %04o", s.path, s.uid, s.gid, s.mode)
	}
	return nil
}

func main() {
	var dirs, trees specs
	var removes paths
	flag.Var(&dirs, "dir", "path=uid:gid:mode: an existing directory's owner, group and mode (repeatable)")
	flag.Var(&trees, "tree", "path=uid:gid:mode: create if missing, own it and all it holds, set its mode (repeatable)")
	flag.Var(&removes, "remove", "a regular file to remove if it exists (repeatable)")
	flag.Parse()
	log.Printf("setup: %s", procinfo.Line())
	if flag.NArg() > 0 {
		log.Fatalf("setup: unexpected arguments %q", flag.Args())
	}
	if err := run(dirs, trees, removes); err != nil {
		log.Fatalf("setup: %v", err)
	}
	log.Print("setup: done")
}
