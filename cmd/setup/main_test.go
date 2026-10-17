package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSpec(t *testing.T) {
	s, err := parseSpec("/run/tacy/agent=10003:10001:0770")
	if err != nil || s.path != "/run/tacy/agent" || s.uid != 10003 || s.gid != 10001 || s.mode != 0o770 {
		t.Fatal(s, err)
	}
	for _, bad := range []string{"run/x=1:1:0700", "/x=1:1", "/x=a:1:0700", "/x=1:1:0800", "/x=1:1:01777", "/=0:0:0755",
		"/a/../b=1:1:0700", "/x=-1:1:0700", "/x"} {
		if _, err := parseSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// As the test's own uid (no root needed): the effects that don't depend on being root.
func TestRun(t *testing.T) {
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	sock := filepath.Join(root, "sock")
	os.Mkdir(sock, 0o755)
	state := filepath.Join(root, "state")
	os.Mkdir(state, 0o755)
	db := filepath.Join(state, "queue.db")
	os.WriteFile(db, []byte("x"), 0o600)
	outside := filepath.Join(root, "outside")
	os.WriteFile(outside, []byte("x"), 0o644)
	tr := filepath.Join(state, "agentd")
	err := run(specs{{sock, uid, gid, 0o750}}, specs{{tr, uid, gid, 0o700}}, paths{db, filepath.Join(state, "missing")})
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v", fi.Mode())
	}
	if fi, err := os.Stat(tr); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("tree %v %v", fi, err)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Error("queue.db not removed")
	}
	// Symlinks: a -dir that is one is refused, a -remove of one is refused (the target stays), a -tree's own path
	// that is one is refused.
	link := filepath.Join(root, "link")
	os.Symlink(outside, link)
	if err := run(nil, nil, paths{link}); err == nil {
		t.Error("removed a symlink")
	}
	dlink := filepath.Join(root, "dlink")
	os.Symlink(sock, dlink)
	if err := run(specs{{dlink, uid, gid, 0o777}}, nil, nil); err == nil {
		t.Error("followed a symlinked -dir")
	}
	if err := run(nil, specs{{dlink, uid, gid, 0o777}}, nil); err == nil {
		t.Error("followed a symlinked -tree")
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o750 {
		t.Errorf("symlink target's mode changed to %v", fi.Mode())
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("symlink target removed")
	}
	// A symlink inside a tree is lchown'd, never followed (the walk doesn't descend into it).
	os.Symlink(root, filepath.Join(tr, "escape"))
	if err := run(nil, specs{{tr, uid, gid, 0o700}}, nil); err != nil {
		t.Fatal(err)
	}
}
