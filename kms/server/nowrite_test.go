package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// kmsd writes nothing to disk: no file, directory, rename or delete call and no database anywhere in its code
// (package kms and below, cmd/kmsd). Reading a flag-given file isn't done either: kmsd takes everything from flags
// and requests. A new call here needs a reason that survives review (its disk holds only public images).
func TestKMSDWritesNothing(t *testing.T) {
	forbidden := map[string][]string{
		"os":        {"Create", "CreateTemp", "WriteFile", "OpenFile", "Open", "ReadFile", "Mkdir", "MkdirAll", "MkdirTemp", "Rename", "Remove", "RemoveAll", "Symlink", "Link", "Chmod", "Chown", "Lchown", "Truncate", "Getenv", "LookupEnv", "Environ"},
		"io/ioutil": {"WriteFile", "TempFile", "TempDir", "ReadFile"},
		"syscall":   {"Open", "Creat", "Mkdir", "Rename", "Unlink", "Getenv"},
	}
	refusedImports := []string{"database/sql", "log/syslog", "os/exec", "modernc.org/sqlite", "plugin"}
	var files []string
	for _, root := range []string{"..", "../../cmd/kmsd"} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}
	if len(files) < 8 {
		t.Fatalf("only %d files found", len(files))
	}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{} // local name -> import path
		for _, im := range file.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			for _, r := range refusedImports {
				if path == r {
					t.Errorf("%s imports %s", f, path)
				}
			}
			name := filepath.Base(path)
			if im.Name != nil {
				name = im.Name.Name
			}
			names[name] = path
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, fn := range forbidden[names[id.Name]] {
				if sel.Sel.Name == fn {
					t.Errorf("%s: %s.%s (kmsd writes nothing and reads no file or env)", fset.Position(sel.Pos()), id.Name, fn)
				}
			}
			return true
		})
	}
}
