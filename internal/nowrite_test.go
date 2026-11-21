// Package internal_test holds the structural checks of the keys plan (§9.2): what runs in the CVM keeps
// nothing a provider's key protects ("Keys: never a provider's").
package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/tacyhq/tacy"

// vmBinaries are the packages built into the CVM's images (cmd/compose bins).
var vmBinaries = []string{"./app", "./cmd/brain", "./cmd/gatewayd", "./cmd/runnerd", "./cmd/setup", "./cmd/unlockd", "./cmd/vaultd"}

// writeAllowed are the only functions in the CVM's code that may write a file, each with why. A key is
// "<file relative to the module>:<function>" (a method as Type.Method). Anything else that writes fails the test: lasting
// state goes through sealstate (the keys plan §3.2) or stays in memory.
var writeAllowed = map[string]string{
	// The brain's sandbox: runsc's state and the brain's root on the runner's tmpfs (/run/runner, compose), and the
	// cgroup files of the kernel's cgroupfs. Memory, not a disk.
	"sandbox/runsc.go:Runsc.Start":            "runsc config and start log on the runner's tmpfs",
	"sandbox/runsc.go:Runsc.Launch":           "runsc config on the runner's tmpfs",
	"sandbox/runsc.go:runscSandbox.Exec":      "runsc process spec on the runner's tmpfs",
	"sandbox/cgroup_linux.go:DelegateCgroups": "cgroupfs (kernel interface)",
	"runner/profiles.go:copyFile":             "the brain's binary into its root on the runner's tmpfs",
	"vault/wipe.go:wipeFile":                  "overwrites the pre-v0.20.0 connections file with zeros before removing it",
	// unlockd's keyring across container restarts (the keys plan §11.2): only into the host tmpfs mounted into unlockd alone
	// (Cache.check refuses a directory statfs doesn't call tmpfs: TD memory, gone at the next boot).
	"unlock/cache.go:Cache.Save": "unlockd's keyring into its host tmpfs (TD memory), checked to be tmpfs first",
	// The cloudflared spike (branch vm-fix-b-cloudflared): the tunnel token for the few seconds cloudflared takes to
	// read it, in gatewayd's private tmpfs (/tmp in its container: TD memory), checked to be tmpfs first; then zeroed.
	"cmd/gatewayd/tunnel.go:runTunnel":          "the launcher's confinement probe report (check names and errors, no secret) in the tunnel's tmpfs, 0600",
	"gateway/cftunnel/cftunnel.go:wipe":         "zeroes the tunnel token file before removing it",
	"gateway/cftunnel/confined.go:PublishToken": "the confined variant: the tunnel token for cloudflared's uid in the shared tmpfs volume, checked to be tmpfs first",
	// agentd's task queue across container restarts (V1-DESIGN §6.2): only into the host tmpfs setup makes for agentd
	// alone (verifier.TasksDir); OpenTmpfs refuses a directory statfs doesn't call tmpfs, or one other uids can read,
	// before it writes. TD memory, gone at every real boot (TestNoWriteExceptionTasksTmpfs).
	// The Worker's drain (app/drain.go): its end time, one number, beside the queue in the same host tmpfs, so the
	// hourly container restart doesn't end a drain early. Only with -tasks-dir (the directory OpenTmpfs checked).
	"app/drain.go:drainState.keep": "the drain's end time (a unix second, nothing of anyone's) in the task queue's host tmpfs (TD memory), checked by OpenTmpfs",
	tasksTmpfsKey:                  "agentd's task queue (its boot marker) into its host tmpfs (TD memory), checked to be tmpfs first",
	// Before v0.20.0 these kept state on the CVM's disk. Since the quick path nothing in the mains opens them
	// (TestMainsOpenNoFileStores); they move onto sealstate's snapshots (the keys plan §3.2, Stage C) and leave this list.
	"activity/store.go:OpenStore":  "legacy file store, unused by the mains",
	"safety/state.go:State.write":  "legacy file store (Config.Dir), the mains pass none",
	"safety/budget.go:Ledger.save": "legacy file store (Ledger.Dir), the mains set none",
	tasksQueueKey:                  "the task queue's SQLite file: from the mains only through queue.OpenTmpfs, into the host tmpfs (TestNoWriteExceptionTasksTmpfs); else its tests",
	"queue/side.go:OpenSide":       "legacy file store (its tests and the rollback tests), unused by the mains (OpenSideMemory)",
}

// The task queue's exception (V1-DESIGN §6.2): OpenTmpfs writes its boot marker (writeMarker, also the heartbeat's
// Beat: review 2 M3) and opens the queue (Open) in agentd's host tmpfs.
const (
	tasksTmpfsKey = "queue/tmpfs.go:Tmpfs.writeMarker"
	tasksQueueKey = "queue/queue.go:Open"
)

// getenvAllowed may read the environment with a name that isn't a literal (local development only).
var getenvAllowed = map[string]string{
	"app/platform.go:local.Secret": "-platform local only (the dstack platform's Secret is always empty)",
}

// secretName: what a secret's environment variable looks like.
var secretName = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)S?$`)

// vmFiles are the non-test Go files of this module that the CVM's binaries are built from (linux/amd64).
func vmFiles(t *testing.T) []string {
	t.Helper()
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	args := append([]string{"list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles ","}}{{end}}`}, vmBinaries...)
	cmd := exec.Command(gobin, args...)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	root, _ := filepath.Abs("..")
	var files []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(ln, "|", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[0], module) {
			continue
		}
		for _, f := range strings.Split(parts[2], ",") {
			if f == "" {
				continue
			}
			rel, err := filepath.Rel(root, filepath.Join(parts[1], f))
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, filepath.ToSlash(rel))
		}
	}
	if len(files) < 50 {
		t.Fatalf("only %d files from go list: %s", len(files), out)
	}
	return files
}

// finding is one call the rules flag, keyed like writeAllowed.
type finding struct {
	key, what string
	pos       token.Position
}

func scan(t *testing.T, root string, files []string) (writes, getenvs, getkeys []finding) {
	fset := token.NewFileSet()
	for _, rel := range files {
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]string{} // local name -> path
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			name := p[strings.LastIndex(p, "/")+1:]
			if im.Name != nil {
				name = im.Name.Name
			}
			imports[name] = p
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := rel + ":" + funcName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "/GetKey") {
					getkeys = append(getkeys, finding{key, "a /GetKey call to dstack (keys derived from Phala's KMS)", fset.Position(lit.Pos())})
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				path := imports[pkg.Name]
				what := path + "." + sel.Sel.Name
				pos := fset.Position(call.Pos())
				switch {
				case path == "os" && (sel.Sel.Name == "WriteFile" || sel.Sel.Name == "Create" || sel.Sel.Name == "CreateTemp"),
					path == "io/ioutil" && (sel.Sel.Name == "WriteFile" || sel.Sel.Name == "TempFile"):
					writes = append(writes, finding{key, what, pos})
				case path == "os" && sel.Sel.Name == "OpenFile" && len(call.Args) >= 2 && writeFlags(call.Args[1]):
					writes = append(writes, finding{key, what + " for writing", pos})
				case path == "database/sql" && sel.Sel.Name == "Open" && len(call.Args) == 2 && !memoryDSN(call.Args[1]):
					writes = append(writes, finding{key, "a file-backed sql.Open", pos})
				case path == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv") && len(call.Args) == 1:
					lit, isLit := call.Args[0].(*ast.BasicLit)
					if !isLit {
						getenvs = append(getenvs, finding{key, what + " of a name that isn't a literal", pos})
					} else if name, _ := strconv.Unquote(lit.Value); secretName.MatchString(name) {
						getenvs = append(getenvs, finding{key, what + "(" + name + "): a secret from the environment", pos})
					}
				}
				return true
			})
		}
	}
	return
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// writeFlags: an os.OpenFile flag expression naming a flag that writes or creates.
func writeFlags(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			switch s.Sel.Name {
			case "O_WRONLY", "O_RDWR", "O_CREATE", "O_APPEND", "O_TRUNC":
				found = true
			}
		}
		return true
	})
	return found
}

// memoryDSN: a literal SQLite DSN that is in memory.
func memoryDSN(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok {
		return false
	}
	s, _ := strconv.Unquote(lit.Value)
	return s == ":memory:" || strings.HasPrefix(s, "file::memory:") || strings.Contains(s, "mode=memory") || strings.Contains(s, "vfs=memdb")
}

// TestNoWritesOutsideSealstate (the keys plan §9.2): no code the CVM runs writes a file or opens a file-backed database
// outside the allowed list, asks dstack for a key (/GetKey), or takes a secret from the environment.
func TestNoWritesOutsideSealstate(t *testing.T) {
	files := vmFiles(t)
	writes, getenvs, getkeys := scan(t, "..", files)
	used := map[string]bool{}
	for _, w := range writes {
		if strings.HasPrefix(w.key, "sealstate/") {
			continue // the one package that may write lasting state (sealed)
		}
		if _, ok := writeAllowed[w.key]; ok {
			used[w.key] = true
			continue
		}
		t.Errorf("%s: %s in %s: only sealstate may write lasting state (or add it to writeAllowed with why)", w.pos, w.what, w.key)
	}
	for k := range writeAllowed {
		if !used[k] {
			t.Errorf("writeAllowed has %s, which no longer writes: take it out", k)
		}
	}
	for _, g := range getenvs {
		if _, ok := getenvAllowed[g.key]; ok && !strings.Contains(g.what, "a secret from the environment") {
			continue
		}
		t.Errorf("%s: %s in %s: secrets arrive by the Worker's push (vault/secrets.go), never from the env", g.pos, g.what, g.key)
	}
	for _, g := range getkeys {
		t.Errorf("%s: %s in %s", g.pos, g.what, g.key)
	}
}

// The rules flag what they must (a check that never fires proves nothing).
func TestNoWriteRulesFire(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import ("os"; "database/sql"; ioutil "io/ioutil")
func a() { os.WriteFile("f", nil, 0o600) }
func b() { os.OpenFile("f", os.O_RDWR|os.O_CREATE, 0o600) }
func c() { os.OpenFile("f", os.O_RDONLY, 0) }
func d() { sql.Open("sqlite", "file:/state/x.db") }
func e() { sql.Open("sqlite", ":memory:") }
func f() { os.Getenv("EXA_API_KEY") }
func g() { os.Getenv("TINFOIL_ENCLAVE") }
func h(n string) { os.Getenv(n) }
func i() { call("POST", "/GetKey") }
func j() { ioutil.WriteFile("f", nil, 0) }
func call(string, string) {}
`
	os.MkdirAll(filepath.Join(dir, "x"), 0o700)
	os.WriteFile(filepath.Join(dir, "x", "x.go"), []byte(src), 0o600)
	writes, getenvs, getkeys := scan(t, dir, []string{"x/x.go"})
	keys := func(fs []finding) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.key[strings.LastIndex(f.key, ":")+1:])
		}
		return strings.Join(out, ",")
	}
	if got := keys(writes); got != "a,b,d,j" {
		t.Errorf("writes flagged in %s, want a,b,d,j", got)
	}
	if got := keys(getenvs); got != "f,h" {
		t.Errorf("env reads flagged in %s, want f,h", got)
	}
	if got := keys(getkeys); got != "i" {
		t.Errorf("GetKey flagged in %s, want i", got)
	}
}

// TestMainsOpenNoFileStores: the CVM's mains don't open the legacy file stores still on writeAllowed's list, so
// they stay unused until they move onto sealstate.
func TestMainsOpenNoFileStores(t *testing.T) {
	fset := token.NewFileSet()
	for _, rel := range []string{"app/main.go", "app/state.go", "cmd/vaultd/main.go", "cmd/gatewayd/main.go", "cmd/unlockd/main.go"} {
		f, err := parser.ParseFile(fset, filepath.Join("..", rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch fn := x.Fun.(type) {
				case *ast.SelectorExpr:
					if id, ok := fn.X.(*ast.Ident); ok {
						name = id.Name + "." + fn.Sel.Name
					} else {
						name = "." + fn.Sel.Name
					}
				case *ast.Ident:
					name = fn.Name
				}
				switch {
				case name == "queue.Open" || name == "queue.OpenSide" || name == "activity.OpenStore":
					t.Errorf("%s: %s opens a file store", fset.Position(x.Pos()), name)
				case name == "openNotifier" || strings.HasSuffix(name, ".EnableConns") || strings.HasSuffix(name, ".Config") && len(x.Args) == 2:
					// Only with "" (no file) or a Persister (sealstate).
					arg := x.Args[len(x.Args)-1]
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Value != `""` || ok && lit.Kind != token.STRING {
						t.Errorf("%s: %s with a path (only \"\": memory)", fset.Position(x.Pos()), name)
					}
				}
			case *ast.CompositeLit:
				// safety.Ledger{Dir: …} keeps the budgets in a file.
				if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Ledger" {
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Dir" {
								t.Errorf("%s: safety.Ledger with a Dir", fset.Position(kv.Pos()))
							}
						}
					}
				}
			}
			return true
		})
	}
}

// TestNoWriteExceptionTasksTmpfs (V1-DESIGN §6.2, §6.5): the task queue's write exception is the only one for tasks,
// and it holds only for the host tmpfs. The mains open no queue but through queue.OpenTmpfs, once (agentState's
// useTasksQueue, -tasks-dir); OpenTmpfs checks the directory is memory before it writes anything or opens the queue;
// and no other code the CVM runs calls the queue's openers.
func TestNoWriteExceptionTasksTmpfs(t *testing.T) {
	for _, k := range []string{tasksTmpfsKey, tasksQueueKey} {
		if why := writeAllowed[k]; !strings.Contains(why, "tmpfs") {
			t.Errorf("writeAllowed[%s] = %q: the task queue's exception must say it is the host tmpfs", k, why)
		}
	}
	for k := range writeAllowed {
		if strings.HasPrefix(k, "queue/") && k != tasksTmpfsKey && k != tasksQueueKey && k != "queue/side.go:OpenSide" {
			t.Errorf("writeAllowed has %s: the task queue's only exception is OpenTmpfs (and the Open it calls)", k)
		}
	}
	// Who calls the queue's openers, among the files the CVM runs (the queue package aside).
	fset := token.NewFileSet()
	calls := map[string][]string{} // opener -> where
	for _, rel := range vmFiles(t) {
		if strings.HasPrefix(rel, "queue/") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join("..", rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "queue" && (sel.Sel.Name == "Open" || sel.Sel.Name == "OpenTmpfs") {
						calls[sel.Sel.Name] = append(calls[sel.Sel.Name], rel)
					}
				}
			}
			return true
		})
	}
	if len(calls["Open"]) != 0 {
		t.Errorf("queue.Open called from %v: only through queue.OpenTmpfs", calls["Open"])
	}
	if got := calls["OpenTmpfs"]; len(got) != 1 || got[0] != "app/state.go" {
		t.Errorf("queue.OpenTmpfs called from %v, want once from app/state.go (useTasksQueue)", got)
	}
	// In OpenTmpfs, the memory check comes before the first write and before Open; in Beat before its write.
	f, err := parser.ParseFile(fset, filepath.Join("..", "queue", "tmpfs.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var markers []string // the functions that call writeMarker
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				if c, ok := m.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "writeMarker" {
						markers = append(markers, fn.Name.Name)
					}
				}
				return true
			})
		}
		return true
	})
	if !slices.Equal(markers, []string{"Beat", "OpenTmpfs"}) {
		t.Errorf("writeMarker called from %v, want Beat and OpenTmpfs (each after its memory check)", markers)
	}
	for _, name := range []string{"Beat"} {
		var check, write token.Pos
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "isMem" && !check.IsValid() {
							check = c.Pos()
						}
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "writeMarker" && !write.IsValid() {
							write = c.Pos()
						}
					}
					return true
				})
			}
		}
		if !check.IsValid() || !write.IsValid() || check > write {
			t.Errorf("queue.%s must check the directory is memory before it writes the marker", name)
		}
	}
	var check, write, open token.Pos
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "OpenTmpfs" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := c.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "isMem" && !check.IsValid() {
					check = c.Pos()
				}
				if fun.Name == "Open" && !open.IsValid() {
					open = c.Pos()
				}
			case *ast.SelectorExpr:
				if id, ok := fun.X.(*ast.Ident); ok && id.Name == "os" && (fun.Sel.Name == "WriteFile" || fun.Sel.Name == "Remove") && !write.IsValid() {
					write = c.Pos()
				}
				if fun.Sel.Name == "writeMarker" && !write.IsValid() {
					write = c.Pos()
				}
			}
			return true
		})
	}
	if !check.IsValid() || !write.IsValid() || !open.IsValid() || check > write || check > open {
		t.Errorf("queue.OpenTmpfs must check the directory is memory (isMem) before it removes, writes or opens: check %v, write %v, open %v",
			fset.Position(check), fset.Position(write), fset.Position(open))
	}
}
