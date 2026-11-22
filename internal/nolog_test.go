package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No key material reaches logs, stdout or crash output (privacy review 2026-11-20): a static check over all of
// this module and the key holders' module (not only the CVM's binaries). It fails on any call that prints or logs
// (fmt.Print*, fmt.Fprint*, log.*, slog.*, a Logf/Printf/Println/Errorf-style method or a logf/logger func field,
// panic) one of whose arguments names key material: an identifier or field such as master, root, seed, share,
// secret, passphrase, password, a private key, a lease secret, a nonce key or an API key. Wrapping it in a call
// (len(x), hex.EncodeToString(x)) doesn't hide it. A name that is really not secret goes in nologAllowed with why.

// keyMaterialName is a name that holds key material.
var keyMaterialName = regexp.MustCompile(`(?i)^(master|masterkey|m_?e|root|roots?key|epochroot|seed|seeds|share|shares|plaintextshare|` +
	`secret|secrets|secretkey|leasesecret|runsecret|noncekey|passphrase|pass|password|apppassword|priv|privkey|privatekey|` +
	`sk|signingkey|apikey|apikeys|exakey|tavilykey|tinfoilkey|relaykey|seedbytes|y)$`)

// printFuncs are the package-level print, log and crash functions checked (package path -> names; "*" all).
var printFuncs = map[string][]string{
	"fmt":      {"Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln"},
	"log":      {"*"},
	"log/slog": {"*"},
}

// printMethods are methods and func fields that print or log, whatever their receiver.
var printMethods = map[string]bool{"Logf": true, "Printf": true, "Println": true, "Print": true, "Infof": true, "Warnf": true,
	"Debugf": true, "Info": true, "Warn": true, "Debug": true, "logf": true, "Fatalf": true, "Panicf": true}

// nologAllowed: "<file relative to this module, or key-holders/...>:<line text fragment>" -> why it isn't key material.
var nologAllowed = map[string]string{
	"app/main.go:agent VM listening on":                "relayKey != nil: whether a relay key is set, a bool",
	"cmd/e2e/main.go:relay key    %s":                  "o.RelayKey is the dev relay key's public half (overlay.go)",
	"cmd/gatewayd/main.go:log.Fatal((&gateway.Server{": "logs ListenAndServe's error; Secrets is a field of the server it starts",
	"cmd/internal/actcheck/actcheck.go:lease %s for":   "activity.Lease.Secret is the secret's name, never its value",
	"cmd/kmsctl/main.go:shares in %s":                  "len(rep.Shares): how many sealed shares were written",
	"cmd/kmsctl/main.go:share %d sent":                 "r.Shares: how many shares the replica has, a count",
	"cmd/kmsctl/split.go:fmt.Println(priv)":            "holder-keygen prints the holder key only into a pipe (it refuses a terminal) for the secret store",
	"cmd/kmsctl/split.go:app %s: firm %s, floor %s":    "describeApps prints an app grant: AppPolicy.Secrets are the bundle's names, never values",
}

func TestNoKeyMaterialInLogs(t *testing.T) {
	var files []string
	for _, root := range []string{"..", "../../key-holders"} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == "node_modules" || d.Name() == "third_party") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}
	if len(files) < 100 {
		t.Fatalf("only %d files found", len(files))
	}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]string{}
		for _, im := range file.Imports {
			path := strings.Trim(im.Path.Value, `"`)
			name := filepath.Base(path)
			if im.Name != nil {
				name = im.Name.Name
			}
			imports[name] = path
		}
		src, _ := os.ReadFile(f)
		lines := strings.Split(string(src), "\n")
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !printing(call, imports) {
				return true
			}
			for _, a := range call.Args {
				if name := secretIn(a); name != "" {
					pos := fset.Position(call.Pos())
					rel := strings.TrimPrefix(strings.TrimPrefix(pos.Filename, "../../"), "../")
					line := strings.TrimSpace(lines[pos.Line-1])
					if allowed(rel, line) {
						continue
					}
					t.Errorf("%s:%d: %s prints or logs %q (key material): %s", rel, pos.Line, callName(call), name, line)
				}
			}
			return true
		})
	}
}

func printing(c *ast.CallExpr, imports map[string]string) bool {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "panic" || fn.Name == "logf" || fn.Name == "println" || fn.Name == "print"
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			if names, ok := printFuncs[imports[id.Name]]; ok {
				for _, n := range names {
					if n == "*" || n == fn.Sel.Name {
						return true
					}
				}
				return false
			}
		}
		return printMethods[fn.Sel.Name]
	}
	return false
}

// secretIn returns the first identifier or field name in e that names key material.
func secretIn(e ast.Expr) string {
	found := ""
	ast.Inspect(e, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if keyMaterialName.MatchString(x.Name) {
				found = x.Name
			}
		case *ast.SelectorExpr:
			if keyMaterialName.MatchString(x.Sel.Name) {
				found = x.Sel.Name
			}
			return true
		case *ast.BasicLit:
			return false
		}
		return true
	})
	return found
}

func callName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return id.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return "call"
}

func allowed(rel, line string) bool {
	for k := range nologAllowed {
		file, frag, _ := strings.Cut(k, ":")
		if file == rel && strings.Contains(line, frag) {
			return true
		}
	}
	return false
}
