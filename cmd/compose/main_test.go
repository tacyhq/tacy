package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// compose.yaml must be what the current source generates, including the reproducible binary hashes.
// Builds the service and the brain for linux/amd64 (a few seconds when cached). Skipped with -short.
func TestComposeCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the service")
	}
	os.Chdir("../..")
	out, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile("compose.yaml")
	if string(cur) != out {
		t.Fatal("compose.yaml is stale: run go run ./cmd/compose")
	}
}

func readCompose(t *testing.T) []byte {
	out, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		out, err = os.ReadFile("compose.yaml") // TestComposeCurrent changed to the module root
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Linux caps one argument at 128 KiB (MAX_ARG_STRLEN), and compose passes each command item as one argument: the
// script and every source chunk must stay under it (the whole source in one script once didn't, and the CVM
// restarted with "argument list too long"). And Phala refuses a compose over 200 KiB with its pre-launch script
// (208 KiB once did).
func TestComposeArgumentsFit(t *testing.T) {
	out := readCompose(t)
	if len(out) > MaxCompose {
		t.Fatalf("compose.yaml is %d bytes (limit %d)", len(out), MaxCompose)
	}
	src := strings.SplitN(string(out), "\nx-agentvm-source:\n", 2)[1]
	src = strings.SplitN(src, "\nservices:\n", 2)[0]
	chunks := strings.Split(src, "\n- &")
	cmd := strings.SplitN(string(out), "    command:\n", 2)[1]
	cmd = strings.SplitN(cmd, "\n  agentd:\n", 2)[0] // the build container's
	items := strings.Split(cmd, "\n      - ")
	if len(chunks) < 2 || len(items) != 2+len(chunks) {
		t.Fatalf("%d chunks, %d command items", len(chunks), len(items))
	}
	for i, it := range append(chunks, items[0]) {
		if len(it) > 120<<10 {
			t.Errorf("item %d is %d bytes", i, len(it))
		}
	}
	// Every chunk is passed by alias, in order, and every alias has its anchor.
	for i := 2; i < len(items); i++ {
		alias := strings.TrimSpace(items[i])
		if alias != "*src"+string(rune('0'+i-2)) || !strings.Contains(src, "&src"+string(rune('0'+i-2))+" |\n") {
			t.Errorf("item %d: %q", i, alias)
		}
	}
	for _, pin := range []string{"AGENTD_SHA256=", "BRAIN_SHA256=", "GATEWAYD_SHA256=", "VAULTD_SHA256="} {
		if strings.Count(string(out), pin) != 2 {
			t.Errorf("%s must appear twice: in the build and in the container that runs it", pin)
		}
	}
}

// The process layout of docs/21: only gatewayd (service agentvm) and the one-shot build have a network; agentd, the
// brain and vaultd have none. The keys go to vaultd only, the run token to agentd only.
func TestComposeLayout(t *testing.T) {
	out := string(readCompose(t))
	services := strings.SplitN(out, "\nservices:\n", 2)[1]
	services = strings.SplitN(services, "\nvolumes:\n", 2)[0]
	byName := map[string]string{}
	name := ""
	for _, ln := range strings.Split(services, "\n") {
		if strings.HasPrefix(ln, "  ") && !strings.HasPrefix(ln, "   ") && strings.HasSuffix(ln, ":") {
			name = strings.TrimSuffix(strings.TrimSpace(ln), ":")
			continue
		}
		byName[name] += ln + "\n"
	}
	for _, name := range []string{"build", "agentd", "brain", "agentvm", "vaultd"} {
		if byName[name] == "" {
			t.Fatalf("no service %s (have %d)", name, len(byName))
		}
	}
	if len(byName) != 5 {
		t.Fatalf("%d services", len(byName))
	}
	for name, body := range byName {
		none := strings.Contains(body, "network_mode: none")
		if want := name == "agentd" || name == "brain" || name == "vaultd"; none != want {
			t.Errorf("%s: network_mode none is %v", name, none)
		}
		if strings.Contains(body, "ports:") != (name == "agentvm") {
			t.Errorf("%s: published ports", name)
		}
		if name != "build" && (!strings.Contains(body, "cap_drop: [ALL]") || !strings.Contains(body, "read_only: true") ||
			!strings.Contains(body, "no-new-privileges:true")) {
			t.Errorf("%s isn't hardened", name)
		}
		for _, env := range []string{"TINFOIL_API_KEY", "TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY"} {
			if strings.Contains(body, "${"+env+"}") != (name == "vaultd") {
				t.Errorf("%s: %s", name, env)
			}
		}
		if strings.Contains(body, "${AGENT_VM_TOKEN}") != (name == "agentd") {
			t.Errorf("%s: AGENT_VM_TOKEN", name)
		}
	}
	if strings.Count(out, "/var/run/dstack.sock:") != 1 || !strings.Contains(byName["agentd"], "/var/run/dstack.sock:") {
		t.Error("only agentd mounts dstack's socket")
	}
	// No long-running process is root (agentd was until VM release 2): each has its own uid, and agentd's is the one
	// gatewayd accepts on its socket.
	for name, body := range byName {
		if name != "build" && (!strings.Contains(body, "    user: \"") || strings.Contains(body, "    user: \"0")) {
			t.Errorf("%s runs as root", name)
		}
	}
	if !strings.Contains(byName["agentd"], `user: "`+agentdUID+":"+agentdUID+`"`) ||
		!strings.Contains(byName["agentvm"], "-agent-uid "+agentdUID+" ") {
		t.Error("agentd's uid and gatewayd's -agent-uid differ")
	}
	// agentd's queue directory and the brain's socket directory are its own, set by the build.
	if !strings.Contains(byName["agentd"], "-storage /state/agentd ") ||
		!strings.Contains(byName["build"], "chown -R "+agentdUID+":"+agentdUID+" /state/agentd") ||
		!strings.Contains(byName["build"], "chown "+agentdUID+":"+brainUID+" /run/tacy/brain") {
		t.Error("agentd's directories")
	}
}

// The embedded source unpacks to exactly the files the compose was generated from, byte for byte.
func TestComposeSourceRoundTrip(t *testing.T) {
	out := readCompose(t)
	root := "../.."
	if _, err := os.Stat("compose.yaml"); err == nil {
		root = "."
	}
	dir := t.TempDir()
	if err := extract(out, dir); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		got, _ := os.ReadFile(p)
		want, err := os.ReadFile(filepath.Join(root, rel))
		if rel == "go.sum" { // the lines the build needs: each one is the repository's
			for _, ln := range strings.Split(strings.TrimSpace(string(got)), "\n") {
				if !strings.Contains("\n"+string(want), "\n"+ln+"\n") {
					t.Errorf("go.sum line %q isn't the repository's", ln)
				}
			}
			n++
			return nil
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from the repository's (or isn't there): %v", rel, err)
		}
		n++
		return nil
	})
	if err != nil || n < 10 {
		t.Fatalf("%d files, %v", n, err)
	}
	for _, must := range []string{"go.mod", "go.sum", "app/main.go", "cmd/brain/main.go", "brain/brain.go", "guard/guard.go",
		"harness/runtime.go", "queue/queue.go", "app/peer_linux.go", "cmd/gatewayd/main.go", "cmd/vaultd/main.go",
		"gateway/server.go", "vault/vault.go", "leakscan/scan.go", "leakscan/patterns.go"} {
		if _, err := os.Stat(filepath.Join(dir, must)); err != nil {
			t.Errorf("%s isn't embedded", must)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "app/peer_other.go")); err == nil {
		t.Error("a file the linux build doesn't use is embedded")
	}
}

// The tar.gz is deterministic: the same files give the same bytes.
func TestArchiveDeterministic(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)
	os.MkdirAll("a/b", 0o755)
	os.WriteFile("a/b/x.go", []byte("package b\n"), 0o600)
	os.WriteFile("go.mod", []byte("module m\n"), 0o640)
	one, err := archive([]string{"go.mod", "a/b/x.go"})
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	os.Chtimes("go.mod", later, later) // times and file modes don't reach the archive
	two, _ := archive([]string{"go.mod", "a/b/x.go"})
	if !bytes.Equal(one, two) {
		t.Fatal("archive isn't deterministic")
	}
}

// Phala refuses a compose with a refused word in it (terms of use), even inside base64: no line may contain one.
func TestComposeNoRefusedWords(t *testing.T) {
	if w := refusedWord(string(readCompose(t))); w != "" {
		t.Fatalf("compose.yaml contains %q", w)
	}
}

// wrap breaks lines inside refused words and keeps every character, in order.
func TestWrap(t *testing.T) {
	in := strings.Repeat("A", lineLen-2) + "fRpB" + strings.Repeat("C", 3*lineLen) + "frp" + "xFRP"
	lines := wrap(in)
	if strings.Join(lines, "") != in {
		t.Fatal("wrap lost or reordered characters")
	}
	for _, ln := range lines {
		if len(ln) == 0 || len(ln) > lineLen || refusedWord(ln) != "" {
			t.Fatalf("bad line %q", ln)
		}
	}
	if got := wrap(strings.Repeat("B", 2*lineLen)); len(got) != 2 {
		t.Fatalf("%d lines for two full ones", len(got))
	}
}
