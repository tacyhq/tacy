package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFakeExecAndLimits(t *testing.T) {
	f := NewFake()
	sb, err := f.Start(t.Context(), NewID())
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	res, err := sb.Exec(t.Context(), Request{Argv: []string{"echo", "hello", "hands"}})
	if err != nil || res.Exit != 0 || string(res.Stdout) != "hello hands\n" {
		t.Fatalf("echo: %+v %v", res, err)
	}
	bad := []Request{
		{},
		{Argv: make([]string, 65)},
		{Argv: []string{"x\x00y"}},
		{Argv: []string{strings.Repeat("a", 4097)}},
		{Argv: []string{"cat"}, Stdin: make([]byte, 1<<20+1)},
		{Argv: []string{"sleep"}, Timeout: 6 * time.Minute},
		{Argv: []string{"sleep"}, Timeout: -time.Second},
	}
	for i, r := range bad {
		if _, err := sb.Exec(t.Context(), r); !errors.Is(err, ErrBadRequest) {
			t.Errorf("bad request %d: %v", i, err)
		}
	}
	if _, err := f.Start(t.Context(), "Bad ID"); !errors.Is(err, ErrBadRequest) {
		t.Errorf("bad id: %v", err)
	}
}

func TestFakeTimeoutAndOutputCap(t *testing.T) {
	f := NewFake()
	f.Limits.OutputBytes = 10
	f.Handler = func(ctx context.Context, _ string, _ map[string][]byte, req Request, stdout, stderr Writer) (int, error) {
		switch req.Argv[0] {
		case "sleep":
			<-ctx.Done()
			return 0, nil
		case "flood":
			stdout.Write(bytes.Repeat([]byte("x"), 25))
			stderr.Write([]byte("short"))
		}
		return 3, nil
	}
	sb, _ := f.Start(t.Context(), NewID())
	defer sb.Close()
	start := time.Now()
	res, err := sb.Exec(t.Context(), Request{Argv: []string{"sleep"}, Timeout: 50 * time.Millisecond})
	if err != nil || !res.TimedOut || res.Exit != 137 || time.Since(start) > 2*time.Second {
		t.Fatalf("timeout: %+v %v", res, err)
	}
	res, err = sb.Exec(t.Context(), Request{Argv: []string{"flood"}})
	if err != nil || !res.Truncated || len(res.Stdout) != 10 || string(res.Stderr) != "short" || res.Exit != 3 {
		t.Fatalf("cap: %+v %v", res, err)
	}
	// The caller's own cancellation is an error, not a result.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sb.Exec(ctx, Request{Argv: []string{"sleep"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

// fileHandler is a tiny shell over the sandbox's working folder: "put NAME" (stdin), "get NAME".
func fileHandler(_ context.Context, _ string, work map[string][]byte, req Request, stdout, _ Writer) (int, error) {
	switch req.Argv[0] {
	case "put":
		work[req.Argv[1]] = req.Stdin
		return 0, nil
	case "get":
		b, ok := work[req.Argv[1]]
		if !ok {
			return 1, nil
		}
		stdout.Write(b)
		return 0, nil
	}
	return 127, nil
}

func TestFakeWorkingFolderPerSandbox(t *testing.T) {
	f := NewFake()
	f.Handler = fileHandler
	a, _ := f.Start(t.Context(), NewID())
	b, _ := f.Start(t.Context(), NewID())
	if _, err := a.Exec(t.Context(), Request{Argv: []string{"put", "notes"}, Stdin: []byte("client data")}); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Exec(t.Context(), Request{Argv: []string{"get", "notes"}}); string(r.Stdout) != "client data" {
		t.Fatalf("same sandbox: %q", r.Stdout)
	}
	if r, _ := b.Exec(t.Context(), Request{Argv: []string{"get", "notes"}}); r.Exit != 1 {
		t.Fatalf("other sandbox sees the file: %+v", r)
	}
	a.Close()
	if _, err := a.Exec(t.Context(), Request{Argv: []string{"get", "notes"}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("exec after close: %v", err)
	}
	b.Close()
	if f.Live() != 0 {
		t.Fatalf("live %d", f.Live())
	}
}

func TestRunscSpec(t *testing.T) {
	r := &Runsc{Path: "/opt/gvisor/runsc", StateDir: "/run/hands/state", BundleDir: "/run/hands/b",
		RootFS: "/opt/hands/rootfs", Limits: DefaultLimits}
	g := strings.Join(r.global(), " ")
	for _, want := range []string{"--network=none", "--host-uds=none", "--overlay2=none", "--platform=systrap",
		"--oci-seccomp", "--ignore-cgroups"} {
		if !strings.Contains(g, want) {
			t.Errorf("global flags %q lack %s", g, want)
		}
	}
	s := r.Spec("h-1")
	root := s["root"].(map[string]any)
	if root["readonly"] != true || root["path"] != "/opt/hands/rootfs" {
		t.Errorf("root %v", root)
	}
	proc := s["process"].(map[string]any)
	if proc["noNewPrivileges"] != true || proc["user"].(map[string]any)["uid"] != 65534 {
		t.Errorf("process %v", proc)
	}
	for k, v := range proc["capabilities"].(map[string]any) {
		if len(v.([]string)) != 0 {
			t.Errorf("capability set %s not empty", k)
		}
	}
	linux := s["linux"].(map[string]any)
	var ns []string
	for _, n := range linux["namespaces"].([]map[string]any) {
		ns = append(ns, n["type"].(string))
	}
	if !slices.Contains(ns, "network") {
		t.Errorf("no network namespace: %v", ns)
	}
	if _, ok := linux["cgroupsPath"]; ok {
		t.Error("cgroupsPath without CgroupParent")
	}
	if linux["seccomp"] == nil {
		t.Error("no seccomp profile")
	}
	var work string
	for _, m := range s["mounts"].([]map[string]any) {
		if m["destination"] == "/work" {
			work = strings.Join(m["options"].([]string), ",")
		}
		if m["type"] == "bind" {
			t.Errorf("bind mount from the host: %v", m)
		}
	}
	if !strings.Contains(work, "size=67108864") {
		t.Errorf("/work options %q", work)
	}

	r.CgroupParent = "/hands"
	r.NoSeccomp = true
	g = strings.Join(r.global(), " ")
	if strings.Contains(g, "--ignore-cgroups") || strings.Contains(g, "--oci-seccomp") {
		t.Errorf("global %q", g)
	}
	s = r.Spec("h-2")
	linux = s["linux"].(map[string]any)
	if linux["cgroupsPath"] != "/hands/h-2" {
		t.Errorf("cgroupsPath %v", linux["cgroupsPath"])
	}
	res := linux["resources"].(map[string]any)
	if res["memory"].(map[string]any)["limit"] != int64(256<<20) || res["pids"].(map[string]any)["limit"] != 512 ||
		res["cpu"].(map[string]any)["quota"] != int64(50000) {
		t.Errorf("resources %v", res)
	}
}

// CI's real-gVisor job downloads the same release with the same pins as the build container (gvisor.go).
func TestCIUsesThePins(t *testing.T) {
	ci, err := os.ReadFile("../../../.github/workflows/ci.yml")
	if err != nil {
		t.Skip("no CI workflow here")
	}
	for _, want := range []string{GVisorURL, GVisorTarSHA256} {
		if !strings.Contains(string(ci), want) {
			t.Errorf("ci.yml lacks %s", want)
		}
	}
	for _, f := range GVisorFiles {
		if !strings.Contains(string(ci), f[1]+"  "+f[0]) {
			t.Errorf("ci.yml lacks %s's pin", f[0])
		}
	}
}
