package internal_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The split-key unlock (the keys plan §11.2): no binary the CVM runs links the key service (kms/server: kmsd's leases,
// register and gen-confirm), a holder, the break-glass relay, a development split, the passphrase shares or a test
// world. The VM's keys come from unlockd only.
func TestVMBinariesLinkNoKeyServiceOrDevKeys(t *testing.T) {
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(gobin, append([]string{"list", "-deps", "-f", "{{.ImportPath}}"}, vmBinaries...)...)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, bad := range []string{"/kms/server", "/kms/kmsdev", "/kms/split/holder", "/kms/split/glass", "/kms/split/splitdev",
			"/unlock/unlocktest", "/kms/passshare"} {
			if p == module+bad {
				t.Errorf("a VM binary links %s", p)
			}
		}
	}
}
