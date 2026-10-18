package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The gVisor release the agent VM runs: Google's release build for x86_64, pinned by the tarball's SHA-256 and each
// binary's (docs/22: Google's release for now, built by us once releases are signed OCI images). The
// release build (cmd/compose) downloads and checks it and puts the binaries in runnerd's image, which the compose
// pins by digest; runnerd checks them again before it runs one. An upgrade is new hashes by review, the real-gVisor
// CI job, a throwaway CVM, then a release.
const (
	GVisorRelease   = "20260928.0"
	GVisorURL       = "https://storage.googleapis.com/gvisor/releases/release/" + GVisorRelease + "/x86_64/gvisor.tar.bz2"
	GVisorTarSHA256 = "f3ed9131bc252259df150e270154180188f9df56b73a2312940325e1f522a2d6"
)

// GVisorFiles are the binaries taken from the tarball (runsc and the sidecars it runs from gvisor-bin/), by path in
// the tarball, with their SHA-256.
var GVisorFiles = [][2]string{
	{"runsc", "88a87d5d6d06160d4c144f51f95ec6dd6fe0fc6b02697eb877876683c5b57a91"},
	{"gvisor-bin/gvisor_sentry", "e10e6e8072a0822f5e80dc203d156f0602b15fab90b85fac1d7bffd79477b267"},
	{"gvisor-bin/gvisor-sentry-prewarmer", "3315d7ad7c2d3751d349e4976fa02da1da6fd7e41746c35622304e5fabe4fce0"},
	{"gvisor-bin/runsc-fd-parking", "03af90d07ea466c10ecc3e3ba839b2a59540959dd3286aea3886917cba850c11"},
}

// CheckPins checks that a gVisor release and runsc hash (what the compose names, so the verifier shows them) are the
// pinned ones.
func CheckPins(release, runscSHA256 string) error {
	if release != GVisorRelease || GVisorFiles[0][0] != "runsc" || runscSHA256 != GVisorFiles[0][1] {
		return fmt.Errorf("gVisor %s with runsc %s isn't the pinned %s with runsc %s", release, runscSHA256, GVisorRelease, GVisorFiles[0][1])
	}
	return nil
}

// CheckGVisor checks that dir holds exactly the pinned binaries.
func CheckGVisor(dir string) error {
	for _, f := range GVisorFiles {
		if err := CheckSHA256(filepath.Join(dir, f[0]), f[1]); err != nil {
			return err
		}
	}
	return nil
}

// CheckSHA256 checks a file's SHA-256.
func CheckSHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s isn't the pinned %s", path, got, want)
	}
	return nil
}
