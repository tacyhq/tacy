package main

import (
	"strings"
	"testing"

	agentvm "github.com/tacyhq/tacy"
	"github.com/tacyhq/tacy/verifier"
)

// The two key modes the generator writes (Fix B, a research note): with
// key_provider none, setup gives unlockd its cache directory (no pre-launch script makes it) and unlockd runs with
// -key-mode none; in the KMS fallback neither, and the memory-root script is the pre-launch script. Each passes the
// verifier's rules of its own mode and fails the other's. Every service sets ulimits core 0 in both.
func TestComposeKeyModes(t *testing.T) {
	rel := releaseOf(t, readCompose(t))
	memRoot := verifier.MemoryRootScript
	none := ""
	for _, inVM := range []bool{true, false} {
		p := pinned()
		p.keysInVM = inVM
		out, err := generateWith(rel, p)
		if err != nil {
			t.Fatal(err)
		}
		cacheOnSetup := strings.Contains(out, `"-dir", "`+verifier.UnlockCacheDir+`=`+unlockdUID+`:`+unlockdUID+`:0700"`)
		keyMode := strings.Contains(out, `"-key-mode", "none"`)
		mounts := strings.Count(out, "      - "+verifier.UnlockCacheDir+":")
		if cacheOnSetup != inVM || keyMode != inVM || mounts != map[bool]int{true: 2, false: 1}[inVM] {
			t.Errorf("keys in VM %v: setup's cache %v, unlockd's -key-mode none %v, %d cache mounts", inVM, cacheOnSetup, keyMode, mounts)
		}
		if n := strings.Count(out, "    ulimits:\n      core: 0\n"); n != 6 {
			t.Errorf("keys in VM %v: %d services with ulimits core 0, want all 6", inVM, n)
		}
		own, other := verifier.KeyProviderNone, verifier.KeyProviderKMS
		ownScript, otherScript := &none, &memRoot
		if !inVM {
			own, other, ownScript, otherScript = other, own, otherScript, ownScript
		}
		if err := verifier.UnlockdRules(out, ownScript, own); err != nil {
			t.Errorf("keys in VM %v: its own rules: %v", inVM, err)
		}
		if err := verifier.UnlockdRules(out, otherScript, other); err == nil {
			t.Errorf("keys in VM %v: passed the other mode's rules", inVM)
		}
		var pre []byte
		if !inVM {
			pre = []byte(memRoot)
		}
		if _, err := verifier.ReleaseAppCompose([]byte(out), pre, !inVM); err != nil {
			t.Errorf("keys in VM %v: release app-compose: %v", inVM, err)
		}
		// The other mode's app-compose of this compose is refused.
		var otherPre []byte
		if inVM {
			otherPre = []byte(memRoot)
		}
		if _, err := verifier.ReleaseAppCompose([]byte(out), otherPre, inVM); err == nil && inVM {
			t.Errorf("keys in VM %v: a KMS-fallback app-compose of a key_provider none compose", inVM)
		}
	}
	if pinned().keysInVM == agentvm.KMSFallback {
		t.Error("pinned() doesn't follow pins.go KMSFallback")
	}
}

// The task queue's host tmpfs (V1-DESIGN §6.2) is key_provider none's only: setup makes it for agentd, agentd mounts
// it and runs with -tasks-dir; the KMS fallback has none (its queue stays in agentd's memory).
func TestComposeTasksTmpfs(t *testing.T) {
	rel := releaseOf(t, readCompose(t))
	for _, inVM := range []bool{true, false} {
		p := pinned()
		p.keysInVM = inVM
		out, err := generateWith(rel, p)
		if err != nil {
			t.Fatal(err)
		}
		made := strings.Contains(out, `"-dir", "`+verifier.TasksDir+`=`+agentdUID+`:`+agentdUID+`:0700"`)
		flag := strings.Contains(out, `"-tasks-dir", "`+verifier.TasksDir+`"`)
		mounts := strings.Count(out, "      - "+verifier.TasksDir+":"+verifier.TasksDir+"\n")
		if made != inVM || flag != inVM || mounts != map[bool]int{true: 2, false: 0}[inVM] {
			t.Errorf("keys in VM %v: setup makes it %v, agentd's -tasks-dir %v, %d mounts", inVM, made, flag, mounts)
		}
		mode := map[bool]string{true: verifier.KeyProviderNone, false: verifier.KeyProviderKMS}[inVM]
		if err := verifier.TasksRules(out, mode); err != nil {
			t.Errorf("keys in VM %v: %v", inVM, err)
		}
	}
}
