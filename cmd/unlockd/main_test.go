package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/verifier"
)

// -key-mode (review, missing test 1): the default is the KMS fallback's strict mode, kms waits for the memory-root
// marker, none doesn't, anything else stops unlockd. The flag's name is the one the verifier's compose rules read.
func TestKeyMode(t *testing.T) {
	fs := flag.NewFlagSet("unlockd", flag.ContinueOnError)
	mode := keyModeFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *mode != "kms" {
		t.Fatalf("default -key-mode %q, want kms (a KMS fallback compose omits the flag)", *mode)
	}
	if req, err := requireMemoryRoot(*mode); err != nil || !req {
		t.Fatalf("the default: memory root %v, %v", req, err)
	}
	if "-"+fs.Lookup("key-mode").Name != verifier.UnlockdKeyModeFlag {
		t.Fatalf("the flag is %q, the verifier reads %q", fs.Lookup("key-mode").Name, verifier.UnlockdKeyModeFlag)
	}
	for _, c := range []struct {
		args []string
		req  bool
		bad  bool
	}{
		{[]string{"-key-mode", "kms"}, true, false},
		{[]string{"-key-mode=none"}, false, false},
		{[]string{"-key-mode", ""}, false, true},
		{[]string{"-key-mode", "KMS"}, false, true},
		{[]string{"-key-mode", "local"}, false, true},
		{[]string{"-key-mode", "none "}, false, true},
	} {
		fs := flag.NewFlagSet("unlockd", flag.ContinueOnError)
		mode := keyModeFlag(fs)
		if err := fs.Parse(c.args); err != nil {
			t.Fatal(err)
		}
		req, err := requireMemoryRoot(*mode)
		if c.bad {
			if err == nil || !strings.Contains(err.Error(), "kms or none") {
				t.Errorf("%v: accepted (memory root %v)", c.args, req)
			}
			continue
		}
		if err != nil || req != c.req {
			t.Errorf("%v: memory root %v, %v; want %v", c.args, req, err, c.req)
		}
	}
}
