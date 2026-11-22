package cftunnel

import (
	"strings"
	"testing"
)

// The probe lets cloudflared's uid reach Docker's embedded resolver only (dockerdns.go): 127.0.0.11, root's, on
// /proc/net/tcp (the line below is a container's on a user-defined network, 2026-11-21); any other address, owner or
// state stays a failed check.
func TestDockerResolverOnly(t *testing.T) {
	line := func(local, st, uid string) []string {
		return strings.Fields("0: " + local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000 " + uid + " 0 1099361 1 0000000044932b54 100 0 0 10 0")
	}
	if !isDockerResolver(line("0B00007F:8753", "0A", "0")) {
		t.Fatal("Docker's resolver (127.0.0.11, root's, listening) not recognised")
	}
	for name, f := range map[string][]string{
		"127.0.0.1":           line("0100007F:8753", "0A", "0"),
		"127.0.0.11 of 10001": line("0B00007F:8753", "0A", "10001"),
		"127.0.0.11 of 10006": line("0B00007F:1F90", "0A", "10006"),
		"0.0.0.0":             line("00000000:1F90", "0A", "0"),
		"127.0.0.110":         line("6E00007F:8753", "0A", "0"),
		"not listening":       line("0B00007F:8753", "01", "0"),
		"short line":          strings.Fields("0: 0B00007F:8753 00000000:0000 0A"),
	} {
		if isDockerResolver(f) {
			t.Errorf("%s: taken for Docker's resolver", name)
		}
	}
}
