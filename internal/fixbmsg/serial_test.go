package fixbmsg

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// Console lines carry a message whole, in any order, among other console output; a missing or edited line leaves
// the message out (incomplete), never half of it.
func TestSerialRoundTrip(t *testing.T) {
	a, b := make([]byte, 5000), make([]byte, 100)
	rand.Read(a)
	rand.Read(b)
	la, lb := SerialLines(a), SerialLines(b)
	if len(la) < 2 || len(lb) != 1 {
		t.Fatalf("%d %d lines", len(la), len(lb))
	}
	for _, l := range la {
		if len(l) > 700 {
			t.Fatalf("line of %d", len(l))
		}
	}
	// Reversed, with the kernel's timestamps and other lines in between.
	var log []string
	for i := len(la) - 1; i >= 0; i-- {
		log = append(log, "[  12.345678] "+la[i], "[  12.4] e2epush: posted x")
	}
	log = append(log, "[ 13.0] "+lb[0], "[ 13.1] "+lb[0]) // a line twice
	msgs, ids, inc := ParseSerial(strings.Join(log, "\n"))
	if inc != 0 || len(ids) != 2 || !bytes.Equal(msgs[ids[0]], a) || !bytes.Equal(msgs[ids[1]], b) {
		t.Fatalf("%d %v %d", len(msgs), ids, inc)
	}
	// One line missing, and one edited: neither message comes out.
	edited := strings.Replace(lb[0], lb[0][len(lb[0])-8:len(lb[0])-4], "AAAA", 1)
	msgs, ids, inc = ParseSerial(strings.Join(la[1:], "\n") + "\n" + edited)
	if len(msgs) != 0 || len(ids) != 0 || inc != 2 {
		t.Fatalf("partial: %d %v %d", len(msgs), ids, inc)
	}
}
