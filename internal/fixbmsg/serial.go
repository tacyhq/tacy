package fixbmsg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The serial transport (2026-11-21, the rollback run): the same sealed messages as on the relay, written to the
// serial console in lines, for when the relay refuses the VM (ntfy.sh answered 429 to every post from Phala's
// shared egress address). The console is the host's (the CVM owner reads it), so it carries what the relay does:
// ciphertext sealed to the tester and signed inside, which the host can drop but not forge, replay or read. A line
// is "e2epush-m <id> <i>/<n> <base64 chunk>", id the first 8 bytes of the ciphertext's sha256 (hex).

// SerialPrefix starts every message line.
const SerialPrefix = "e2epush-m "

// SerialChunk is the base64 characters a line carries (a console record holds about 1000).
const SerialChunk = 600

// SerialLines is ct as console lines.
func SerialLines(ct []byte) []string {
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:8])
	b := base64.StdEncoding.EncodeToString(ct)
	n := (len(b) + SerialChunk - 1) / SerialChunk
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s%s %d/%d %s", SerialPrefix, id, i+1, n, b[i*SerialChunk:min(len(b), (i+1)*SerialChunk)]))
	}
	return out
}

var reSerial = regexp.MustCompile(`e2epush-m ([0-9a-f]{16}) (\d+)/(\d+) ([A-Za-z0-9+/=]+)`)

// ParseSerial reassembles the messages of a console log: by id, each one whose lines are all there and whose
// ciphertext hashes to its id. ids lists them in the order their first line appears; incomplete counts the rest.
func ParseSerial(log string) (msgs map[string][]byte, ids []string, incomplete int) {
	type part struct {
		n      int
		chunks map[int]string
	}
	parts := map[string]*part{}
	var order []string
	for _, ln := range strings.Split(log, "\n") {
		m := reSerial.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		i, _ := strconv.Atoi(m[2])
		n, _ := strconv.Atoi(m[3])
		if i < 1 || n < 1 || i > n || n > 1<<16 {
			continue
		}
		p := parts[m[1]]
		if p == nil {
			p = &part{n: n, chunks: map[int]string{}}
			parts[m[1]] = p
			order = append(order, m[1])
		}
		if p.n == n {
			p.chunks[i] = m[4]
		}
	}
	msgs = map[string][]byte{}
	for _, id := range order {
		p := parts[id]
		if len(p.chunks) != p.n {
			incomplete++
			continue
		}
		var b strings.Builder
		for i := 1; i <= p.n; i++ {
			b.WriteString(p.chunks[i])
		}
		ct, err := base64.StdEncoding.DecodeString(b.String())
		h := sha256.Sum256(ct)
		if err != nil || hex.EncodeToString(h[:8]) != id {
			incomplete++
			continue
		}
		msgs[id] = ct
		ids = append(ids, id)
	}
	return
}
