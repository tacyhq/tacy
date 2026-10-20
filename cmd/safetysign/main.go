// safetysign makes keys and signs the step 6 documents (docs/23-safety-controls.md): policies and stop lists.
// Development and offline signing only; it is not part of the VM (cmd/compose doesn't build it).
// Private keys are written to files (0600) and never printed.
//
//	go run ./cmd/safetysign keygen DIR NAME            # DIR/NAME.key (private, base64 seed), prints the public key
//	go run ./cmd/safetysign sign -key K policy.json    # a policy (JSON, checked first) -> signed envelope on stdout
//	go run ./cmd/safetysign sign -key K -kind stop stop.json
//	go run ./cmd/safetysign heartbeat -key K [-ttl 15m] [-all]   # the operator's list: seq = now in ms
//	go run ./cmd/safetysign stop -key K -firm f_chat [-seq N] [-space s_chat | -all]   # the firm's own stop list
//
// The firm key log's entries (keys v2 slice 5): identity, x25519, keylog-genesis, keylog-sign, keylog-check
// (keylog.go).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tacyhq/tacy/safety"
)

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "safetysign: "+format+"\n", args...)
	os.Exit(1)
}

func readKey(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		die("%s isn't a key file", path)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func out(e safety.Envelope) {
	b, err := json.Marshal(e)
	if err != nil {
		die("%v", err)
	}
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "hash %s\n", e.Hash())
}

func main() {
	if len(os.Args) < 2 {
		die("usage: keygen | sign | heartbeat | stop | identity | x25519 | keylog-genesis | keylog-sign | keylog-check (see the source)")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	kind := fs.String("kind", safety.KindPolicy, "sign: policy | stop; keylog-sign: the entry kind of a payload")
	ttl := fs.Duration("ttl", 15*time.Minute, "heartbeat: lifetime (at most 1 h)")
	all := fs.Bool("all", false, "heartbeat: stop everything; stop: the whole firm")
	firm := fs.String("firm", "f_chat", "stop: the firm")
	space := fs.String("space", "", "stop: a space to stop")
	seq := fs.Uint64("seq", 0, "stop: sequence number (0: now in ms)")
	identity := fs.String("identity", "", "keylog-genesis: the first owner's public identity (identity's output)")
	kit := fs.String("kit", "", "keylog-genesis: the recovery kit's key (ed25519:…; f_chat: the offline admin key)")
	root := fs.String("root", "", "keylog-genesis: the firm root's public key (x25519:…)")
	user := fs.String("user", "", "identity: the account id the identity belongs to")
	email := fs.String("email", "", "identity: that account's email (the entry commits to it)")
	fs.Parse(os.Args[2:])
	if keylogCmd(os.Args[1], fs.Args(), *keyPath, *kind, *firm, *identity, *kit, *root, *user, *email) {
		return
	}
	now := time.Now().UTC()
	if *seq == 0 {
		*seq = uint64(now.UnixMilli())
	}
	switch os.Args[1] {
	case "keygen":
		if fs.NArg() != 2 {
			die("keygen DIR NAME")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("%v", err)
		}
		path := filepath.Join(fs.Arg(0), fs.Arg(1)+".key")
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			die("%v", err)
		}
		fmt.Println(safety.KeyString(pub))
	case "sign":
		if fs.NArg() != 1 || *keyPath == "" {
			die("sign -key K [-kind policy|stop] FILE")
		}
		var b []byte
		var err error
		if fs.Arg(0) == "-" {
			b, err = io.ReadAll(os.Stdin)
		} else {
			b, err = os.ReadFile(fs.Arg(0))
		}
		if err != nil {
			die("%v", err)
		}
		switch *kind { // checked as the VM will check it, then signed byte for byte
		case safety.KindPolicy:
			var p safety.Policy
			if err := json.Unmarshal(b, &p, json.RejectUnknownMembers(true)); err != nil {
				die("policy: %v", err)
			}
			if err := p.Validate(); err != nil {
				die("%v", err)
			}
		case safety.KindStop:
			var l safety.StopList
			if err := json.Unmarshal(b, &l, json.RejectUnknownMembers(true)); err != nil {
				die("stop list: %v", err)
			}
			if err := l.Validate(); err != nil {
				die("%v", err)
			}
		default:
			die("unknown kind %q", *kind)
		}
		out(safety.Sign(*kind, b, readKey(*keyPath)))
	case "heartbeat":
		if *keyPath == "" {
			die("heartbeat -key K")
		}
		e, err := safety.Heartbeat(readKey(*keyPath), *seq, now, *ttl, *all)
		if err != nil {
			die("%v", err)
		}
		out(e)
	case "stop":
		if *keyPath == "" {
			die("stop -key K -firm F [-space S | -all]")
		}
		l := safety.StopList{Type: safety.StopType, Issuer: safety.IssuerFirm, Firm: *firm, Seq: *seq, IssuedAt: now, All: *all}
		if *space != "" {
			l.Stop = []safety.Target{{Firm: *firm, Space: *space}}
		}
		if err := l.Validate(); err != nil {
			die("%v", err)
		}
		b, _ := json.Marshal(l)
		out(safety.Sign(safety.KindStop, b, readKey(*keyPath)))
	default:
		die("unknown command %q", os.Args[1])
	}
}
