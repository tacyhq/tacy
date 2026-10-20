package main

// Keys v2 slice 5: the firm key log entries for f_chat (docs/26 section 4, decision 6), made and signed offline
// like the policies. The first owner's identity for f_chat is made here (its private halves only in files and
// then the password manager, as the admin key's), the genesis is signed by it and co-signed by the offline admin key
// (from then on f_chat's recovery kit), and keylog-check prints the genesis hash the compose pins.
//
//	safetysign identity DIR NAME -user <account id> -email <its email>   # DIR/NAME.key (Ed25519) + DIR/NAME.x25519.key; prints the public identity JSON
//	safetysign x25519 DIR NAME                             # DIR/NAME.x25519.key (the firm root); prints its public key
//	safetysign keylog-genesis -identity ID.json -kit ed25519:… -root x25519:… [-firm f_chat] > genesis.payload.json
//	pbpaste | safetysign keylog-sign -key /dev/stdin -kind genesis genesis.payload.json > genesis.1.json   # identity
//	pbpaste | safetysign keylog-sign -key /dev/stdin genesis.1.json > genesis.json                        # kit co-signs
//	safetysign keylog-check [-firm f_chat] genesis.json [more entries…]   # replays; prints seq, head, genesis, admins, kit

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/keylog"
)

// identityPub is an identity's public half as keylog-genesis takes it.
type identityPub struct {
	Identity    string `json:"identity"`
	Member      string `json:"member"`
	User        string `json:"user"`
	EmailHash   string `json:"email_hash"`
	Ed25519     string `json:"ed25519"`
	X25519      string `json:"x25519"`
	Fingerprint string `json:"fingerprint"`
}

func newID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return prefix + "_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

var userRe = regexp.MustCompile(`^([0-9a-f]{32}|u_[a-z2-7]{25}[aeimquy4])\z`)

// writeKey writes a private key file (0600, base64), refusing to overwrite one.
func writeKey(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(base64.StdEncoding.EncodeToString(b) + "\n"))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func newX25519(path string) (string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := writeKey(path, k.Bytes()); err != nil {
		return "", err
	}
	return "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// makeIdentity writes DIR/NAME.key and DIR/NAME.x25519.key and returns the public identity (fresh i_ and m_ ids).
func makeIdentity(dir, name, firm, user, email string) (*identityPub, error) {
	if !userRe.MatchString(user) {
		return nil, errors.New("-user must be the account's id (32 hex) or a u_ id")
	}
	eh, err := keylog.EmailHash(firm, email)
	if err != nil {
		return nil, fmt.Errorf("-email: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err = writeKey(filepath.Join(dir, name+".key"), priv.Seed()); err != nil {
		return nil, err
	}
	x, err := newX25519(filepath.Join(dir, name+".x25519.key"))
	if err != nil {
		return nil, err
	}
	ed := keylog.EdString(pub)
	fp, err := keylog.Fingerprint(ed, x)
	if err != nil {
		return nil, err
	}
	return &identityPub{Identity: newID("i"), Member: newID("m"), User: user, EmailHash: eh, Ed25519: ed, X25519: x, Fingerprint: fp}, nil
}

// genesisPayload is the canonical genesis payload (checked as the VM and the browser check it).
func genesisPayload(firm string, id *identityPub, kit, root string, now time.Time) ([]byte, error) {
	p := keylog.Payload{Kind: keylog.KindGenesis, Firm: firm, Seq: 1, Time: now.Unix(), Identity: id.Identity, Member: id.Member,
		User: id.User, EmailHash: id.EmailHash, Ed25519: id.Ed25519, X25519: id.X25519, Fingerprint: id.Fingerprint, Kit: kit, Root: root, Threshold: 1}
	b, err := p.Canonical()
	if err != nil {
		return nil, err
	}
	if _, err := keylog.DecodePayload(keylog.KindGenesis, b, firm); err != nil {
		return nil, err
	}
	if fp, err := keylog.Fingerprint(id.Ed25519, id.X25519); err != nil || fp != id.Fingerprint {
		return nil, errors.New("the identity's fingerprint doesn't match its keys")
	}
	if kit == id.Ed25519 {
		return nil, errors.New("the kit must be its own key")
	}
	return b, nil
}

// keylogSign signs in (a canonical payload of kind, or an entry to co-sign) with key. A payload is checked
// before it is signed; an entry's existing signatures must verify, and a key signs once.
func keylogSign(in []byte, kind, firm string, key ed25519.PrivateKey) (keylog.Entry, error) {
	in = bytes.TrimSpace(in)
	var e keylog.Entry
	if err := json.Unmarshal(in, &e, json.RejectUnknownMembers(true)); err == nil && e.Kind != "" {
		if _, err := keylog.DecodePayload(e.Kind, e.Payload, firm); err != nil {
			return e, err
		}
		msg := keylog.Signed(e.Kind, e.Payload)
		me := keylog.EdString(key.Public().(ed25519.PublicKey))
		for _, s := range e.Sigs {
			k, err := keylog.ParseEd(s.Key)
			if err != nil || !ed25519.Verify(k, msg, s.Sig) {
				return e, errors.New("the entry has a signature that doesn't verify")
			}
			if s.Key == me {
				return e, errors.New("this key already signed the entry")
			}
		}
		if len(e.Sigs) >= keylog.MaxSigs {
			return e, errors.New("too many signatures")
		}
		e.Sigs = append(e.Sigs, keylog.Sig{Key: me, Sig: ed25519.Sign(key, msg)})
		return e, nil
	}
	if !keylog.IsKind(kind) {
		return e, fmt.Errorf("-kind must be one of %v for a payload", keylog.Kinds)
	}
	if _, err := keylog.DecodePayload(kind, in, firm); err != nil {
		return e, err
	}
	return keylog.Sign(kind, in, key), nil
}

// readEntries reads each file: one entry, or a JSON array of them.
func readEntries(paths []string) ([]keylog.Entry, error) {
	var out []keylog.Entry
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 && b[0] == '[' {
			var es []keylog.Entry
			if err := json.Unmarshal(b, &es, json.RejectUnknownMembers(true)); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			out = append(out, es...)
			continue
		}
		var e keylog.Entry
		if err := json.Unmarshal(b, &e, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, e)
	}
	return out, nil
}

func outEntry(e keylog.Entry) {
	b, err := json.Marshal(e)
	if err != nil {
		die("%v", err)
	}
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "key log entry %s, %d signature(s), hash %s\n", e.Kind, len(e.Sigs), e.Hash())
}

// keylogCmd runs the key log subcommands (false: not one of them).
func keylogCmd(cmd string, args []string, keyPath, kind, firm, identity, kit, root, user, email string) bool {
	switch cmd {
	case "identity":
		if len(args) != 2 {
			die("identity DIR NAME -user <account id> -email <its email> [-firm f_chat]")
		}
		id, err := makeIdentity(args[0], args[1], firm, user, email)
		if err != nil {
			die("%v", err)
		}
		b, _ := json.Marshal(id)
		fmt.Println(string(b))
	case "x25519":
		if len(args) != 2 {
			die("x25519 DIR NAME")
		}
		pub, err := newX25519(filepath.Join(args[0], args[1]+".x25519.key"))
		if err != nil {
			die("%v", err)
		}
		fmt.Println(pub)
	case "keylog-genesis":
		if identity == "" || kit == "" || root == "" {
			die("keylog-genesis -identity ID.json -kit ed25519:… -root x25519:… [-firm f_chat]")
		}
		b, err := os.ReadFile(identity)
		if err != nil {
			die("%v", err)
		}
		var id identityPub
		if err := json.Unmarshal(bytes.TrimSpace(b), &id, json.RejectUnknownMembers(true)); err != nil {
			die("identity: %v", err)
		}
		p, err := genesisPayload(firm, &id, kit, root, time.Now())
		if err != nil {
			die("%v", err)
		}
		os.Stdout.Write(p)
	case "keylog-sign":
		if len(args) != 1 || keyPath == "" {
			die("keylog-sign -key K [-kind KIND] FILE (a payload of KIND, or an entry to co-sign)")
		}
		b, err := os.ReadFile(args[0])
		if err != nil {
			die("%v", err)
		}
		e, err := keylogSign(b, kind, firm, readKey(keyPath))
		if err != nil {
			die("%v", err)
		}
		outEntry(e)
	case "keylog-check":
		if len(args) == 0 {
			die("keylog-check [-firm f_chat] FILE…")
		}
		es, err := readEntries(args)
		if err != nil {
			die("%v", err)
		}
		st, err := keylog.Replay(firm, es)
		if err != nil {
			die("%v", err)
		}
		admins := st.Admins()
		slices.Sort(admins)
		fmt.Printf("firm %s: %d entries, head %s\ngenesis %s (the compose's -keylog-genesis)\nkey admins %v (threshold %d)\nkit %s\n",
			st.Firm, st.Seq, st.Head, st.Genesis, admins, st.Effective(), st.Kit)
	default:
		return false
	}
	return true
}
