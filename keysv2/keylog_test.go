// The firm key log's vectors: the Go side of the firm key log, checked against the browser's
// golden vectors (testdata/v2-keylog.json, identical to the chat client's test/golden/v2-keylog.json). A small
// replay of the chain with the signer rules, so the VM's key log verifier and the browser agree on every entry
// before either ships: hash, prev, canonical payload, signatures, who may sign what, and the final state. Also the
// safety code (the VM never shows one, but its inputs are pinned here too). Nothing here runs in the VM yet.
package keysv2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/keylog"
)

type keylogVectors struct {
	Format    string `json:"format"`
	Scheme    string `json:"scheme"`
	Constants struct {
		Labels map[string]string   `json:"labels"`
		Kinds  []string            `json:"kinds"`
		Fields map[string][]string `json:"fields"`
	} `json:"constants"`
	Firm       string `json:"firm"`
	Identities map[string]struct {
		ID        string `json:"id"`
		Member    string `json:"member"`
		User      string `json:"user"`
		Email     string `json:"email"`
		EmailHash string `json:"emailHash"`
		Ed25519   string `json:"ed25519"`
		X25519    string `json:"x25519"`
	} `json:"identities"`
	Kit struct {
		Ed25519 string `json:"ed25519"`
	} `json:"kit"`
	Keylog []struct {
		Kind      string   `json:"kind"`
		Signers   []string `json:"signers"`
		Payload   string   `json:"payload"`
		SignedHex string   `json:"signedHex"`
		Hash      string   `json:"hash"`
		Envelope  string   `json:"envelope"`
	} `json:"keylog"`
	Refused []struct {
		Why      string `json:"why"`
		At       int    `json:"at"`
		Envelope string `json:"envelope"`
	} `json:"refused"`
	State struct {
		Seq       int      `json:"seq"`
		Head      string   `json:"head"`
		Genesis   string   `json:"genesis"`
		Admins    []string `json:"admins"`
		Threshold int      `json:"threshold"`
		Current   []string `json:"current"`
		Revoked   []string `json:"revoked"`
		RootGen   int      `json:"rootGen"`
		Root      string   `json:"root"`
		Kit       string   `json:"kit"`
	} `json:"state"`
	Safety struct {
		MemberNonceHex string `json:"memberNonceHex"`
		AdminNonceHex  string `json:"adminNonceHex"`
		CommitInputHex string `json:"commitInputHex"`
		Commit         string `json:"commit"`
		CodeInputHex   string `json:"codeInputHex"`
		Code           string `json:"code"`
	} `json:"safety"`
}

func loadKeylog(t *testing.T) *keylogVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/v2-keylog.json")
	if err != nil {
		t.Fatal(err)
	}
	var v keylogVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Format != "tacy-golden-crypto-vectors" || v.Scheme != "keys-v2-keylog" {
		t.Fatalf("not the key log fixture: %s %s", v.Format, v.Scheme)
	}
	return &v
}

// replay verifies the whole chain from genesis with the VM's own verifier (../keylog, the exact port of the
// browser's keylog.ts) and returns its state, or the first error.
func replay(t *testing.T, v *keylogVectors, envs []envelope) (*keylog.State, string, error) {
	t.Helper()
	var es []keylog.Entry
	for _, e := range envs {
		k := keylog.Entry{Kind: e.Kind, Payload: e.Payload}
		for _, s := range e.Sigs {
			k.Sigs = append(k.Sigs, keylog.Sig{Key: s.Key, Sig: s.Sig})
		}
		es = append(es, k)
	}
	st, err := keylog.Replay(v.Firm, es)
	if err != nil {
		return nil, "", err
	}
	return st, st.Head, nil
}

func TestKeylogChain(t *testing.T) {
	v := loadKeylog(t)
	if v.Constants.Labels["keylog"] != "tacy-keylog/v1" || v.Constants.Labels["safetyCommit"] != "tacy/v2/safety-commit" || v.Constants.Labels["safetyCode"] != "tacy/v2/safety-code" || v.Constants.Labels["spaceName"] != "tacy/v2/space-name" {
		t.Fatalf("labels: %v", v.Constants.Labels)
	}
	var envs []envelope
	for i, lv := range v.Keylog {
		e := decodeEnvelope(t, lv.Envelope)
		msg := signedEntry(v.Constants.Labels["keylog"], e.Kind, e.Payload)
		if e.Kind != lv.Kind || string(e.Payload) != lv.Payload || hex.EncodeToString(msg) != lv.SignedHex {
			t.Fatalf("entry %d: bytes", i+1)
		}
		if sum := sha256.Sum256(msg); hex.EncodeToString(sum[:]) != lv.Hash {
			t.Errorf("entry %d: hash", i+1)
		}
		// The payload's fields are exactly the kind's, in order (canonical JSON).
		var keys []string
		dec := strings.NewReader(lv.Payload)
		var raw map[string]any
		_ = json.UnmarshalRead(dec, &raw)
		for k := range raw {
			keys = append(keys, k)
		}
		want := slices.Clone(v.Constants.Fields[e.Kind])
		slices.Sort(keys)
		slices.Sort(want)
		if !slices.Equal(keys, want) {
			t.Errorf("entry %d: fields %v, want %v", i+1, keys, want)
		}
		order := v.Constants.Fields[e.Kind]
		last := -1
		for _, f := range order {
			at := strings.Index(lv.Payload, `"`+f+`":`)
			if at < last {
				t.Errorf("entry %d: field %s out of order", i+1, f)
			}
			last = at
		}
		envs = append(envs, e)
	}
	st, head, err := replay(t, v, envs)
	if err != nil {
		t.Fatal(err)
	}
	if head != v.State.Head || len(v.Keylog) != v.State.Seq || v.Keylog[0].Hash != v.State.Genesis {
		t.Error("head")
	}
	var current, revoked []string
	for _, id := range append(slices.Clone(v.State.Current), v.State.Revoked...) {
		if st.Current(id) {
			current = append(current, id)
		} else if _, ok := st.Identity(id); ok {
			revoked = append(revoked, id)
		}
	}
	slices.Sort(current)
	slices.Sort(revoked)
	if !slices.Equal(st.Admins(), v.State.Admins) || !slices.Equal(current, v.State.Current) || !slices.Equal(revoked, v.State.Revoked) {
		t.Errorf("state: admins %v current %v revoked %v", st.Admins(), current, revoked)
	}
	if int(st.Threshold) != v.State.Threshold || int(st.RootGen) != v.State.RootGen || st.Root != v.State.Root || st.Kit != v.State.Kit || st.Kit != v.Kit.Ed25519 {
		t.Error("threshold, root or kit")
	}
	// Every negative vector is refused (appended after its first `at` entries).
	for _, r := range v.Refused {
		if _, _, err := replay(t, v, append(slices.Clone(envs[:r.At]), decodeEnvelope(t, r.Envelope))); err == nil {
			t.Errorf("refused vector accepted: %s", r.Why)
		}
	}

	// Refusals: reordered, a signature dropped below the threshold, a payload changed after signing, the kit
	// signing anything but admins, a fork against a pinned head.
	if _, _, err := replay(t, v, []envelope{envs[0], envs[2], envs[1]}); err == nil {
		t.Error("reordered log accepted")
	}
	short := envs[6]
	short.Sigs = short.Sigs[:1]
	if _, _, err := replay(t, v, append(slices.Clone(envs[:6]), short)); err == nil || !strings.Contains(err.Error(), "needs 2") {
		t.Errorf("one signature at threshold 2: %v", err)
	}
	changed := envs[1]
	changed.Payload = []byte(strings.Replace(string(changed.Payload), `"custodian":true`, `"custodian":false`, 1))
	if _, _, err := replay(t, v, append([]envelope{envs[0]}, changed)); err == nil {
		t.Error("changed payload accepted")
	}
	kitAdd := envs[2]
	kitAdd.Sigs = envs[5].Sigs // the kit's signature (over another payload) can't stand in, and the kit may not add
	if _, _, err := replay(t, v, envs[:2:2]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := replay(t, v, append(slices.Clone(envs[:2]), kitAdd)); err == nil {
		t.Error("kit-signed identity.add accepted")
	}
}

func TestSafetyCode(t *testing.T) {
	v := loadKeylog(t)
	s := v.Safety
	m := v.Identities["cal"]
	a := v.Identities["owner"]
	// Inputs: label, firm, then each person's identity, member, user, email hash and keys (the member first).
	who := func(x struct {
		ID        string `json:"id"`
		Member    string `json:"member"`
		User      string `json:"user"`
		Email     string `json:"email"`
		EmailHash string `json:"emailHash"`
		Ed25519   string `json:"ed25519"`
		X25519    string `json:"x25519"`
	}) []string {
		return []string{x.ID, x.Member, x.User, x.EmailHash, x.Ed25519, x.X25519}
	}
	commitIn := append(nul(append([]string{v.Constants.Labels["safetyCommit"], v.Firm}, who(m)...)...), 0)
	commitIn = append(commitIn, unhex(t, s.MemberNonceHex)...)
	if hex.EncodeToString(commitIn) != s.CommitInputHex {
		t.Fatal("commit input")
	}
	if sum := sha256.Sum256(commitIn); hex.EncodeToString(sum[:]) != s.Commit {
		t.Error("commit")
	}
	codeIn := append(nul(append(append([]string{v.Constants.Labels["safetyCode"], v.Firm}, who(m)...), who(a)...)...), 0)
	codeIn = append(codeIn, unhex(t, s.MemberNonceHex)...)
	codeIn = append(codeIn, unhex(t, s.AdminNonceHex)...)
	if hex.EncodeToString(codeIn) != s.CodeInputHex {
		t.Fatal("code input")
	}
	// The email hashes are the ones keylog.EmailHash makes from the people's emails.
	for name, p := range map[string]struct {
		ID        string `json:"id"`
		Member    string `json:"member"`
		User      string `json:"user"`
		Email     string `json:"email"`
		EmailHash string `json:"emailHash"`
		Ed25519   string `json:"ed25519"`
		X25519    string `json:"x25519"`
	}{"cal": m, "owner": a} {
		if h, err := keylog.EmailHash(v.Firm, p.Email); p.Email != "" && (err != nil || h != p.EmailHash) {
			t.Errorf("%s: email hash", name)
		}
	}
	sum := sha256.Sum256(codeIn)
	if got := fmt.Sprintf("%06d", binary.BigEndian.Uint64(sum[:8])%1_000_000); got != s.Code {
		t.Errorf("code %s, want %s", got, s.Code)
	}
}

// The email commitment (label "tacy/v2/member-email"): the browser's vectors, made by keylog.EmailHash too.
func TestEmailHashVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/v2-keylog.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Constants struct {
			Labels map[string]string `json:"labels"`
		} `json:"constants"`
		EmailHash []struct {
			Firm       string `json:"firm"`
			Email      string `json:"email"`
			Normalized string `json:"normalized"`
			InputHex   string `json:"inputHex"`
			Hash       string `json:"hash"`
		} `json:"emailHash"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Constants.Labels["memberEmail"] != keylog.EmailLabel || len(v.EmailHash) == 0 {
		t.Fatal("label or vectors missing")
	}
	for _, c := range v.EmailHash {
		if hex.EncodeToString(nul(keylog.EmailLabel, c.Firm, c.Normalized)) != c.InputHex {
			t.Errorf("%q: input", c.Email)
		}
		if h, err := keylog.EmailHash(c.Firm, c.Email); err != nil || h != c.Hash {
			t.Errorf("%q: %v", c.Email, err)
		}
	}
}
