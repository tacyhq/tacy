// Package keysv2 holds the Go side of keys v2's first vectors: for now only this test, which checks
// the browser's golden vectors (testdata/v2.json, written once by the chat client's generator) with the standard
// library alone, so the VM's later verifiers (firm key log, space proofs, unattended custody) and the browser
// agree byte for byte. Nothing here runs in the VM yet.
package keysv2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type identity struct {
	ID          string `json:"id"`
	EdSeedHex   string `json:"ed25519SeedHex"`
	XPrivHex    string `json:"x25519PrivateHex"`
	Ed25519     string `json:"ed25519"`
	X25519      string `json:"x25519"`
	Fingerprint string `json:"fingerprint"`
	Admin       bool   `json:"admin"`
	Current     bool   `json:"current"`
}

type generation struct {
	Gen            int    `json:"gen"`
	SpaceKeyHex    string `json:"spaceKeyHex"`
	SealPrivateHex string `json:"sealPrivateHex"`
	Seal           string `json:"seal"`
	SealIvHex      string `json:"sealIvHex"`
	SealAadHex     string `json:"sealAadHex"`
	SealedSealHex  string `json:"sealedSealHex"`
}

type wrapVector struct {
	Name         string `json:"name"`
	EphemeralHex string `json:"ephemeralHex"`
	HpkeAadHex   string `json:"hpkeAadHex"`
	SignedHex    string `json:"signedHex"`
	Wrap         string `json:"wrap"`
}

type logVector struct {
	Kind      string `json:"kind"`
	Payload   string `json:"payload"`
	SignedHex string `json:"signedHex"`
	Hash      string `json:"hash"`
	Envelope  string `json:"envelope"`
}

type space struct {
	Firm        string       `json:"firm"`
	Space       string       `json:"space"`
	Generations []generation `json:"generations"`
	Wraps       []wrapVector `json:"wraps"`
	Log         []logVector  `json:"log"`
}

type itemKey struct {
	Name       string `json:"name"`
	Space      string `json:"space"`
	Gen        int    `json:"gen"`
	Item       string `json:"item"`
	Epoch      uint32 `json:"epoch"`
	ItemKeyHex string `json:"itemKeyHex"`
	IvHex      string `json:"ivHex"`
	AadHex     string `json:"aadHex"`
	WrappedHex string `json:"wrappedHex"`
}

type record struct {
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Item       string         `json:"item"`
	Record     string         `json:"record"`
	Version    int            `json:"version"`
	Epoch      uint32         `json:"epoch"`
	ItemKeyHex string         `json:"itemKeyHex"`
	IvHex      string         `json:"ivHex"`
	AadHex     string         `json:"aadHex"`
	Plaintext  map[string]any `json:"plaintext"`
	BlobHex    string         `json:"blobHex"`
}

type vectors struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	Constants struct {
		Labels      map[string]string `json:"labels"`
		Separator   string            `json:"separator"`
		Format      byte              `json:"format"`
		Alg         byte              `json:"alg"`
		IDPrefixes  []string          `json:"idPrefixes"`
		Personal    string            `json:"personal"`
		ItemKeyWrap int               `json:"itemKeyWrapBytes"`
		SealedSeal  int               `json:"sealedSealKeyBytes"`
	} `json:"constants"`
	IDs struct {
		Valid []struct {
			Prefix string `json:"prefix"`
			Hex    string `json:"hex"`
			ID     string `json:"id"`
		} `json:"valid"`
		Invalid []string `json:"invalid"`
	} `json:"ids"`
	Identities    map[string]identity `json:"identities"`
	FirmSpace     space               `json:"firmSpace"`
	PersonalSpace space               `json:"personalSpace"`
	ItemKeys      []itemKey           `json:"itemKeys"`
	Records       []record            `json:"records"`
	Keylog        struct {
		Signers   []string `json:"signers"`
		Kind      string   `json:"kind"`
		Payload   string   `json:"payload"`
		SignedHex string   `json:"signedHex"`
		Hash      string   `json:"hash"`
		Envelope  string   `json:"envelope"`
	} `json:"keylog"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	// Unknown members are fine here (the TS test owns the file's shape); every value used is checked.
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Format != "tacy-golden-crypto-vectors" || v.Version != 2 {
		t.Fatalf("not the v2 fixture: %s %d", v.Format, v.Version)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// nul joins parts with NUL, as every v2 AAD and signed string does.
func nul(parts ...string) []byte { return []byte(strings.Join(parts, "\x00")) }

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
var idRE = regexp.MustCompile(`^([a-z])_([a-z2-7]{26})$`)

// parseID is the strict id check the VM will use: a known prefix and the one canonical base32 spelling.
func parseID(prefixes []string, s string) ([]byte, bool) {
	m := idRE.FindStringSubmatch(s)
	if m == nil || !slices.Contains(prefixes, m[1]) {
		return nil, false
	}
	b, err := b32.DecodeString(m[2])
	if err != nil || len(b) != 16 || b32.EncodeToString(b) != m[2] {
		return nil, false
	}
	return b, true
}

func parseKey(t *testing.T, prefix, s string) []byte {
	t.Helper()
	raw, ok := strings.CutPrefix(s, prefix+":")
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	if !ok || err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != raw {
		t.Fatalf("bad %s key %q", prefix, s)
	}
	return b
}

func gcmOpen(t *testing.T, key, iv, ct, aad []byte) ([]byte, error) {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	return g.Open(nil, iv, ct, aad)
}

func TestIDs(t *testing.T) {
	v := load(t)
	if !slices.Equal(v.Constants.IDPrefixes, []string{"f", "m", "g", "u", "s", "i", "t", "d", "a"}) {
		t.Fatalf("prefixes changed: %v", v.Constants.IDPrefixes)
	}
	for _, c := range v.IDs.Valid {
		b, ok := parseID(v.Constants.IDPrefixes, c.ID)
		if !ok || hex.EncodeToString(b) != c.Hex || c.ID != c.Prefix+"_"+b32.EncodeToString(unhex(t, c.Hex)) {
			t.Errorf("id %s: bytes %x, want %s", c.ID, b, c.Hex)
		}
	}
	for _, s := range v.IDs.Invalid {
		if _, ok := parseID(v.Constants.IDPrefixes, s); ok {
			t.Errorf("invalid id %q accepted", s)
		}
	}
}

func TestIdentities(t *testing.T) {
	v := load(t)
	for name, id := range v.Identities {
		priv := ed25519.NewKeyFromSeed(unhex(t, id.EdSeedHex))
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), parseKey(t, "ed25519", id.Ed25519)) {
			t.Errorf("%s: ed25519 public key", name)
		}
		x, err := ecdh.X25519().NewPrivateKey(unhex(t, id.XPrivHex))
		if err != nil || !bytes.Equal(x.PublicKey().Bytes(), parseKey(t, "x25519", id.X25519)) {
			t.Errorf("%s: x25519 public key", name)
		}
		sum := sha256.Sum256(append(parseKey(t, "ed25519", id.Ed25519), parseKey(t, "x25519", id.X25519)...))
		if b32.EncodeToString(sum[:16]) != id.Fingerprint {
			t.Errorf("%s: fingerprint", name)
		}
	}
}

func TestRecordsAndItemKeys(t *testing.T) {
	v := load(t)
	L := v.Constants.Labels
	labels := map[string]string{"thread": L["recordThread"], "message": L["recordMessage"], "file": L["recordFile"], "memory": L["recordMemory"]}
	spaceKeys := map[string][]byte{}
	for _, s := range []space{v.FirmSpace, v.PersonalSpace} {
		for _, g := range s.Generations {
			spaceKeys[s.Space+"/"+strconv.Itoa(g.Gen)] = unhex(t, g.SpaceKeyHex)
		}
	}
	for _, k := range v.ItemKeys {
		aad := nul(L["itemKey"], k.Space, strconv.Itoa(k.Gen), k.Item, strconv.FormatUint(uint64(k.Epoch), 10))
		if hex.EncodeToString(aad) != k.AadHex {
			t.Errorf("%s: item key AAD", k.Name)
		}
		w := unhex(t, k.WrappedHex)
		if len(w) != v.Constants.ItemKeyWrap || w[0] != 2 || w[1] != 1 || !bytes.Equal(w[2:14], unhex(t, k.IvHex)) {
			t.Fatalf("%s: item key wrap layout", k.Name)
		}
		key, err := gcmOpen(t, spaceKeys[k.Space+"/"+strconv.Itoa(k.Gen)], w[2:14], w[14:], aad)
		if err != nil || hex.EncodeToString(key) != k.ItemKeyHex {
			t.Errorf("%s: item key: %v", k.Name, err)
		}
		// Another epoch (or anything else in the AAD) doesn't open it.
		bad := nul(L["itemKey"], k.Space, strconv.Itoa(k.Gen), k.Item, strconv.FormatUint(uint64(k.Epoch)+1, 10))
		if _, err := gcmOpen(t, spaceKeys[k.Space+"/"+strconv.Itoa(k.Gen)], w[2:14], w[14:], bad); err == nil {
			t.Errorf("%s: opened with another epoch", k.Name)
		}
	}
	for _, r := range v.Records {
		aad := nul(labels[r.Kind], r.Item, r.Record, strconv.Itoa(r.Version), "2", "1", strconv.FormatUint(uint64(r.Epoch), 10))
		if hex.EncodeToString(aad) != r.AadHex {
			t.Errorf("%s: record AAD", r.Name)
		}
		blob := unhex(t, r.BlobHex)
		if blob[0] != v.Constants.Format || blob[1] != v.Constants.Alg || binary.BigEndian.Uint32(blob[2:6]) != r.Epoch || !bytes.Equal(blob[6:18], unhex(t, r.IvHex)) {
			t.Fatalf("%s: record header", r.Name)
		}
		pt, err := gcmOpen(t, unhex(t, r.ItemKeyHex), blob[6:18], blob[18:], aad)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		trimmed := bytes.TrimRight(pt, " ")
		if len(pt) != padded(len(trimmed)) {
			t.Errorf("%s: padding %d for %d bytes", r.Name, len(pt), len(trimmed))
		}
		var got map[string]any
		if err := json.Unmarshal(trimmed, &got); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(r.Plaintext, json.Deterministic(true))
		have, _ := json.Marshal(got, json.Deterministic(true))
		if !bytes.Equal(want, have) {
			t.Errorf("%s: plaintext %s, want %s", r.Name, have, want)
		}
		// The same bytes under another kind's label are refused (label confusion).
		for kind, label := range labels {
			if kind == r.Kind {
				continue
			}
			other := nul(label, r.Item, r.Record, strconv.Itoa(r.Version), "2", "1", strconv.FormatUint(uint64(r.Epoch), 10))
			if _, err := gcmOpen(t, unhex(t, r.ItemKeyHex), blob[6:18], blob[18:], other); err == nil {
				t.Errorf("%s: opened as a %s record", r.Name, kind)
			}
		}
	}
}

// padded is v1's length buckets: powers of two from 1 KiB to 64 KiB, then multiples of 64 KiB.
func padded(n int) int {
	const step = 65536
	if n > step {
		return (n + step - 1) / step * step
	}
	size := 1024
	for size < n {
		size *= 2
	}
	return size
}

type wrap struct {
	V     int    `json:"v"`
	Firm  string `json:"firm"`
	Space string `json:"space"`
	Gen   int    `json:"gen"`
	To    string `json:"to"`
	By    string `json:"by"`
	Enc   []byte `json:"enc"`
	CT    []byte `json:"ct"`
	Sig   []byte `json:"sig"`
}

func TestSpacesAndWraps(t *testing.T) {
	v := load(t)
	L := v.Constants.Labels
	byID := map[string]identity{}
	for _, id := range v.Identities {
		byID[id.ID] = id
	}
	suiteKDF, suiteAEAD := hpke.HKDFSHA256(), hpke.AES256GCM()
	for _, s := range []space{v.FirmSpace, v.PersonalSpace} {
		keys := map[int][]byte{}
		for _, g := range s.Generations {
			keys[g.Gen] = unhex(t, g.SpaceKeyHex)
			aad := nul(L["spaceSealKey"], s.Firm, s.Space, strconv.Itoa(g.Gen), g.Seal)
			if hex.EncodeToString(aad) != g.SealAadHex {
				t.Errorf("gen %d: seal AAD", g.Gen)
			}
			sealed := unhex(t, g.SealedSealHex)
			if len(sealed) != v.Constants.SealedSeal || sealed[0] != 2 || sealed[1] != 1 {
				t.Fatalf("gen %d: sealed seal layout", g.Gen)
			}
			pkcs8, err := gcmOpen(t, keys[g.Gen], sealed[2:14], sealed[14:], aad)
			if err != nil {
				t.Fatalf("gen %d: seal key: %v", g.Gen, err)
			}
			prefix := unhex(t, "302e020100300506032b656e04220420")
			if !bytes.HasPrefix(pkcs8, prefix) || len(pkcs8) != 48 || hex.EncodeToString(pkcs8[16:]) != g.SealPrivateHex {
				t.Fatalf("gen %d: seal key isn't RFC 8410 PKCS#8 of the recorded key", g.Gen)
			}
			priv, _ := ecdh.X25519().NewPrivateKey(pkcs8[16:])
			if !bytes.Equal(priv.PublicKey().Bytes(), parseKey(t, "x25519", g.Seal)) {
				t.Errorf("gen %d: seal public key", g.Gen)
			}
		}
		for _, wv := range s.Wraps {
			var w wrap
			if err := json.Unmarshal([]byte(wv.Wrap), &w, json.RejectUnknownMembers(true)); err != nil {
				t.Fatalf("%s: %v", wv.Name, err)
			}
			canon, _ := json.Marshal(&w)
			if string(canon) != wv.Wrap || w.V != 2 || w.Firm != s.Firm || w.Space != s.Space {
				t.Fatalf("%s: not canonical: %s", wv.Name, canon)
			}
			signed := append(nul(L["spaceWrapSig"], w.Firm, w.Space, strconv.Itoa(w.Gen), w.To, w.By), 0)
			signed = append(append(signed, w.Enc...), w.CT...)
			if hex.EncodeToString(signed) != wv.SignedHex {
				t.Errorf("%s: signed bytes", wv.Name)
			}
			granter, recipient := byID[w.By], byID[w.To]
			if !ed25519.Verify(parseKey(t, "ed25519", granter.Ed25519), signed, w.Sig) {
				t.Errorf("%s: signature", wv.Name)
			}
			// A wrap presented as signed by anyone else fails.
			for _, other := range v.Identities {
				if other.ID != w.By && ed25519.Verify(parseKey(t, "ed25519", other.Ed25519), signed, w.Sig) {
					t.Errorf("%s: verifies under %s", wv.Name, other.ID)
				}
			}
			aad := nul(w.Firm, w.Space, strconv.Itoa(w.Gen), w.To)
			if hex.EncodeToString(aad) != wv.HpkeAadHex {
				t.Errorf("%s: HPKE aad", wv.Name)
			}
			// The ephemeral's public key is enc.
			eph, _ := ecdh.X25519().NewPrivateKey(unhex(t, wv.EphemeralHex))
			if !bytes.Equal(eph.PublicKey().Bytes(), w.Enc) {
				t.Errorf("%s: enc isn't the recorded ephemeral's public key", wv.Name)
			}
			// Open with Go's own HPKE (RFC 9180 base mode), independent of the browser's WebCrypto version.
			xpriv, _ := ecdh.X25519().NewPrivateKey(unhex(t, recipient.XPrivHex))
			k, err := hpke.NewDHKEMPrivateKey(xpriv)
			if err != nil {
				t.Fatal(err)
			}
			r, err := hpke.NewRecipient(w.Enc, k, suiteKDF, suiteAEAD, []byte(L["spaceWrapInfo"]))
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Open(aad, w.CT)
			if err != nil || !bytes.Equal(got, keys[w.Gen]) {
				t.Errorf("%s: HPKE open: %v", wv.Name, err)
			}
			// Another recipient in the aad fails.
			r2, _ := hpke.NewRecipient(w.Enc, k, suiteKDF, suiteAEAD, []byte(L["spaceWrapInfo"]))
			if _, err := r2.Open(nul(w.Firm, w.Space, strconv.Itoa(w.Gen), w.By+"x"), w.CT); err == nil {
				t.Errorf("%s: opened with another aad", wv.Name)
			}
		}
	}
}

type envelope struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	Sigs    []struct {
		Key string `json:"key"`
		Sig []byte `json:"sig"`
	} `json:"sigs"`
}

func decodeEnvelope(t *testing.T, s string) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal([]byte(s), &e, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if canon, _ := json.Marshal(&e); string(canon) != s {
		t.Fatalf("envelope not canonical: %s", canon)
	}
	return e
}

func signedEntry(label, kind string, payload []byte) []byte {
	return append(nul(label, kind, ""), payload...)
}

func TestSpaceLogs(t *testing.T) {
	v := load(t)
	L := v.Constants.Labels
	byID := map[string]identity{}
	for _, id := range v.Identities {
		byID[id.ID] = id
	}
	for _, s := range []space{v.FirmSpace, v.PersonalSpace} {
		prev := ""
		for i, lv := range s.Log {
			e := decodeEnvelope(t, lv.Envelope)
			if e.Kind != lv.Kind || string(e.Payload) != lv.Payload {
				t.Fatalf("entry %d: kind or payload", i+1)
			}
			msg := signedEntry(L["spaceLog"], e.Kind, e.Payload)
			if hex.EncodeToString(msg) != lv.SignedHex {
				t.Errorf("entry %d: signed bytes", i+1)
			}
			sum := sha256.Sum256(msg)
			if hex.EncodeToString(sum[:]) != lv.Hash {
				t.Errorf("entry %d: hash", i+1)
			}
			var p struct {
				Space string `json:"space"`
				Firm  string `json:"firm"`
				Seq   int    `json:"seq"`
				Prev  string `json:"prev"`
				By    string `json:"by"`
			}
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Seq != i+1 || p.Prev != prev || p.Space != s.Space || p.Firm != s.Firm {
				t.Errorf("entry %d: chain (seq %d prev %s)", i+1, p.Seq, p.Prev)
			}
			if len(e.Sigs) != 1 || e.Sigs[0].Key != byID[p.By].Ed25519 || !ed25519.Verify(parseKey(t, "ed25519", e.Sigs[0].Key), msg, e.Sigs[0].Sig) {
				t.Errorf("entry %d: signature by its author", i+1)
			}
			// The same entry presented as a firm key log entry, or as another kind, fails.
			if ed25519.Verify(parseKey(t, "ed25519", e.Sigs[0].Key), signedEntry(L["keylog"], e.Kind, e.Payload), e.Sigs[0].Sig) {
				t.Errorf("entry %d: verifies under the key log label", i+1)
			}
			if ed25519.Verify(parseKey(t, "ed25519", e.Sigs[0].Key), signedEntry(L["spaceLog"], "grant"+strings.Repeat("x", i), e.Payload), e.Sigs[0].Sig) {
				t.Errorf("entry %d: verifies as another kind", i+1)
			}
			prev = lv.Hash
		}
	}
}

func TestKeylogEnvelope(t *testing.T) {
	v := load(t)
	k := v.Keylog
	e := decodeEnvelope(t, k.Envelope)
	msg := signedEntry(v.Constants.Labels["keylog"], e.Kind, e.Payload)
	if e.Kind != k.Kind || string(e.Payload) != k.Payload || hex.EncodeToString(msg) != k.SignedHex {
		t.Fatal("key log entry bytes")
	}
	if sum := sha256.Sum256(msg); hex.EncodeToString(sum[:]) != k.Hash {
		t.Error("key log hash")
	}
	if len(e.Sigs) != len(k.Signers) {
		t.Fatal("signature count")
	}
	for i, s := range e.Sigs {
		if s.Key != k.Signers[i] || !ed25519.Verify(parseKey(t, "ed25519", s.Key), msg, s.Sig) {
			t.Errorf("signature %d", i)
		}
		if ed25519.Verify(parseKey(t, "ed25519", s.Key), signedEntry(v.Constants.Labels["spaceLog"], e.Kind, e.Payload), s.Sig) {
			t.Errorf("signature %d verifies under the space log label", i)
		}
	}
}

func TestLabels(t *testing.T) {
	v := load(t)
	want := map[string]string{
		"recordThread": "tacy/v2/thread", "recordMessage": "tacy/v2/message", "recordFile": "tacy/v2/file", "recordMemory": "tacy/v2/memory",
		"itemKey": "tacy/v2/item-key", "spaceSealKey": "tacy/v2/space-seal-key", "spaceWrapInfo": "tacy/v2/space-wrap",
		"spaceWrapSig": "tacy/v2/space-wrap/signed", "spaceLog": "tacy/v2/space-log", "keylog": "tacy-keylog/v1",
	}
	if len(v.Constants.Labels) != len(want) {
		t.Fatalf("labels: %v", v.Constants.Labels)
	}
	for k, l := range want {
		if v.Constants.Labels[k] != l {
			t.Errorf("label %s = %q, want %q", k, v.Constants.Labels[k], l)
		}
	}
	if v.Constants.Separator != "\x00" || v.Constants.Personal != "personal" {
		t.Error("separator or personal")
	}
}
