// Package keylog is the VM's side of the firm key log (keys v2 slice 5, docs/26-keys-v2.md section 4 and its
// decisions 5, 6 and 12): an append-only, hash-chained list of signed entries per firm naming its identities'
// public keys, its key admins, the signature threshold, the firm root public key and the recovery-kit signer.
//
// The VM's compose pins the firm and the genesis entry's hash; the VM verifies the chain from that genesis itself
// and takes the firm's admin signers (for policies and the firm's stop lists) from the log's current key admins,
// so admin keys are no longer pinned in the compose. This is the same check as the browser's and the Worker's
// (the chat's src/client/v2/keylog.ts), rule for rule: the golden vectors in ../keysv2/testdata
// (v2-keylog.json, made by the browser's code) replay here, and testdata/fchat-keylog.json (made here) replays
// there.
//
// Envelope: the safety envelope's shape under the label "tacy-keylog/v1". A signature covers "tacy-keylog/v1" ‖
// NUL ‖ kind ‖ NUL ‖ payload, and the entry's hash (what the next entry's prev names) is the hex SHA-256 of those
// bytes. Payloads are canonical JSON (JSON.stringify of exactly the kind's fields, in order):
//
//	genesis          {firm, seq: 1, prev: "", time, identity, member, user, email_hash, ed25519, x25519, fingerprint, kit, root, threshold: 1}
//	identity.add     {firm, seq, prev, time, identity, member, user, email_hash, ed25519, x25519, fingerprint, admin, custodian}
//	identity.revoke  {firm, seq, prev, time, identity}
//	admins           {firm, seq, prev, time, admins: [i_…] (sorted, distinct)}
//	threshold        {firm, seq, prev, time, threshold}
//	root.rotate      {firm, seq, prev, time, gen, root}
//
// Who signs: genesis exactly the first owner's identity and the recovery kit; identity.add, threshold and
// root.rotate the key admins (threshold); identity.revoke the key admins or the identity alone; admins the key
// admins or the recovery kit (the kit signs nothing else after genesis). The threshold in force is min(threshold,
// number of admins). Identities are never re-added and no public key is used twice; a member and an account have
// at most one current identity. email_hash binds the person's email (EmailHash): the log only checks its form,
// browsers compare it with the email they show, and the safety code covers it.
//
// The placeholder firm f_chat (the chat's shared VM, ours) is accepted only when the log is asked for exactly
// that firm, and there an identity's user may also be a legacy account id (32 lowercase hex), since our own
// accounts predate u_ ids. Standard library only.
package keylog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Label is what every key log signature and hash starts with.
const Label = "tacy-keylog/v1"

// Placeholder is the chat VM's firm id until slice 6.
const Placeholder = "f_chat"

// Kinds of entries.
const (
	KindGenesis  = "genesis"
	KindAdd      = "identity.add"
	KindRevoke   = "identity.revoke"
	KindAdmins   = "admins"
	KindThresh   = "threshold"
	KindRootRot  = "root.rotate"
	MaxSigs      = 8
	MaxAdmins    = MaxSigs
	MaxThreshold = MaxSigs
	// MaxPayload is the browser's bound (log.ts MAX_PAYLOAD); a valid payload is under 1 KiB.
	MaxPayload = 32 << 10
	// MaxEntries bounds one firm's log in the VM (a firm adds a few entries a month). The whole log travels with
	// the documents agentd passes to gatewayd and the vault.
	MaxEntries = 1024
	// MaxEntryWire bounds one valid entry as JSON (its payload is under 1 KiB by format, plus up to 8 signatures).
	MaxEntryWire = 4 << 10
)

// Kinds lists every entry kind, in the browser's order.
var Kinds = []string{KindGenesis, KindAdd, KindRevoke, KindAdmins, KindThresh, KindRootRot}

// IsKind says whether kind is a key log entry kind (they never collide with safety document kinds).
func IsKind(kind string) bool { return slices.Contains(Kinds, kind) }

// Sig is one signature: Key is "ed25519:<base64>".
type Sig struct {
	Key string `json:"key"`
	Sig []byte `json:"sig"`
}

// Entry is one signed entry as it travels: the payload exactly as signed.
type Entry struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	Sigs    []Sig  `json:"sigs"`
}

// Signed is what the signatures cover and the hash is of.
func Signed(kind string, payload []byte) []byte {
	b := make([]byte, 0, len(Label)+len(kind)+2+len(payload))
	b = append(b, Label...)
	b = append(b, 0)
	b = append(b, kind...)
	b = append(b, 0)
	return append(b, payload...)
}

// Hash is the entry's hash, hex.
func (e *Entry) Hash() string {
	h := sha256.Sum256(Signed(e.Kind, e.Payload))
	return hex.EncodeToString(h[:])
}

// Sign makes an entry signed by each key (tests and cmd/safetysign).
func Sign(kind string, payload []byte, keys ...ed25519.PrivateKey) Entry {
	e := Entry{Kind: kind, Payload: bytes.Clone(payload)}
	for _, k := range keys {
		e.Sigs = append(e.Sigs, Sig{Key: EdString(k.Public().(ed25519.PublicKey)), Sig: ed25519.Sign(k, Signed(kind, payload))})
	}
	return e
}

// ---- payloads -------------------------------------------------------------------------------------------------

// Payload holds every field any kind has; Fields says which a kind uses, in canonical order.
type Payload struct {
	Kind        string   `json:"-"`
	Firm        string   `json:"firm"`
	Seq         int64    `json:"seq"`
	Prev        string   `json:"prev"`
	Time        int64    `json:"time"`
	Identity    string   `json:"identity"`
	Member      string   `json:"member"`
	User        string   `json:"user"`
	EmailHash   string   `json:"email_hash"`
	Ed25519     string   `json:"ed25519"`
	X25519      string   `json:"x25519"`
	Fingerprint string   `json:"fingerprint"`
	Kit         string   `json:"kit"`
	Root        string   `json:"root"`
	Threshold   int64    `json:"threshold"`
	Admin       bool     `json:"admin"`
	Custodian   bool     `json:"custodian"`
	Admins      []string `json:"admins"`
	Gen         int64    `json:"gen"`
}

var (
	common = []string{"firm", "seq", "prev", "time"}
	ident  = []string{"identity", "member", "user", "email_hash", "ed25519", "x25519", "fingerprint"}
	// Fields are each kind's payload fields in canonical order (keylog.ts KEYLOG_FIELDS).
	Fields = map[string][]string{
		KindGenesis: concat(common, ident, []string{"kit", "root", "threshold"}),
		KindAdd:     concat(common, ident, []string{"admin", "custodian"}),
		KindRevoke:  concat(common, []string{"identity"}),
		KindAdmins:  concat(common, []string{"admins"}),
		KindThresh:  concat(common, []string{"threshold"}),
		KindRootRot: concat(common, []string{"gen", "root"}),
	}
)

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

const maxSafe = 1<<53 - 1

var (
	hashRe   = regexp.MustCompile(`^[0-9a-f]{64}\z`)
	fpRe     = regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]\z`)
	legacyRe = regexp.MustCompile(`^[0-9a-f]{32}\z`)
	b32      = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// IsID: a canonical id with this one-letter prefix: "<p>_" plus 26 base32 characters, the last one's two low
// bits zero (ids.ts isId).
func IsID(s, prefix string) bool {
	return len(s) == 28 && strings.HasPrefix(s, prefix+"_") && fpRe.MatchString(s[2:])
}

// EdString is an Ed25519 public key as entries name it.
func EdString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// strictKey decodes "<prefix>:<base64 of 32 bytes>" in its one canonical spelling.
func strictKey(prefix, s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, prefix+":")
	if !ok {
		return nil, fmt.Errorf("bad %s key", prefix)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != b64 {
		return nil, fmt.Errorf("bad %s key", prefix)
	}
	return b, nil
}

// ParseEd parses an Ed25519 public key string.
func ParseEd(s string) (ed25519.PublicKey, error) {
	b, err := strictKey("ed25519", s)
	return ed25519.PublicKey(b), err
}

// ParseX parses an X25519 public key string (the all-zero key refused).
func ParseX(s string) ([]byte, error) {
	b, err := strictKey("x25519", s)
	if err == nil && bytes.Equal(b, make([]byte, 32)) {
		return nil, errors.New("bad x25519 key")
	}
	return b, err
}

// EmailLabel separates the email commitment (EmailHash) from every other hash.
const EmailLabel = "tacy/v2/member-email"

// EmailHash commits an identity entry to the person's email: hex SHA-256(label ‖ NUL ‖ firm ‖ NUL ‖ normalized
// email), normalized = trimmed and lowercased. ASCII only here (the browser's toLowerCase and Go's agree on it);
// tools refuse anything else.
func EmailHash(firm, email string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(email))
	for i := 0; i < len(e); i++ {
		if e[i] < 0x21 || e[i] > 0x7e {
			return "", errors.New("email: printable ASCII only")
		}
	}
	if e == "" || !strings.Contains(e, "@") {
		return "", errors.New("email: missing")
	}
	h := sha256.Sum256([]byte(EmailLabel + "\x00" + firm + "\x00" + e))
	return hex.EncodeToString(h[:]), nil
}

// Fingerprint is the first 16 bytes of SHA-256(ed25519 ‖ x25519), in id base32.
func Fingerprint(ed, x string) (string, error) {
	e, err := ParseEd(ed)
	if err != nil {
		return "", err
	}
	xb, err := ParseX(x)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append(append([]byte{}, e...), xb...))
	return b32.EncodeToString(h[:16]), nil
}

// Canonical writes p's fields for its kind as JSON.stringify does (every string field is checked to plain ASCII
// before this is compared, so escaping never differs).
func (p *Payload) Canonical() ([]byte, error) {
	fields, ok := Fields[p.Kind]
	if !ok {
		return nil, errors.New("unknown entry kind")
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(f))
		b.WriteByte(':')
		switch f {
		case "firm":
			jstr(&b, p.Firm)
		case "seq":
			b.WriteString(strconv.FormatInt(p.Seq, 10))
		case "prev":
			jstr(&b, p.Prev)
		case "time":
			b.WriteString(strconv.FormatInt(p.Time, 10))
		case "identity":
			jstr(&b, p.Identity)
		case "member":
			jstr(&b, p.Member)
		case "user":
			jstr(&b, p.User)
		case "email_hash":
			jstr(&b, p.EmailHash)
		case "ed25519":
			jstr(&b, p.Ed25519)
		case "x25519":
			jstr(&b, p.X25519)
		case "fingerprint":
			jstr(&b, p.Fingerprint)
		case "kit":
			jstr(&b, p.Kit)
		case "root":
			jstr(&b, p.Root)
		case "threshold":
			b.WriteString(strconv.FormatInt(p.Threshold, 10))
		case "admin":
			b.WriteString(strconv.FormatBool(p.Admin))
		case "custodian":
			b.WriteString(strconv.FormatBool(p.Custodian))
		case "admins":
			b.WriteByte('[')
			for j, a := range p.Admins {
				if j > 0 {
					b.WriteByte(',')
				}
				jstr(&b, a)
			}
			b.WriteByte(']')
		case "gen":
			b.WriteString(strconv.FormatInt(p.Gen, 10))
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// jstr writes s as a JSON string; only printable ASCII without '"' and '\' is written as is, anything else is
// refused by the checks before Canonical's output is compared, so a placeholder suffices.
func jstr(b *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			b.WriteString(`"\u0000"`) // never equal to a canonical payload: forces a mismatch
			return
		}
	}
	b.WriteByte('"')
	b.WriteString(s)
	b.WriteByte('"')
}

// firmOK: the log's firm: a canonical f_ id, or the placeholder only when the log is for it ("" checks only the form).
func firmOK(s, want string) bool {
	if want == Placeholder {
		return s == Placeholder
	}
	return IsID(s, "f") && (want == "" || s == want)
}

func (p *Payload) checkIdentity(firm string) error {
	switch {
	case !IsID(p.Identity, "i"):
		return errors.New("bad identity id")
	case !IsID(p.Member, "m"):
		return errors.New("bad member id")
	case !IsID(p.User, "u") && !(firm == Placeholder && legacyRe.MatchString(p.User)):
		return errors.New("bad user id")
	case !fpRe.MatchString(p.Fingerprint):
		return errors.New("bad fingerprint")
	case !hashRe.MatchString(p.EmailHash):
		return errors.New("bad email hash")
	}
	if _, err := ParseEd(p.Ed25519); err != nil {
		return err
	}
	_, err := ParseX(p.X25519)
	return err
}

// DecodePayload reads kind's payload strictly (exactly the kind's fields, canonical bytes) for a log of firm.
func DecodePayload(kind string, payload []byte, firm string) (*Payload, error) {
	if _, ok := Fields[kind]; !ok {
		return nil, errors.New("unknown entry kind")
	}
	var p Payload
	if err := json.Unmarshal(payload, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("bad payload: %w", err)
	}
	p.Kind = kind
	if err := p.check(firm); err != nil {
		return nil, err
	}
	c, err := p.Canonical()
	if err != nil || !bytes.Equal(c, payload) {
		return nil, errors.New("payload isn't canonical JSON of the kind's fields")
	}
	return &p, nil
}

func (p *Payload) check(firm string) error {
	switch {
	case !firmOK(p.Firm, firm):
		return errors.New("bad firm")
	case p.Seq < 1 || p.Seq > maxSafe:
		return errors.New("bad seq")
	case p.Seq == 1 && p.Prev != "" || p.Seq != 1 && !hashRe.MatchString(p.Prev):
		return errors.New("bad prev")
	case p.Time < 0 || p.Time > maxSafe:
		return errors.New("bad time")
	case (p.Kind == KindGenesis) != (p.Seq == 1):
		return errors.New("genesis must be entry 1, and only it")
	}
	switch p.Kind {
	case KindGenesis:
		if err := p.checkIdentity(firm); err != nil {
			return err
		}
		if _, err := ParseEd(p.Kit); err != nil {
			return err
		}
		if _, err := ParseX(p.Root); err != nil {
			return err
		}
		if p.Threshold != 1 {
			return errors.New("genesis threshold must be 1")
		}
	case KindAdd:
		return p.checkIdentity(firm)
	case KindRevoke:
		if !IsID(p.Identity, "i") {
			return errors.New("bad identity id")
		}
	case KindAdmins:
		if len(p.Admins) == 0 || len(p.Admins) > MaxAdmins {
			return errors.New("bad admins")
		}
		for i, a := range p.Admins {
			if !IsID(a, "i") {
				return errors.New("bad admin")
			}
			if i > 0 && !(p.Admins[i-1] < a) {
				return errors.New("admins must be sorted and distinct")
			}
		}
	case KindThresh:
		if p.Threshold < 1 || p.Threshold > MaxThreshold {
			return errors.New("bad threshold")
		}
	case KindRootRot:
		if p.Gen < 2 || p.Gen > maxSafe {
			return errors.New("bad root generation")
		}
		if _, err := ParseX(p.Root); err != nil {
			return err
		}
	}
	return nil
}

// ---- checked entries ------------------------------------------------------------------------------------------

// Checked is an entry whose shape, payload and signatures verified on their own (no log state read yet).
type Checked struct {
	Entry   Entry
	P       *Payload
	Hash    string
	Signers []string // distinct signer keys, in order
}

// Check verifies an entry on its own for a log of firm: kind, sizes, canonical payload, every signature valid
// and by a distinct key (log.ts verifiedSigners: one bad signature fails the entry).
func Check(e Entry, firm string) (*Checked, error) {
	if !IsKind(e.Kind) {
		return nil, errors.New("key log: unknown entry kind")
	}
	if len(e.Payload) == 0 || len(e.Payload) > MaxPayload || len(e.Sigs) == 0 || len(e.Sigs) > MaxSigs {
		return nil, errors.New("key log: bad entry size")
	}
	p, err := DecodePayload(e.Kind, e.Payload, firm)
	if err != nil {
		return nil, fmt.Errorf("key log: %w", err)
	}
	msg := Signed(e.Kind, e.Payload)
	var signers []string
	for _, s := range e.Sigs {
		k, err := ParseEd(s.Key)
		if err != nil {
			return nil, errors.New("key log: bad signature key")
		}
		if slices.Contains(signers, s.Key) {
			return nil, errors.New("key log: duplicate signer")
		}
		if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(k, msg, s.Sig) {
			return nil, errors.New("key log: bad signature")
		}
		signers = append(signers, s.Key)
	}
	return &Checked{Entry: e, P: p, Hash: e.Hash(), Signers: signers}, nil
}

// ---- the state the log describes ----------------------------------------------------------------------------

// Identity is one identity the log named.
type Identity struct {
	ID, Member, User, Ed25519, X25519, Fingerprint string
	Custodian                                      bool
	Added                                          int64
	Revoked                                        int64 // 0 while current
}

// State is what the log says at its head.
type State struct {
	Firm      string
	Seq       int64
	Head      string
	Genesis   string
	ids       map[string]*Identity
	admins    map[string]bool
	Threshold int64
	Kit       string
	Root      string
	RootGen   int64
}

func (s *State) clone() *State {
	c := *s
	c.ids = make(map[string]*Identity, len(s.ids))
	for k, v := range s.ids {
		vv := *v
		c.ids[k] = &vv
	}
	c.admins = make(map[string]bool, len(s.admins))
	for k := range s.admins {
		c.admins[k] = true
	}
	return &c
}

// Current says whether id is in the log and not revoked.
func (s *State) Current(id string) bool {
	i := s.ids[id]
	return i != nil && i.Revoked == 0
}

// Identity is id's entry, if any.
func (s *State) Identity(id string) (Identity, bool) {
	i := s.ids[id]
	if i == nil {
		return Identity{}, false
	}
	return *i, true
}

// Admins are the current key admins' identity ids, sorted.
func (s *State) Admins() []string {
	out := make([]string, 0, len(s.admins))
	for a := range s.admins {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// AdminKeys are the current key admins' Ed25519 keys, sorted.
func (s *State) AdminKeys() []string {
	var out []string
	for a := range s.admins {
		if i := s.ids[a]; i != nil && i.Revoked == 0 {
			out = append(out, i.Ed25519)
		}
	}
	slices.Sort(out)
	return out
}

// Effective is the number of admin signatures an admin-signed entry or document needs: the threshold, never
// more than there are admins.
func (s *State) Effective() int64 { return max(1, min(s.Threshold, int64(len(s.admins)))) }

// adminSigners splits signer keys into current admins (by identity) and the rest.
func (s *State) adminSigners(keys []string) (admins, others []string) {
	byKey := map[string]string{}
	for a := range s.admins {
		if i := s.ids[a]; i != nil && i.Revoked == 0 {
			byKey[i.Ed25519] = a
		}
	}
	for _, k := range keys {
		if a, ok := byKey[k]; ok {
			admins = append(admins, a)
		} else {
			others = append(others, k)
		}
	}
	return
}

func (s *State) requireAdmins(keys []string, seq int64) error {
	admins, others := s.adminSigners(keys)
	if len(others) > 0 {
		return fmt.Errorf("key log entry %d has a signature by a key that isn't a current key admin", seq)
	}
	if int64(len(admins)) < s.Effective() {
		return fmt.Errorf("key log entry %d needs %d key admin signatures", seq, s.Effective())
	}
	return nil
}

func (s *State) addIdentity(p *Payload, seq int64, custodian bool) error {
	if _, ok := s.ids[p.Identity]; ok {
		return errors.New("identity already in the key log")
	}
	for _, i := range s.ids {
		if i.Ed25519 == p.Ed25519 || i.X25519 == p.X25519 {
			return errors.New("public key already in the key log")
		}
		if i.Revoked == 0 && (i.Member == p.Member || i.User == p.User) {
			return errors.New("the member already has a current identity (revoke it first)")
		}
		if i.Member == p.Member && i.User != p.User {
			return errors.New("member is bound to another account")
		}
	}
	if p.Ed25519 == s.Kit {
		return errors.New("public key already in the key log")
	}
	fp, err := Fingerprint(p.Ed25519, p.X25519)
	if err != nil || fp != p.Fingerprint {
		return errors.New("fingerprint doesn't match the public keys")
	}
	s.ids[p.Identity] = &Identity{ID: p.Identity, Member: p.Member, User: p.User, Ed25519: p.Ed25519, X25519: p.X25519,
		Fingerprint: p.Fingerprint, Custodian: custodian, Added: seq}
	return nil
}

// apply applies a checked entry to s (nil before genesis) and returns the new state; s is never changed.
func apply(s *State, c *Checked) (*State, error) {
	p, keys := c.P, c.Signers
	if p.Kind == KindGenesis {
		if s != nil {
			return nil, errors.New("second genesis")
		}
		if p.Kit == p.Ed25519 {
			return nil, errors.New("the recovery kit must be its own key")
		}
		if len(keys) != 2 || !slices.Contains(keys, p.Ed25519) || !slices.Contains(keys, p.Kit) {
			return nil, errors.New("genesis must be signed by the first owner and the recovery kit")
		}
		n := &State{Firm: p.Firm, Genesis: c.Hash, ids: map[string]*Identity{}, admins: map[string]bool{p.Identity: true},
			Threshold: 1, Kit: p.Kit, Root: p.Root, RootGen: 1}
		if err := n.addIdentity(p, 1, true); err != nil {
			return nil, err
		}
		n.Seq, n.Head = 1, c.Hash
		return n, nil
	}
	if s == nil {
		return nil, errors.New("key log doesn't start with genesis")
	}
	if p.Firm != s.Firm {
		return nil, errors.New("entry is for another firm")
	}
	if p.Seq != s.Seq+1 {
		return nil, fmt.Errorf("key log entry out of order (seq %d after %d)", p.Seq, s.Seq)
	}
	if p.Prev != s.Head {
		return nil, fmt.Errorf("key log entry %d doesn't follow the one before", p.Seq)
	}
	if slices.Contains(keys, s.Kit) && p.Kind != KindAdmins {
		return nil, errors.New("the recovery kit can only change key admins")
	}
	n := s.clone()
	switch p.Kind {
	case KindAdd:
		if err := n.requireAdmins(keys, p.Seq); err != nil {
			return nil, err
		}
		if err := n.addIdentity(p, p.Seq, p.Custodian); err != nil {
			return nil, err
		}
		if p.Admin {
			if len(n.admins) >= MaxAdmins {
				return nil, errors.New("too many key admins")
			}
			n.admins[p.Identity] = true
		}
	case KindRevoke:
		i := n.ids[p.Identity]
		if i == nil || i.Revoked != 0 {
			return nil, errors.New("revoke of an identity that isn't current")
		}
		if !(len(keys) == 1 && keys[0] == i.Ed25519) {
			if err := n.requireAdmins(keys, p.Seq); err != nil {
				return nil, err
			}
		}
		i.Revoked = p.Seq
		delete(n.admins, p.Identity)
	case KindAdmins:
		if slices.Contains(keys, n.Kit) {
			rest := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return k == n.Kit })
			if _, others := n.adminSigners(rest); len(others) > 0 {
				return nil, fmt.Errorf("key log entry %d has a signature by a key that isn't a current key admin", p.Seq)
			}
		} else if err := n.requireAdmins(keys, p.Seq); err != nil {
			return nil, err
		}
		for _, a := range p.Admins {
			if !n.Current(a) {
				return nil, errors.New("a key admin must be a current identity")
			}
		}
		n.admins = map[string]bool{}
		for _, a := range p.Admins {
			n.admins[a] = true
		}
	case KindThresh:
		if err := n.requireAdmins(keys, p.Seq); err != nil {
			return nil, err
		}
		if p.Threshold > int64(len(n.admins)) {
			return nil, errors.New("threshold above the number of key admins")
		}
		n.Threshold = p.Threshold
	case KindRootRot:
		if err := n.requireAdmins(keys, p.Seq); err != nil {
			return nil, err
		}
		if p.Gen != n.RootGen+1 {
			return nil, errors.New("root rotation skips a generation")
		}
		if p.Root == n.Root {
			return nil, errors.New("root rotation reuses the key")
		}
		n.Root, n.RootGen = p.Root, p.Gen
	}
	n.Seq, n.Head = p.Seq, c.Hash
	return n, nil
}

// Replay verifies a whole log from genesis for firm and returns its state (tests, tools, the browser's twin).
func Replay(firm string, entries []Entry) (*State, error) {
	var s *State
	for i, e := range entries {
		c, err := Check(e, firm)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		if c.P.Seq != int64(i+1) {
			return nil, fmt.Errorf("key log entry out of order (seq %d at %d)", c.P.Seq, i+1)
		}
		if s, err = apply(s, c); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
	}
	if s == nil {
		return nil, errors.New("empty key log")
	}
	return s, nil
}
