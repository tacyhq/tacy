// Package runauth is where and who for a run request (keys v2 slice 6, docs/26-keys-v2.md section 6).
//
// Where: the request names its space ("s_…") and the space's seal public key ("x25519:<base64>"), and proves it
// holds the seal private key with an HMAC keyed by one X25519 agreement between the seal key and this boot's attested
// EHBP key (the pattern activity.RecordProof used for record_to):
//
//	k     = HKDF-SHA256(X25519(seal, vm), salt empty, info "tacy/v2/space-proof", 32 bytes)
//	proof = HMAC-SHA256(k, "tacy/v2/space-proof" ‖ 0 ‖ space ‖ 0 ‖ seal ‖ 0 ‖ hex(vm public key))
//
// The seal private key is sealed under the space key, so only the space's holders can make the proof. The run's
// activity records are sealed to the seal key: a chain is a space's history, readable by its holders.
//
// Who: the identity asking ("i_…") and its Ed25519 key sign the request together with this boot's VM key, a fresh
// nonce and the time:
//
//	digest = SHA-256(SHA-256(item 1) ‖ SHA-256(item 2) ‖ …), each item a UTF-8 string, in this order:
//	         "tacy/v2/run-request", hex(vm public key), nonce, signed_at (decimal), space, space_seal, identity,
//	         identity_key, model, reasoning_effort, max_steps (decimal, 0 if absent), tools ("*" when absent, else the
//	         names joined by ","), cache_secret, run_secret, permissions (sorted "kind=setting" joined by ","),
//	         fallback_models (in order, joined by ","), auto_fallback ("true" or "false"), the number of messages
//	         (decimal), then each message's role and content
//	sig    = Ed25519(identity key, "tacy/v2/run-request" ‖ 0 ‖ digest)
//
// A plain chat's search (POST /search) and an answer's pictures (POST /pictures) carry the same where and who (v0.10.0),
// each with its own label, so no signature passes for another kind of request; the first eight items are a run's:
//
//	search:   "tacy/v2/search-request", hex(vm public key), nonce, signed_at, space, space_seal, identity,
//	          identity_key, query, count (decimal, 0 if absent), question, decision, edited ("true" or "false"),
//	          cache_secret
//	pictures: "tacy/v2/pictures-request", hex(vm public key), nonce, signed_at, space, space_seal, identity,
//	          identity_key, ticket
//	sig     = Ed25519(identity key, label ‖ 0 ‖ digest)
//
// The request travels EHBP-encrypted to the VM key, so the relay can't read or change it; the nonce and the time
// stop the relay from replaying a whole request to the same boot (a second run, a second record), and the VM key
// stops a replay to another boot. On a firm's VM the identity must be current in the firm key log with that key; on
// the shared chat VM personal identities are self-certified (nobody wraps keys to them), so the signature shows
// possession and binds the nonce, nothing more.
package runauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// Labels.
const (
	ProofLabel    = "tacy/v2/space-proof"
	RequestLabel  = "tacy/v2/run-request"
	SearchLabel   = "tacy/v2/search-request"
	PicturesLabel = "tacy/v2/pictures-request"
)

// MaxSkew is how far signed_at may be from the VM's clock, either way.
const MaxSkew = 5 * time.Minute

var (
	idTail  = regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]\z`)
	nonceRe = regexp.MustCompile(`^[0-9a-f]{32}\z`)
)

// IsID: a canonical id with this one-letter prefix ("s", "i"): "<p>_" plus 26 base32 characters, the last one's two
// low bits zero (the chat's ids.ts isId; keylog.IsID).
func IsID(s, prefix string) bool {
	return len(s) == 28 && strings.HasPrefix(s, prefix+"_") && idTail.MatchString(s[2:])
}

// strictKey decodes "<prefix>:<base64 of 32 bytes>" in its one canonical spelling.
func strictKey(prefix, s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, prefix+":")
	if !ok {
		return nil, errors.New("runauth: bad " + prefix + " key")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != b64 {
		return nil, errors.New("runauth: bad " + prefix + " key")
	}
	return b, nil
}

// ParseSeal parses a seal public key ("x25519:<base64>"; the all-zero key refused).
func ParseSeal(s string) (*ecdh.PublicKey, error) {
	b, err := strictKey("x25519", s)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(b, make([]byte, 32)) {
		return nil, errors.New("runauth: bad x25519 key")
	}
	return ecdh.X25519().NewPublicKey(b)
}

// SealString is an X25519 public key as requests name it.
func SealString(pub *ecdh.PublicKey) string {
	return "x25519:" + base64.StdEncoding.EncodeToString(pub.Bytes())
}

// EdString is an Ed25519 public key as requests name it.
func EdString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// SpaceProof is the request's side: priv is the seal private key, peer the VM's attested key (vmPub its bytes).
func SpaceProof(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, space, seal string, vmPub []byte) ([]byte, error) {
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	k, err := hkdf.Key(sha256.New, shared, nil, ProofLabel, 32)
	clear(shared)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(ProofLabel + "\x00" + space + "\x00" + seal + "\x00" + hex.EncodeToString(vmPub)))
	return m.Sum(nil), nil
}

// ErrSpaceProof: the request named a space and seal key it didn't prove it holds.
var ErrSpaceProof = errors.New("runauth: space_proof doesn't prove the space's seal key")

// CheckSpaceProof is the VM's side: vm is its EHBP private key.
func CheckSpaceProof(vm *ecdh.PrivateKey, space, seal string, proof []byte) error {
	pub, err := ParseSeal(seal)
	if err != nil {
		return err
	}
	want, err := SpaceProof(vm, pub, space, seal, vm.PublicKey().Bytes())
	if err != nil || len(proof) != len(want) || !hmac.Equal(want, proof) {
		return ErrSpaceProof
	}
	return nil
}

// fields is a request's where and who, whatever its kind.
type fields struct {
	Space, SpaceSeal             string
	SpaceProof                   []byte
	Identity, IdentityKey, Nonce string
	SignedAt                     int64
	IdentitySig                  []byte
}

func runFields(r *proto.RunRequest) fields {
	return fields{r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey, r.Nonce, r.SignedAt, r.IdentitySig}
}

func searchFields(r *proto.SearchRequest) fields {
	return fields{r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey, r.Nonce, r.SignedAt, r.IdentitySig}
}

func picturesFields(r *proto.PicturesRequest) fields {
	return fields{r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey, r.Nonce, r.SignedAt, r.IdentitySig}
}

// digest hashes label, the VM key, f's where and who, then the request's own items (see the package doc).
func digest(label string, vmPub []byte, f fields, rest ...string) [32]byte {
	items := append([]string{label, hex.EncodeToString(vmPub), f.Nonce, strconv.FormatInt(f.SignedAt, 10), f.Space, f.SpaceSeal,
		f.Identity, f.IdentityKey}, rest...)
	h := sha256.New()
	for _, it := range items {
		s := sha256.Sum256([]byte(it))
		h.Write(s[:])
	}
	var d [32]byte
	h.Sum(d[:0])
	return d
}

// Digest is a run request's digest for vmPub (see the package doc). It reads the request as the VM decoded it.
func Digest(r *proto.RunRequest, vmPub []byte) [32]byte {
	tools := "*"
	if r.Tools != nil {
		tools = strings.Join(r.Tools, ",")
	}
	perms := make([]string, 0, len(r.Permissions))
	for k, v := range r.Permissions {
		perms = append(perms, k+"="+v)
	}
	slices.Sort(perms)
	rest := []string{r.Model, r.ReasoningEffort, strconv.Itoa(r.MaxSteps), tools, r.CacheSecret, r.RunSecret,
		strings.Join(perms, ","), strings.Join(r.FallbackModels, ","), strconv.FormatBool(r.AutoFallback), strconv.Itoa(len(r.Messages))}
	for _, m := range r.Messages {
		rest = append(rest, m.Role, m.Content)
	}
	return digest(RequestLabel, vmPub, runFields(r), rest...)
}

// SearchDigest is a search request's digest for vmPub (see the package doc), as the VM decoded it.
func SearchDigest(r *proto.SearchRequest, vmPub []byte) [32]byte {
	return digest(SearchLabel, vmPub, searchFields(r), r.Query, strconv.Itoa(r.Count), r.Question, r.Decision,
		strconv.FormatBool(r.Edited), r.CacheSecret)
}

// PicturesDigest is a pictures request's digest for vmPub (see the package doc).
func PicturesDigest(r *proto.PicturesRequest, vmPub []byte) [32]byte {
	return digest(PicturesLabel, vmPub, picturesFields(r), r.Ticket)
}

func signed(label string, d [32]byte) []byte {
	return append([]byte(label+"\x00"), d[:]...)
}

// Sign is the request's side: the identity's signature over r for the VM key vmPub (r's nonce, time, space and
// identity fields already set).
func Sign(priv ed25519.PrivateKey, r *proto.RunRequest, vmPub []byte) []byte {
	return ed25519.Sign(priv, signed(RequestLabel, Digest(r, vmPub)))
}

// SignSearch is Sign for a search request.
func SignSearch(priv ed25519.PrivateKey, r *proto.SearchRequest, vmPub []byte) []byte {
	return ed25519.Sign(priv, signed(SearchLabel, SearchDigest(r, vmPub)))
}

// SignPictures is Sign for a pictures request.
func SignPictures(priv ed25519.PrivateKey, r *proto.PicturesRequest, vmPub []byte) []byte {
	return ed25519.Sign(priv, signed(PicturesLabel, PicturesDigest(r, vmPub)))
}

// Who is what the VM verified about a request.
type Who struct {
	Space    string // "s_…"
	Seal     string // the space's seal public key: the run's activity records are sealed to it
	Identity string // "i_…"
	Key      string // the identity's Ed25519 key
}

// Check verifies a run request's where and who against this boot's EHBP key vm at now: the ids' shapes, the space
// proof, the time, the nonce's shape and the identity's signature. It doesn't claim the nonce (Nonces) and doesn't
// know whether the identity or seal key are the ones a firm's key log and space policy name (the caller checks that).
func Check(vm *ecdh.PrivateKey, r *proto.RunRequest, now time.Time) (Who, error) {
	return check(vm, runFields(r), RequestLabel, Digest(r, vm.PublicKey().Bytes()), now)
}

// CheckSearch is Check for a search request (its own label and digest).
func CheckSearch(vm *ecdh.PrivateKey, r *proto.SearchRequest, now time.Time) (Who, error) {
	return check(vm, searchFields(r), SearchLabel, SearchDigest(r, vm.PublicKey().Bytes()), now)
}

// CheckPictures is Check for a pictures request (its own label and digest).
func CheckPictures(vm *ecdh.PrivateKey, r *proto.PicturesRequest, now time.Time) (Who, error) {
	return check(vm, picturesFields(r), PicturesLabel, PicturesDigest(r, vm.PublicKey().Bytes()), now)
}

func check(vm *ecdh.PrivateKey, f fields, label string, d [32]byte, now time.Time) (Who, error) {
	switch {
	case f.Space == "":
		return Who{}, errors.New("the request names no space")
	case !IsID(f.Space, "s"):
		return Who{}, errors.New("space must be an s_ id")
	case !IsID(f.Identity, "i"):
		return Who{}, errors.New("identity must be an i_ id")
	case !nonceRe.MatchString(f.Nonce):
		return Who{}, errors.New("nonce must be 32 lowercase hex characters")
	}
	if err := CheckSpaceProof(vm, f.Space, f.SpaceSeal, f.SpaceProof); err != nil {
		return Who{}, err
	}
	if d := now.Sub(time.Unix(f.SignedAt, 0)); d > MaxSkew || d < -MaxSkew {
		return Who{}, errors.New("signed_at is too far from the VM's clock")
	}
	key, err := strictKey("ed25519", f.IdentityKey)
	if err != nil {
		return Who{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(key), signed(label, d), f.IdentitySig) {
		return Who{}, errors.New("identity_sig doesn't verify")
	}
	return Who{Space: f.Space, Seal: f.SpaceSeal, Identity: f.Identity, Key: f.IdentityKey}, nil
}

// Nonces remembers the nonces this boot took, for as long as their requests' signed_at can still pass (MaxSkew
// either way), so each request runs at most once. Safe for concurrent use.
type Nonces struct {
	Now func() time.Time
	Max int // the most remembered at once (0: 1<<18); past it, new requests are refused until old nonces expire

	mu     sync.Mutex
	seen   map[string]time.Time // nonce -> when it can be forgotten
	claims int
}

// ErrReplay: the nonce was used already.
var ErrReplay = errors.New("this request was sent before (a replayed nonce)")

// ErrBusy: too many nonces remembered right now.
var ErrBusy = errors.New("too many requests right now; try again in a minute")

// Claim takes nonce for a request signed at signedAt, or refuses a nonce taken before.
func (n *Nonces) Claim(nonce string, signedAt int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	if n.Now != nil {
		now = n.Now()
	}
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	if _, ok := n.seen[nonce]; ok {
		return ErrReplay
	}
	max := n.Max
	if max <= 0 {
		max = 1 << 18
	}
	if n.claims++; len(n.seen) >= max || n.claims%1024 == 0 {
		for k, until := range n.seen {
			if now.After(until) {
				delete(n.seen, k)
			}
		}
	}
	if len(n.seen) >= max {
		return ErrBusy
	}
	// Forgotten only once signed_at can't pass any more: then the request is refused for its time anyway.
	n.seen[nonce] = time.Unix(signedAt, 0).Add(MaxSkew + time.Second)
	return nil
}

// ---- the request's side (cmd/client, cmd/e2e, agentclient and tests; the chat's browser has its own) -------------

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// IDFrom is the canonical id with prefix for 16 bytes (the chat's ids.ts format).
func IDFrom(prefix string, b [16]byte) string { return prefix + "_" + b32.EncodeToString(b[:]) }

// NewID is a random canonical id with prefix.
func NewID(prefix string) string {
	var b [16]byte
	rand.Read(b[:])
	return IDFrom(prefix, b)
}

// SpaceFor is a space id derived from a seal key (tools that keep only a key file, so their chain stays the same).
func SpaceFor(seal *ecdh.PublicKey) string {
	h := sha256.Sum256(append([]byte("tacy/v2/tool-space\x00"), seal.Bytes()...))
	return IDFrom("s", [16]byte(h[:16]))
}

// Asker is a request's where and who: a space with its seal private key, and an identity with its Ed25519 key.
type Asker struct {
	Space    string
	Seal     *ecdh.PrivateKey
	Identity string
	Key      ed25519.PrivateKey
	Now      func() time.Time // nil: time.Now
}

// NewAsker is a fresh personal space and identity (random keys and ids).
func NewAsker() (*Asker, error) {
	seal, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Asker{Space: NewID("s"), Seal: seal, Identity: NewID("i"), Key: key}, nil
}

// AskerFor is an Asker in seal's derived space (SpaceFor) with a fresh identity.
func AskerFor(seal *ecdh.PrivateKey) (*Asker, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Asker{Space: SpaceFor(seal.PublicKey()), Seal: seal, Identity: NewID("i"), Key: key}, nil
}

// SealString is the seal public key as requests name it.
func (a *Asker) SealString() string { return SealString(a.Seal.PublicKey()) }

// where is a fresh where and who for the VM key vmPub: space, seal key and proof, identity, a nonce and the time (no
// signature yet).
func (a *Asker) where(vmPub []byte) (fields, error) {
	peer, err := ecdh.X25519().NewPublicKey(vmPub)
	if err != nil {
		return fields{}, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	f := fields{Space: a.Space, SpaceSeal: a.SealString(), Identity: a.Identity, IdentityKey: EdString(a.Key.Public().(ed25519.PublicKey)),
		Nonce: hex.EncodeToString(nonce[:]), SignedAt: now.Unix()}
	if f.SpaceProof, err = SpaceProof(a.Seal, peer, f.Space, f.SpaceSeal, vmPub); err != nil {
		return fields{}, err
	}
	return f, nil
}

// onWire is v as the VM will decode it (a JSON round trip: an empty tool list, for one, travels as none).
func onWire[T any](v *T) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var wire T
	if err := json.Unmarshal(b, &wire); err != nil {
		return nil, err
	}
	return &wire, nil
}

// Authorize fills r's where and who for the VM key vmPub (the attested EHBP key): space, seal key and proof, identity,
// a fresh nonce, the time and the signature. The digest is taken over r as the VM will decode it.
func (a *Asker) Authorize(r *proto.RunRequest, vmPub []byte) error {
	f, err := a.where(vmPub)
	if err != nil {
		return err
	}
	r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey = f.Space, f.SpaceSeal, f.SpaceProof, f.Identity, f.IdentityKey
	r.Nonce, r.SignedAt, r.IdentitySig = f.Nonce, f.SignedAt, nil
	wire, err := onWire(r)
	if err != nil {
		return err
	}
	r.IdentitySig = Sign(a.Key, wire, vmPub)
	return nil
}

// AuthorizeSearch is Authorize for a search request.
func (a *Asker) AuthorizeSearch(r *proto.SearchRequest, vmPub []byte) error {
	f, err := a.where(vmPub)
	if err != nil {
		return err
	}
	r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey = f.Space, f.SpaceSeal, f.SpaceProof, f.Identity, f.IdentityKey
	r.Nonce, r.SignedAt, r.IdentitySig = f.Nonce, f.SignedAt, nil
	wire, err := onWire(r)
	if err != nil {
		return err
	}
	r.IdentitySig = SignSearch(a.Key, wire, vmPub)
	return nil
}

// AuthorizePictures is Authorize for a pictures request.
func (a *Asker) AuthorizePictures(r *proto.PicturesRequest, vmPub []byte) error {
	f, err := a.where(vmPub)
	if err != nil {
		return err
	}
	r.Space, r.SpaceSeal, r.SpaceProof, r.Identity, r.IdentityKey = f.Space, f.SpaceSeal, f.SpaceProof, f.Identity, f.IdentityKey
	r.Nonce, r.SignedAt, r.IdentitySig = f.Nonce, f.SignedAt, nil
	wire, err := onWire(r)
	if err != nil {
		return err
	}
	r.IdentitySig = SignPictures(a.Key, wire, vmPub)
	return nil
}
