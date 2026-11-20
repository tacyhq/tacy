// Package client is the agent VM's side of the Tacy key service (package kms): it asks kmsd for its keys with a
// fresh attestation and accepts a reply only if the KMS id it pins signed it. It reaches kmsd through a Transport,
// in the VM a typed gateway/v0 op through gatewayd (the only process with a network); HTTP is for tools and tests.
// Standard library plus kms and proto only.
package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/proto"
)

// KeySource is what the VM's processes use to get their keys. Client implements it; Static is a stub for tests
// and for wiring before the KMS is reachable.
type KeySource interface {
	// Release asks for keys for purposes (of kms.Purposes, the caller's own only) and the app's secrets.
	Release(ctx context.Context, purposes []string) (*Keys, error)
}

// Keys is what a release gave: per-purpose 32-byte keys, the app's secrets and the instance lease.
type Keys struct {
	App     string
	Firm    string
	Release string
	Epoch   uint32
	Keys    map[string][]byte
	Secrets map[string]string
	Lease   kms.Lease
	LogSeq  uint64 // the audit entry that recorded the release
	// LeaseSecret proves the lease (renewals and generation commits). Keep it with the keys.
	LeaseSecret []byte
	// Certs are the KMS id's StoreCerts for the released purposes of kms.StorePurposes (checked: signed by the
	// pinned id, for this app, firm and epoch, naming the store-auth key of the released purpose key).
	Certs map[string]kms.StoreCert
}

// Key returns the key for purpose, or an error if the release didn't include it.
func (k *Keys) Key(purpose string) ([]byte, error) {
	b, ok := k.Keys[purpose]
	if !ok || len(b) != 32 {
		return nil, fmt.Errorf("kms: no %s key in this release", purpose)
	}
	return b, nil
}

// Transport carries one request to kmsd: method and path as in package kms's wire format (path with its query),
// body the JSON request (nil for GET). It returns the response body; a refusal is a *RefusedError.
type Transport interface {
	Do(ctx context.Context, method, path string, body []byte) ([]byte, error)
}

// RefusedError is a refusal from kmsd: its HTTP status and reason.
type RefusedError struct {
	Status int
	Reason string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("kms refused (%d): %s", e.Status, e.Reason) }

// Evidence makes this TD's attestation for reportData: dstack's GetQuote and Info responses.
type Evidence func(ctx context.Context, reportData []byte) (quote, info json.RawMessage, err error)

// Config is a client's setup.
type Config struct {
	KMSID     ed25519.PublicKey // the pinned KMS id (the compose's -kms-key): only replies it signed are accepted
	Transport Transport
	Evidence  Evidence
	Platform  string // "dstack"; "local" only against a development kmsd
	// Release is this VM's release version (vX.Y.Z) and ReleaseBundle its Sigstore bundle (optional).
	Release       string
	ReleaseBundle json.RawMessage
	// Holder names this process's lease ("agentd", "vaultd"; "" = "main").
	Holder string
	// Key is this process's boot key: every release is sealed to it and the lease is bound to it, so only this
	// process (not a clone with the same instance id) renews or re-takes the lease. nil: one made by New.
	Key *ecdh.PrivateKey
	Now func() time.Time // nil = time.Now
}

// Client asks kmsd for keys.
type Client struct{ cfg Config }

// ErrBadSignature: the reply isn't signed by the pinned KMS id. Nothing in it was opened or used.
var ErrBadSignature = errors.New("kms: reply isn't signed by the pinned KMS id")

// New checks cfg.
func New(cfg Config) (*Client, error) {
	if len(cfg.KMSID) != ed25519.PublicKeySize {
		return nil, errors.New("kms client: no pinned KMS id")
	}
	if cfg.Transport == nil || cfg.Evidence == nil {
		return nil, errors.New("kms client: transport and evidence are required")
	}
	if cfg.Platform == "" {
		cfg.Platform = "dstack"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Holder == "" {
		cfg.Holder = "main"
	}
	if !kms.ValidHolder(cfg.Holder) {
		return nil, errors.New("kms client: bad holder name")
	}
	if cfg.Key == nil {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.Key = k
	}
	return &Client{cfg: cfg}, nil
}

// NewNonce is 32 random bytes, hex: a register read's or a commit's nonce.
func NewNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Challenge gets a fresh nonce.
func Challenge(ctx context.Context, t Transport) ([]byte, error) {
	b, err := t.Do(ctx, http.MethodGet, "/v1/challenge", nil)
	if err != nil {
		return nil, err
	}
	var ch kms.Challenge
	if err := kms.Strict(b, &ch); err != nil {
		return nil, fmt.Errorf("kms: challenge: %w", err)
	}
	n, err := hex.DecodeString(ch.Nonce)
	if err != nil || len(n) != 32 {
		return nil, errors.New("kms: challenge isn't 32 bytes of hex")
	}
	return n, nil
}

// Attest makes an attestation for nonce bound to a fresh X25519 key and returns its exact JSON and the key.
func Attest(ctx context.Context, ev Evidence, platform string, nonce []byte) (json.RawMessage, *ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	b, err := AttestWith(ctx, ev, platform, nonce, priv)
	return b, priv, err
}

// AttestWith makes an attestation for nonce bound to priv's public key and returns its exact JSON.
func AttestWith(ctx context.Context, ev Evidence, platform string, nonce []byte, priv *ecdh.PrivateKey) (json.RawMessage, error) {
	pub := priv.PublicKey().Bytes()
	quote, info, err := ev(ctx, proto.ReportData(nonce, pub))
	if err != nil {
		return nil, fmt.Errorf("kms: attestation: %w", err)
	}
	att := proto.Attestation{Version: proto.Version, Platform: platform, Nonce: hex.EncodeToString(nonce),
		HPKEPublicKey: hex.EncodeToString(pub), HPKESuite: proto.HPKESuite, Quote: quote, Info: info,
		Booted: time.Now().UTC().Format(time.RFC3339)}
	return json.Marshal(att)
}

// Release implements KeySource.
func (c *Client) Release(ctx context.Context, purposes []string) (*Keys, error) {
	if len(purposes) == 0 {
		return nil, errors.New("kms: no purposes")
	}
	nonce, err := Challenge(ctx, c.cfg.Transport)
	if err != nil {
		return nil, err
	}
	att, err := AttestWith(ctx, c.cfg.Evidence, c.cfg.Platform, nonce, c.cfg.Key)
	if err != nil {
		return nil, err
	}
	req, _ := json.Marshal(kms.ReleaseRequest{Nonce: hex.EncodeToString(nonce), Attestation: att, Release: c.cfg.Release,
		ReleaseBundle: c.cfg.ReleaseBundle, Purposes: purposes, Holder: c.cfg.Holder})
	b, err := c.cfg.Transport.Do(ctx, http.MethodPost, "/v1/release", req)
	if err != nil {
		return nil, err
	}
	k, err := OpenRelease(b, c.cfg.KMSID, nonce, att, c.cfg.Key, purposes)
	if err != nil {
		return nil, err
	}
	if k.Lease.Holder != c.cfg.Holder || k.Lease.Key != hex.EncodeToString(c.cfg.Key.PublicKey().Bytes()) {
		return nil, errors.New("kms: the lease isn't this process's (holder or boot key)")
	}
	return k, nil
}

// OpenRelease checks a release reply's signature under the pinned KMS id (before anything else), then opens it
// with priv and checks it holds exactly the purposes asked for.
func OpenRelease(body []byte, kmsID ed25519.PublicKey, nonce []byte, att json.RawMessage, priv *ecdh.PrivateKey, purposes []string) (*Keys, error) {
	var r kms.ReleaseReply
	if err := kms.Strict(body, &r); err != nil {
		return nil, fmt.Errorf("kms: release reply: %w", err)
	}
	ah := sha256.Sum256(att)
	if len(r.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kmsID, kms.ReleaseSigMessage(nonce, ah[:], r.Sealed.Hash(), r.Lease, r.LogSeq), r.Sig) {
		return nil, ErrBadSignature
	}
	pt, err := kms.Open(priv, kms.LabelRelease, nonce, r.Sealed)
	if err != nil {
		return nil, errors.New("kms: release reply doesn't open with this attestation's key")
	}
	defer clear(pt)
	var p kms.ReleasePayload
	if err := kms.Strict(pt, &p); err != nil {
		return nil, fmt.Errorf("kms: release payload: %w", err)
	}
	if p.Lease != r.Lease {
		return nil, errors.New("kms: sealed lease differs from the signed one")
	}
	if len(p.Keys) != len(purposes) {
		return nil, errors.New("kms: release holds other purposes than asked")
	}
	for _, pu := range purposes {
		if len(p.Keys[pu]) != 32 {
			return nil, fmt.Errorf("kms: release has no %s key", pu)
		}
	}
	for pu, c := range p.Certs {
		if err := CheckStoreCert(c, kmsID); err != nil {
			return nil, err
		}
		k, ok := p.Keys[pu]
		if !ok || c.Purpose != pu || c.App != p.App || c.Firm != p.Firm || c.Epoch != p.Epoch {
			return nil, fmt.Errorf("kms: the %s store certificate doesn't match the release", pu)
		}
		sk, err := kms.StoreAuthKey(k)
		if err != nil || c.Key != kms.IDString(sk.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf("kms: the %s store certificate names another key", pu)
		}
		clear(sk)
	}
	for _, pu := range purposes {
		if _, ok := p.Certs[pu]; slices.Contains(kms.StorePurposes, pu) && !ok {
			return nil, fmt.Errorf("kms: release has no store certificate for %s", pu)
		}
	}
	return &Keys{App: p.App, Firm: p.Firm, Release: p.Release, Epoch: p.Epoch, Keys: p.Keys, Secrets: p.Secrets,
		Lease: p.Lease, LogSeq: r.LogSeq, LeaseSecret: p.LeaseSecret, Certs: p.Certs}, nil
}

// CheckStoreCert checks a StoreCert's purpose and its signature under the KMS id.
func CheckStoreCert(c kms.StoreCert, kmsID ed25519.PublicKey) error {
	if !slices.Contains(kms.StorePurposes, c.Purpose) || len(c.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kmsID, kms.StoreCertMessage(c), c.Sig) {
		return errors.New("kms: a store certificate isn't signed by the pinned KMS id")
	}
	return nil
}

// Renew extends k's lease and returns the new one (signed by the KMS id; checked).
func (c *Client) Renew(ctx context.Context, k *Keys) (kms.Lease, error) {
	at := c.cfg.Now().Unix()
	req, _ := json.Marshal(kms.LeaseRenew{App: k.App, Holder: k.Lease.Holder, Lease: k.Lease.ID, At: at,
		MAC: kms.RenewMAC(k.LeaseSecret, k.App, k.Lease.Holder, k.Lease.ID, at)})
	b, err := c.cfg.Transport.Do(ctx, http.MethodPost, "/v1/lease/renew", req)
	if err != nil {
		return kms.Lease{}, err
	}
	l, err := c.checkLease(b)
	if err != nil {
		return kms.Lease{}, err
	}
	if l.ID != k.Lease.ID || l.Instance != k.Lease.Instance || l.Holder != k.Lease.Holder || l.Key != k.Lease.Key || l.Expires < k.Lease.Expires {
		return kms.Lease{}, errors.New("kms: renewal answered for another lease, or an older one")
	}
	k.Lease = l
	return l, nil
}

// Drop frees k's lease (a clean stop), so the next boot takes it at once.
func (c *Client) Drop(ctx context.Context, k *Keys) error {
	at := c.cfg.Now().Unix()
	req, _ := json.Marshal(kms.LeaseRenew{App: k.App, Holder: k.Lease.Holder, Lease: k.Lease.ID, At: at,
		MAC: kms.DropMAC(k.LeaseSecret, k.App, k.Lease.Holder, k.Lease.ID, at)})
	b, err := c.cfg.Transport.Do(ctx, http.MethodPost, "/v1/lease/drop", req)
	if err != nil {
		return err
	}
	_, err = c.checkLease(b)
	return err
}

func (c *Client) checkLease(b []byte) (kms.Lease, error) {
	var sl kms.SignedLease
	if err := kms.Strict(b, &sl); err != nil {
		return kms.Lease{}, err
	}
	if !ed25519.Verify(c.cfg.KMSID, kms.LeaseSigMessage(sl.Lease), sl.Sig) {
		return kms.Lease{}, ErrBadSignature
	}
	return sl.Lease, nil
}

// Reserve reserves generation gen of the sealed blob name (sha256 hash, hex) under k's lease, before the blob is
// stored. The answer is signed by the KMS id over a fresh nonce (checked).
func (c *Client) Reserve(ctx context.Context, k *Keys, name string, gen uint64, hash string) (kms.SignedGen, error) {
	return c.commit(ctx, k, name, gen, hash, false)
}

// MarkStored tells the register the reserved generation gen (hash) is stored.
func (c *Client) MarkStored(ctx context.Context, k *Keys, name string, gen uint64, hash string) (kms.SignedGen, error) {
	return c.commit(ctx, k, name, gen, hash, true)
}

func (c *Client) commit(ctx context.Context, k *Keys, name string, gen uint64, hash string, stored bool) (kms.SignedGen, error) {
	g := kms.Gen{App: k.App, Name: name, Gen: gen, Hash: hash}
	gc := kms.GenCommit{Gen: g, Holder: k.Lease.Holder, Stored: stored, Nonce: NewNonce(), Lease: k.Lease.ID, At: c.cfg.Now().Unix()}
	gc.MAC = kms.CommitMAC(k.LeaseSecret, gc)
	req, _ := json.Marshal(gc)
	b, err := c.cfg.Transport.Do(ctx, http.MethodPost, "/v1/gen/commit", req)
	if err != nil {
		return kms.SignedGen{}, err
	}
	got, err := CheckGen(b, c.cfg.KMSID, gc.Nonce)
	if err == nil && (got.Gen != g || got.Stored != stored) {
		err = errors.New("kms: commit answered for another generation")
	}
	return got, err
}

// Generation reads the register's entry for (app, name), signed by the KMS id over a fresh nonce (checked: an old
// answer replayed doesn't verify).
func (c *Client) Generation(ctx context.Context, app, name string) (kms.SignedGen, error) {
	nonce := NewNonce()
	b, err := c.cfg.Transport.Do(ctx, http.MethodGet, "/v1/gen?app="+url.QueryEscape(app)+"&name="+url.QueryEscape(name)+"&nonce="+nonce, nil)
	if err != nil {
		return kms.SignedGen{}, err
	}
	g, err := CheckGen(b, c.cfg.KMSID, nonce)
	if err == nil && (g.Gen.App != app || g.Gen.Name != name) {
		err = errors.New("kms: register answered for another entry")
	}
	return g, err
}

// CheckGen decodes a SignedGen and checks its signature and that it answers nonce.
func CheckGen(b []byte, kmsID ed25519.PublicKey, nonce string) (kms.SignedGen, error) {
	var sg kms.SignedGen
	if err := kms.Strict(b, &sg); err != nil {
		return kms.SignedGen{}, err
	}
	if sg.Nonce != nonce || len(sg.Sig) != ed25519.SignatureSize || !ed25519.Verify(kmsID, kms.GenSigMessage(sg), sg.Sig) {
		return kms.SignedGen{}, ErrBadSignature
	}
	return sg, nil
}

// Snapshot fetches the whole register, signed by the KMS id over a fresh nonce (checked): kmsctl gen-snapshot.
func Snapshot(ctx context.Context, t Transport, kmsID ed25519.PublicKey) (*kms.SignedSnapshot, error) {
	nonce := NewNonce()
	b, err := t.Do(ctx, http.MethodGet, "/v1/gen/snapshot?nonce="+nonce, nil)
	if err != nil {
		return nil, err
	}
	var ss kms.SignedSnapshot
	if err := kms.Strict(b, &ss); err != nil {
		return nil, err
	}
	if ss.Snapshot.Nonce != nonce {
		return nil, ErrBadSignature
	}
	return &ss, CheckSnapshot(&ss, kmsID)
}

// CheckSnapshot checks a snapshot's signature under the KMS id it names, which must be kmsID.
func CheckSnapshot(ss *kms.SignedSnapshot, kmsID ed25519.PublicKey) error {
	if ss.Snapshot.KMSID != kms.IDString(kmsID) || len(ss.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kmsID, kms.SnapshotSigMessage(ss.Snapshot), ss.Sig) {
		return ErrBadSignature
	}
	return nil
}

// Static is a KeySource stub: it returns Keys (only the purposes asked for) or Err.
type Static struct {
	Keys *Keys
	Err  error
}

// Release implements KeySource.
func (s Static) Release(_ context.Context, purposes []string) (*Keys, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	if s.Keys == nil {
		return nil, errors.New("kms: static key source has no keys")
	}
	k := *s.Keys
	k.Keys = map[string][]byte{}
	for _, p := range purposes {
		b, ok := s.Keys.Keys[p]
		if !ok {
			return nil, fmt.Errorf("kms: static key source has no %s key", p)
		}
		k.Keys[p] = slices.Clone(b)
	}
	return &k, nil
}

// HTTP is a Transport over HTTP(S) to Base (e.g. "https://kms-1.example"): kmsctl, peers and tests. The
// protocol's own signatures and sealing protect what matters; TLS adds nothing it relies on.
type HTTP struct {
	Base   string
	Client *http.Client // nil = a client with a 60 s timeout
}

// Do implements Transport.
func (h HTTP) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.Base, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		var e kms.Error
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(res.StatusCode)
		}
		return nil, &RefusedError{Status: res.StatusCode, Reason: e.Error}
	}
	return b, nil
}

// Handler is a Transport straight to an http.Handler (tests, and a kmsd in the same process).
type Handler struct{ H http.Handler }

// Do implements Transport.
func (h Handler) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://kms"+path, rd)
	if err != nil {
		return nil, err
	}
	w := &recorder{h: http.Header{}, code: http.StatusOK}
	h.H.ServeHTTP(w, req)
	if w.code != http.StatusOK {
		var e kms.Error
		if json.Unmarshal(w.buf.Bytes(), &e) != nil || e.Error == "" {
			e.Error = http.StatusText(w.code)
		}
		return nil, &RefusedError{Status: w.code, Reason: e.Error}
	}
	return w.buf.Bytes(), nil
}

type recorder struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return r.buf.Write(b) }
func (r *recorder) WriteHeader(c int)           { r.code = c }
