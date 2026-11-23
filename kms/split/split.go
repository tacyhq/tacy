// Package split is Tacy's split-key unlock (the keys plan §11, FD-17). The Tacy KMS's master key M (same M, same KMS id
// as the genesis) stays offline in the admin's passphrase shares. Each epoch e has a VM root R_e = HKDF(M,
// "tacy-split/vm-root/v1", e) (EpochRoot), and it is R_e, never M, that is Shamir-split t-of-n across online share
// holders (the chat Worker's holder, Vercel, later Google Cloud). The agent VM rebuilds R_e at every boot from any t
// of them. No always-on key service: each holder checks the VM's TDX attestation, its own fresh nonce and a
// admin-signed unlock policy by itself, then seals its share to the key the quote binds. The VM combines t shares,
// checks R_e is the epoch's (its root id, in the share set the KMS id signed), derives its per-purpose keys from R_e
// and drops it. The KMS id signs, offline and once per epoch, an epoch certificate for R_e's public keys (the
// store certificates, the activity signer), so the VM never needs the KMS id's private key. A leaked R_e is answered
// by an offline re-split to e+1: no new KMS id, no client update (the no-downtime plan).
//
// This package is the wire format, the share math and the VM's side (Unlock); package split/holder is a holder.
// Standard library plus kms, kms/client, proto and safety only, so the VM's binaries can use it without the
// verifier. It touches no file.
//
// # Documents
//
//   - ShareSet (signed by the KMS id, so only someone holding M made it): the split's KMS id, epoch, set number,
//     threshold, R_e's root id and, per holder, its id, share index, the public key its share is sealed to, and the
//     share's commitment. Made by Resplit (kmsctl resplit, on the admin's laptop from two passphrase shares). Set
//     numbers grow with each re-split: shares of different sets never combine.
//   - EpochCert (signed by the KMS id, once per epoch; NewEpochCert): R_e's root id and public keys.
//   - UnlockPolicy (KindUnlockPolicy, the admin's admin keys): kms.Policy (release pins, floors, OS images,
//     boot sets, apps and purposes) plus the holders' URLs, up to two share sets, their epochs' certificates and
//     optional fields (TCB grace, platforms, start tickets, rollback witnesses, next admin keys) that later changes
//     use without a lockstep client update. The holder list and the threshold are policy data, not compiled into a
//     VM release. During a re-split the policy carries the old and the new share set side by side (the no-downtime plan: add,
//     switch, remove): the VM tries the newest set first and falls back to the older one. No expiry: a newer seq
//     withdraws.
//   - HolderShare: one holder's share sealed (HPKE) to that holder's own key: what the holder keeps.
//
// # Unlock (tacy-split/v1)
//
//		GET  /v1/challenge -> Challenge (a holder nonce: stateless, MAC'd, NonceTTL)
//		POST /v1/unlock  UnlockRequest -> UnlockReply
//		POST /v1/policy  a signed unlock policy -> {"policy_seq": N}
//		GET  /v1/status    -> Status (public: holder id, KMS id, the sets it serves and its index in each)
//
//	 1. The VM asks every holder in the policy for a nonce (in parallel; a holder that doesn't answer is skipped).
//	 2. It makes one X25519 key in memory and one TDX quote whose report_data is proto.ReportData(Bind(nonces), key):
//	    one quote binds every holder's nonce (Bind sorts them by holder id).
//	 3. It sends each holder UnlockRequest{nonces, attestation, policy, set}. Each holder checks its own nonce, the
//	    policy (admin signatures, kind, KMS id, seq floor, the highest seq it has seen, newly pinned releases only
//	    after a delay), the attestation, and that its share matches its commitment.
//	 4. Reply: HPKE(DHKEM(X25519), HKDF-SHA256, AES-256-GCM; info LabelReply, aad ReplyAAD) of the share to the
//	    attested key. The VM keeps shares that match their commitments, combines t, and keeps R_e only if its root id
//	    is the share set's.
package split

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// Version names this wire format.
const Version = "tacy-split/v1"

// Labels. Each use has its own, so nothing made for one opens or verifies as another (nor as a kms one).
const (
	LabelNonces      = "tacy-split/nonces/v1"       // the bound nonce: sha256 over every holder's nonce
	LabelNonceMAC    = "tacy-split/nonce-mac/v1"    // HMAC label: a holder's stateless nonce
	LabelHolderShare = "tacy-split/holder-share/v1" // HPKE info: a share sealed to its holder's key
	LabelReply       = "tacy-split/reply/v1"        // HPKE info: a share sealed to the VM's quote-bound key
	LabelBreakGlass  = "tacy-split/break-glass/v1"  // HPKE info: R_e itself sealed to the VM's key (break-glass only)
	sigShareSet      = "tacy-split/share-set/v1"    // Ed25519 label (KMS id): a share set
	sigCommit        = "tacy-split/commit/v1"       // commitment label
)

// KindUnlockPolicy is the admin-signed unlock policy's safety.Envelope kind (not kms.KindPolicy, so a kmsd policy
// can't pass as one).
const KindUnlockPolicy = "kms-unlock-policy"

// KindStartTicket is a Worker-signed start ticket: the Worker started this VM (UnlockPolicy.StartTicketKeys).
const KindStartTicket = "vm-start-ticket"

// Break-glass (2026-11-20: manual, emergency only): when too few holders answer, the admin's kmsctl
// rebuilds M from two passphrase shares and serves one boot as the holder BreakGlassHolder, through a relay at the
// policy's BreakGlass URL. Its reply is UnlockReply with Set 0 and Index 0 whose Sealed is R_e for the policy's
// epoch (info LabelBreakGlass, aad ReplyAAD(bound, kms id, epoch, 0, BreakGlassHolder, 0)), never M; the VM keeps
// it only if its root id is the epoch certificate's.
const BreakGlassHolder = "break-glass"

// Bounds.
const (
	NonceTTL     = 2 * time.Minute
	NonceSize    = 32
	MaxHolders   = 16
	MaxBody      = 1 << 20
	MaxClockSkew = time.Minute
	MaxShareSets = 2    // the live share set and the one replacing it
	MaxSeqJump   = 1000 // a policy seq at most this far above the highest one a holder has seen
)

var holderRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// hostHoldsNoShare: the VM host holds no share ("Keys", design review H4; gcp-host review M4): a policy that
// lets the VM run on Google Cloud names no Google-run holder.
func (p *UnlockPolicy) hostHoldsNoShare() error {
	if !p.AllowsPlatform(PlatformGCP) {
		return nil
	}
	for _, h := range p.Holders {
		if GoogleHolder(h.Holder) {
			return fmt.Errorf("split: unlock policy: names %s and the Google holder %q: the VM's host may not hold a share", PlatformGCP, h.Holder)
		}
	}
	return nil
}

// GoogleHolder says whether a holder id is a Google Cloud holder's ("gcp", the Google holder's id in code, or any id
// starting "gcp-" or "google").
func GoogleHolder(id string) bool {
	return id == "gcp" || strings.HasPrefix(id, "gcp-") || strings.HasPrefix(id, "google")
}

// ValidHolder is a holder id's syntax ("cloudflare", "vercel", "gcp").
func ValidHolder(s string) bool { return holderRe.MatchString(s) }

// HolderNonce is one holder's nonce (hex) as the VM bound it.
type HolderNonce struct {
	Holder string `json:"holder"`
	Nonce  string `json:"nonce"`
}

// Bind is the nonce the VM's quote binds (proto.ReportData(Bind(nonces), key)): sha256 of the label and every
// holder's id and nonce, strictly sorted by holder id. 1 to MaxHolders entries, each nonce NonceSize bytes.
func Bind(nonces []HolderNonce) ([]byte, error) {
	if len(nonces) == 0 || len(nonces) > MaxHolders {
		return nil, fmt.Errorf("split: 1 to %d holder nonces", MaxHolders)
	}
	h := sha256.New()
	h.Write(append([]byte(LabelNonces), 0))
	for i, n := range nonces {
		if !ValidHolder(n.Holder) || (i > 0 && nonces[i-1].Holder >= n.Holder) {
			return nil, errors.New("split: holder nonces must be sorted by holder id, each holder once")
		}
		b, err := hex.DecodeString(n.Nonce)
		if err != nil || len(b) != NonceSize || strings.ToLower(n.Nonce) != n.Nonce {
			return nil, fmt.Errorf("split: %s's nonce isn't %d bytes of lowercase hex", n.Holder, NonceSize)
		}
		h.Write(lp(nil, n.Holder))
		h.Write(b)
	}
	return h.Sum(nil), nil
}

// Challenge is GET /v1/challenge.
type Challenge struct {
	Holder  string `json:"holder"`
	Nonce   string `json:"nonce"`   // NonceSize bytes, hex
	Expires int64  `json:"expires"` // unix seconds
}

// NewNonce makes holder's stateless nonce: 8 random bytes, the expiry (u64 big-endian unix seconds) and the first
// 16 bytes of HMAC-SHA256(key, label ‖ holder ‖ the first 16 bytes). Only the holder (key) makes one that checks.
func NewNonce(key []byte, holder string, expires time.Time, rnd io.Reader) (string, error) {
	b := make([]byte, NonceSize)
	if _, err := io.ReadFull(rnd, b[:8]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(b[8:16], uint64(expires.Unix()))
	copy(b[16:], nonceMAC(key, holder, b[:16]))
	return hex.EncodeToString(b), nil
}

// CheckNonce checks a nonce NewNonce made with key for holder and returns its expiry. It doesn't know whether the
// nonce was used: the holder's NonceStore does.
func CheckNonce(key []byte, holder, nonce string, now time.Time) (time.Time, error) {
	b, err := hex.DecodeString(nonce)
	if err != nil || len(b) != NonceSize {
		return time.Time{}, errors.New("nonce isn't 32 bytes of hex")
	}
	if !hmac.Equal(b[16:], nonceMAC(key, holder, b[:16])) {
		return time.Time{}, errors.New("nonce wasn't issued by this holder")
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)
	if !now.Before(exp) {
		return time.Time{}, errors.New("nonce expired")
	}
	if exp.Sub(now) > NonceTTL+MaxClockSkew {
		return time.Time{}, errors.New("nonce expires too far ahead")
	}
	return exp, nil
}

func nonceMAC(key []byte, holder string, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(append([]byte(LabelNonceMAC), 0))
	m.Write(lp(nil, holder))
	m.Write(b)
	return m.Sum(nil)[:16]
}

// SetHolder is one holder of a share set.
type SetHolder struct {
	Holder string `json:"holder"`
	Index  byte   `json:"index"` // the share's x (1..n)
	// Recipient is the holder's own key its HolderShare is sealed to: "x25519:<base64 32 bytes>" or
	// "p256:<base64 SEC1 uncompressed>".
	Recipient  string `json:"recipient"`
	Commitment string `json:"commitment"` // Commitment(...) of its share, hex
}

// ShareSet is one split of an epoch's VM root R_e across holders.
type ShareSet struct {
	KMSID     string      `json:"kms_id"`
	Epoch     uint32      `json:"epoch"`
	Set       uint32      `json:"set"`  // grows with each re-split (the genesis's passphrase shares of M are set 1)
	Root      string      `json:"root"` // R_e's root id (RootID, "ed25519:<base64>"): what the combined shares must give
	Threshold int         `json:"threshold"`
	Holders   []SetHolder `json:"holders"`
	IssuedAt  time.Time   `json:"issued_at"`
}

// Holder returns id's entry.
func (s *ShareSet) Holder(id string) (SetHolder, bool) {
	i := slices.IndexFunc(s.Holders, func(h SetHolder) bool { return h.Holder == id })
	if i < 0 {
		return SetHolder{}, false
	}
	return s.Holders[i], true
}

// Validate checks a share set's form.
func (s *ShareSet) Validate() error {
	if _, err := kms.ParseID(s.KMSID); err != nil {
		return fmt.Errorf("split: share set: %w", err)
	}
	if _, err := kms.ParseID(s.Root); err != nil {
		return fmt.Errorf("split: share set root: %w", err)
	}
	if s.Epoch == 0 || s.Set < 2 {
		return errors.New("split: share set: epoch must be > 0 and set > 1 (set 1 is the genesis)")
	}
	n := len(s.Holders)
	if n < 1 || n > MaxHolders || s.Threshold < 1 || s.Threshold > n {
		return fmt.Errorf("split: share set: %d-of-%d isn't a valid split", s.Threshold, n)
	}
	if n > 1 && s.Threshold < 2 {
		return errors.New("split: share set: with more than one holder the threshold must be at least 2")
	}
	ids, idx, rcp := map[string]bool{}, map[byte]bool{}, map[string]bool{}
	for _, h := range s.Holders {
		if !ValidHolder(h.Holder) || h.Holder == BreakGlassHolder || ids[h.Holder] || h.Index == 0 || idx[h.Index] || rcp[h.Recipient] {
			return errors.New("split: share set: holder ids, indexes and recipients must be valid and distinct")
		}
		if _, err := ParseRecipient(h.Recipient); err != nil {
			return fmt.Errorf("split: share set: %s: %w", h.Holder, err)
		}
		if b, err := hex.DecodeString(h.Commitment); err != nil || len(b) != 32 {
			return fmt.Errorf("split: share set: %s's commitment isn't 32 bytes of hex", h.Holder)
		}
		ids[h.Holder], idx[h.Index], rcp[h.Recipient] = true, true, true
	}
	return nil
}

// SignedShareSet is a ShareSet's exact JSON and the KMS id's signature over label ‖ 0 ‖ doc. Doc is bytes (base64
// in JSON, like safety.Envelope's payload), so re-encoding the outer JSON never changes what was signed.
type SignedShareSet struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// Open checks the KMS id signed s and returns its valid share set for that id.
func (s SignedShareSet) Open(kmsID ed25519.PublicKey) (*ShareSet, error) {
	if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(kmsID, signMessage(sigShareSet, s.Doc), s.Sig) {
		return nil, errors.New("split: share set isn't signed by the KMS id")
	}
	var set ShareSet
	if err := kms.Strict(s.Doc, &set); err != nil {
		return nil, fmt.Errorf("split: share set: %w", err)
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	if set.KMSID != kms.IDString(kmsID) {
		return nil, errors.New("split: share set is for another KMS id")
	}
	return &set, nil
}

func signMessage(label string, doc []byte) []byte { return append(append([]byte(label), 0), doc...) }

// HolderURL is where the VM reaches a holder, and the holder's pinned build: the sha256 of the reproducible build
// the holder deploys (its build-hashes record; "" = not pinned). A holder reports its build in /v1/status, and the
// holders' cron and the chat Worker alert on any holder whose build isn't the pinned one.
type HolderURL struct {
	Holder string `json:"holder"`
	URL    string `json:"url"` // https://...
	// AltURLs are other addresses of the same holder (a second domain), tried in order when URL doesn't answer.
	AltURLs []string `json:"alt_urls,omitempty"`
	Build   string   `json:"build,omitempty"`
}

// UnlockPolicy (KindUnlockPolicy, the admin keys) is what holders release to whom, and which holders hold what.
// kms.Policy's fields are inline (its KMSID names the key service; Epoch is the newest epoch its share sets use; Seq
// replaces only a lower one). No expiry (2026-11-20): a newer seq withdraws.
type UnlockPolicy struct {
	kms.Policy
	Holders []HolderURL `json:"holders"`
	// ShareSets: the live share set and, during a re-split, the one replacing it (1 to MaxShareSets, distinct set
	// numbers, of Epoch or, while an epoch change overlaps, Epoch-1). The VM tries them newest first.
	ShareSets []SignedShareSet `json:"share_sets"`
	// EpochCerts: the KMS id's certificate of each epoch the share sets use.
	EpochCerts []SignedEpochCert `json:"epoch_certs"`
	// BreakGlass is the admin's break-glass relay (https; "" = none): the VM asks it only after every share set
	// failed.
	BreakGlass string `json:"break_glass,omitempty"`

	// Optional fields, added before anything uses all of them so later changes need no lockstep update.

	// TCBGrace lets a quote whose TCB status is one of its statuses (never Revoked) unlock until it ends (Intel
	// published a TCB update and the hosts haven't caught up; the no-downtime plan row 14). The status is in every event.
	TCBGrace *safety.TCBGrace `json:"tcb_grace,omitempty"`
	// Platforms are the attestation platforms holders accept ("dstack"; empty = ["dstack"]).
	Platforms []string `json:"platforms,omitempty"`
	// StartTicketKeys, when set, are the Worker keys ("ed25519:<base64>") one of which must have signed the
	// request's start ticket (KindStartTicket): the Worker started this VM.
	StartTicketKeys []string `json:"start_ticket_keys,omitempty"`
	// Witnesses are the holders that keep the VM's rollback-witness head (the keys plan §11.2; with Google). Not used yet.
	Witnesses []string `json:"witnesses,omitempty"`
	// NextAdminKeys announce the admin keys that will sign after a rotation (the no-downtime plan row 15). Not used yet.
	NextAdminKeys []string `json:"next_admin_keys,omitempty"`
	// Emergency, signed by the KMS id (two passphrase shares) on top of the admin signature, lets the release pins
	// it names unlock at once, without the holders' pin delay (the no-downtime plan row 13). Every holder alerts on it.
	Emergency *SignedEmergency `json:"emergency,omitempty"`

	// The machine allowlist (V1-DESIGN §3; safety/machine.go). MachineCerts are the machines a VM may run on, each
	// signed by the KMS id (two passphrase shares), not by the admin key and not tied to this seq; required and
	// non-empty (no omitempty: an empty list never reads as "the built-in ones", review L2). MachinesRevoked are
	// certificate hashes refused for good: each holder keeps every one it has seen (ItemMachineRevoked items, never
	// withdrawn), so an admin key alone can revoke but never re-allow. Neither has a 24 h delay or a policy item of
	// its own beyond the revocations' record (decided for v1). It stops quotes forged on machines outside the
	// list, NOT the host: Phala (or anyone with physical access to a listed machine) can forge one that passes.
	//
	// omitzero, unlike the design's "no omitempty" (review L2), on purpose: the trap L2 names (an empty list
	// dropped and read as "absent = the built-in ones") can't happen, since Validate refuses absent and empty alike
	// at every holder and kmsctl (TestProductionPolicyNeedsMachineCerts), and a holder has no built-in machines. It
	// keeps OtherItem's bytes for policies without the fields, so a holder upgrade starts no 24 h wait.
	MachineCerts    []safety.SignedMachineCert `json:"machine_certs,omitzero"`
	MachinesRevoked []string                   `json:"machines_revoked,omitzero"`
}

// PlatformGCP is the platform name that turns on the Google Cloud fallback (verifier.PlatformDstackGCP): a Google
// machine certificate is valid only in a policy that names it (V1-DESIGN §2.7).
const PlatformGCP = "dstack-gcp"

// OpenMachines checks every machine certificate is the KMS id's (a policy with one that isn't is refused whole) and
// returns the policy's machines without its revoked ones. A holder also refuses the revocations its store kept.
func (p *UnlockPolicy) OpenMachines(kmsID ed25519.PublicKey) (*safety.MachineSet, error) {
	if len(p.MachineCerts) == 0 {
		return nil, errors.New("split: unlock policy: no machine certificates (machine_certs is required)")
	}
	s, err := safety.OpenMachineCerts(kmsID, p.MachineCerts, p.MachinesRevoked, p.AllowsPlatform(PlatformGCP), fmt.Sprintf("unlock policy %d", p.Seq))
	if err != nil {
		return nil, fmt.Errorf("split: unlock policy: %w", err)
	}
	return s, nil
}

// OpenShareSets checks every share set is signed by kmsID, of the policy's epoch or the one before, certified by an
// epoch certificate, with distinct set numbers, and returns them newest (highest set) first.
func (p *UnlockPolicy) OpenShareSets(kmsID ed25519.PublicKey) ([]*ShareSet, error) {
	if len(p.ShareSets) == 0 || len(p.ShareSets) > MaxShareSets {
		return nil, fmt.Errorf("split: unlock policy: 1 to %d share sets", MaxShareSets)
	}
	certs, err := p.OpenEpochCerts(kmsID)
	if err != nil {
		return nil, err
	}
	var out []*ShareSet
	for _, ss := range p.ShareSets {
		set, err := ss.Open(kmsID)
		if err != nil {
			return nil, err
		}
		if set.Epoch != p.Epoch && set.Epoch+1 != p.Epoch {
			return nil, fmt.Errorf("split: share set %d is of epoch %d, the policy's is %d", set.Set, set.Epoch, p.Epoch)
		}
		c, ok := certs[set.Epoch]
		if !ok || c.Root != set.Root {
			return nil, fmt.Errorf("split: share set %d's root isn't certified for epoch %d", set.Set, set.Epoch)
		}
		if _, dup := FindSet(out, set.Set); dup {
			return nil, fmt.Errorf("split: share set %d is listed twice", set.Set)
		}
		out = append(out, set)
	}
	slices.SortFunc(out, func(a, b *ShareSet) int { return int(b.Set) - int(a.Set) })
	return out, nil
}

// OpenEpochCerts checks every epoch certificate is signed by kmsID, one per epoch, and returns them by epoch.
func (p *UnlockPolicy) OpenEpochCerts(kmsID ed25519.PublicKey) (map[uint32]*EpochCert, error) {
	if len(p.EpochCerts) == 0 || len(p.EpochCerts) > MaxShareSets {
		return nil, fmt.Errorf("split: unlock policy: 1 to %d epoch certificates", MaxShareSets)
	}
	out := map[uint32]*EpochCert{}
	for _, sc := range p.EpochCerts {
		c, err := sc.Open(kmsID)
		if err != nil {
			return nil, err
		}
		if _, dup := out[c.Epoch]; dup {
			return nil, fmt.Errorf("split: two epoch certificates for epoch %d", c.Epoch)
		}
		out[c.Epoch] = c
	}
	return out, nil
}

// FindSet is the set numbered n among sets.
func FindSet(sets []*ShareSet, n uint32) (*ShareSet, bool) {
	i := slices.IndexFunc(sets, func(s *ShareSet) bool { return s.Set == n })
	if i < 0 {
		return nil, false
	}
	return sets[i], true
}

// Validate checks an unlock policy's form (not its signatures, nor the share sets' and certificates').
func (p *UnlockPolicy) Validate() error {
	if err := p.Policy.Validate(); err != nil {
		return err
	}
	if p.KMSID == "" {
		return errors.New("split: unlock policy names no KMS id")
	}
	if p.TCBGrace != nil {
		if err := p.TCBGrace.Validate(p.IssuedAt); err != nil {
			return fmt.Errorf("split: unlock policy: %w", err)
		}
		if p.TCBGrace.MinTCBEval != 0 {
			return errors.New("split: unlock policy: min_tcb_eval isn't checked yet (the quote's TCB evaluation number isn't read); leave it out")
		}
	}
	if len(p.Holders) == 0 || len(p.Holders) > MaxHolders {
		return fmt.Errorf("split: unlock policy: 1 to %d holders", MaxHolders)
	}
	seen := map[string]bool{}
	for _, h := range p.Holders {
		if !ValidHolder(h.Holder) || seen[h.Holder] || h.Holder == BreakGlassHolder {
			return errors.New("split: unlock policy: holder ids must be valid and distinct (and never the break-glass one)")
		}
		if !strings.HasPrefix(h.URL, "https://") {
			return fmt.Errorf("split: unlock policy: %s's URL isn't https", h.Holder)
		}
		for _, u := range h.AltURLs {
			if !strings.HasPrefix(u, "https://") || len(h.AltURLs) > 3 {
				return fmt.Errorf("split: unlock policy: %s's alternate URLs must be https, at most 3", h.Holder)
			}
		}
		if b, err := hex.DecodeString(h.Build); h.Build != "" && (err != nil || len(b) != 32) {
			return fmt.Errorf("split: unlock policy: %s's build isn't a sha256", h.Holder)
		}
		seen[h.Holder] = true
	}
	if p.BreakGlass != "" && !strings.HasPrefix(p.BreakGlass, "https://") {
		return errors.New("split: unlock policy: the break-glass URL isn't https")
	}
	for _, pl := range p.Platforms {
		if !holderRe.MatchString(pl) {
			return fmt.Errorf("split: unlock policy: bad platform %q", pl)
		}
	}
	if err := p.hostHoldsNoShare(); err != nil {
		return err
	}
	for _, list := range [][]string{p.StartTicketKeys, p.NextAdminKeys} {
		for _, k := range list {
			if _, err := kms.ParseID(k); err != nil {
				return fmt.Errorf("split: unlock policy: %w", err)
			}
		}
	}
	for _, w := range p.Witnesses {
		if !seen[w] {
			return fmt.Errorf("split: unlock policy: witness %q isn't a holder", w)
		}
	}
	if len(p.MachineCerts) == 0 || len(p.MachineCerts) > safety.MaxMachineCerts {
		return fmt.Errorf("split: unlock policy: 1 to %d machine certificates (machine_certs is required)", safety.MaxMachineCerts)
	}
	if err := safety.ValidRevocations(p.MachinesRevoked); err != nil {
		return fmt.Errorf("split: unlock policy: %w", err)
	}
	return nil
}

// AllowsPlatform: the platforms the policy names, or "dstack" when it names none.
func (p *UnlockPolicy) AllowsPlatform(name string) bool {
	if len(p.Platforms) == 0 {
		return name == "dstack"
	}
	return slices.Contains(p.Platforms, name)
}

// HolderShare is what a holder keeps: its share sealed to its own key (info LabelHolderShare, aad HolderShareAAD).
type HolderShare struct {
	KMSID     string `json:"kms_id"`
	Epoch     uint32 `json:"epoch"`
	Set       uint32 `json:"set"`
	Holder    string `json:"holder"`
	Index     byte   `json:"index"`
	Recipient string `json:"recipient"`
	kms.Sealed
}

// HolderShareAAD binds a holder share to its KMS id, epoch, set, holder and index.
func HolderShareAAD(kmsID string, epoch, set uint32, holder string, index byte) []byte {
	b := lp(nil, kmsID)
	b = binary.BigEndian.AppendUint32(b, epoch)
	b = binary.BigEndian.AppendUint32(b, set)
	b = lp(b, holder)
	return append(b, index)
}

// Commitment is sha256(label ‖ 0 ‖ HolderShareAAD(...) ‖ share), hex: what a holder's share must hash to.
func Commitment(kmsID string, epoch, set uint32, holder string, index byte, share []byte) string {
	h := sha256.New()
	h.Write(append([]byte(sigCommit), 0))
	h.Write(HolderShareAAD(kmsID, epoch, set, holder, index))
	h.Write(share)
	return hex.EncodeToString(h.Sum(nil))
}

// UnlockRequest is POST /v1/unlock.
type UnlockRequest struct {
	Nonces []HolderNonce `json:"nonces"` // every holder nonce the quote binds (Bind), sorted
	// Attestation is proto.Attestation for Bind(Nonces), bound to the VM's in-memory X25519 key.
	Attestation json.RawMessage `json:"attestation"`
	Policy      json.RawMessage `json:"policy"` // the safety.Envelope (KindUnlockPolicy), the newest the VM got
	Set         uint32          `json:"set"`
	Release     string          `json:"release,omitempty"` // the VM's release (vX.Y.Z): must be the pinned one when given
	// StartTicket: the Worker's KindStartTicket envelope for this start (required when the policy names
	// StartTicketKeys).
	StartTicket json.RawMessage `json:"start_ticket,omitempty"`
}

// StartTicket is a start ticket's payload (KindStartTicket, a Worker key the policy names; the chat Worker's
// start-ticket.ts makes it): the Worker started a VM of this app id at IssuedAt, and delivers the ticket to that VM
// once. A holder takes a ticket for one VM only: the first attested instance that brings it (within
// StartTicketTTL of its issue) claims it, keyed on the envelope's hash; the same instance may bring it again for
// StartTicketBoot (a container restart unlocks again), any other is refused.
type StartTicket struct {
	KMSID    string    `json:"kms_id"`
	AppID    string    `json:"app_id"`
	IssuedAt time.Time `json:"issued_at"`
}

// StartTicketTTL is how soon after its issue a ticket must first be used; StartTicketBoot how long its first VM may
// use it again.
const (
	StartTicketTTL  = time.Hour
	StartTicketBoot = 24 * time.Hour
)

// UnlockReply is POST /v1/unlock's answer: the holder's share sealed to the attested key.
type UnlockReply struct {
	Holder string     `json:"holder"`
	Index  byte       `json:"index"`
	KMSID  string     `json:"kms_id"`
	Epoch  uint32     `json:"epoch"`
	Set    uint32     `json:"set"`
	Sealed kms.Sealed `json:"sealed"`
	// No witness_head: the legacy rollback witness is removed (V1-DESIGN §2.5 step 1). The VM decodes replies
	// strictly, so a reply that still carries one is refused.
}

// noWitnessHead is the last AAD item, as it was when replies could carry the legacy witness head and carried none
// (sha256 of nothing): kept so the AAD's bytes don't change.
var noWitnessHead = func() string { h := sha256.Sum256(nil); return string(h[:]) }()

// ReplyAAD binds a reply to the bound nonce (so to this quote and boot key), the KMS id, epoch, set, holder, index
// and the policy the holder served it under (PolicyHash of its payload: the VM refuses a reply under another policy
// than the one it sent).
func ReplyAAD(bound []byte, kmsID string, epoch, set uint32, holder string, index byte, policyHash string) []byte {
	b := append(lp(nil, string(bound)), HolderShareAAD(kmsID, epoch, set, holder, index)...)
	b = lp(b, policyHash)
	return lp(b, noWitnessHead)
}

// Status is GET /v1/status (public).
type Status struct {
	Version   string      `json:"version"`
	Holder    string      `json:"holder"`
	KMSID     string      `json:"kms_id"`
	Sets      []StatusSet `json:"sets"`       // the share sets this holder serves
	PolicySeq uint64      `json:"policy_seq"` // the highest policy seq this holder took (0: its store isn't initialized)
	Build     string      `json:"build"`      // this holder's build (sha256), as its deploy states it
}

// StatusSet is one share set a holder serves: its number, epoch and the holder's index in it.
type StatusSet struct {
	Set   uint32 `json:"set"`
	Epoch uint32 `json:"epoch"`
	Index byte   `json:"index"`
}

// ParseRecipient reads a holder recipient: "x25519:<base64 32 bytes>" or "p256:<base64 SEC1 uncompressed>".
func ParseRecipient(s string) (*ecdh.PublicKey, error) {
	if b64, ok := strings.CutPrefix(strings.TrimSpace(s), "x25519:"); ok {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(b) != 32 {
			return nil, errors.New("recipient must be x25519:<base64 of 32 bytes>")
		}
		return ecdh.X25519().NewPublicKey(b)
	}
	return kms.ParseRecipient(s)
}

// RecipientString names a holder's public key (X25519 or P-256).
func RecipientString(pub *ecdh.PublicKey) string {
	if pub.Curve() == ecdh.X25519() {
		return "x25519:" + base64.StdEncoding.EncodeToString(pub.Bytes())
	}
	return kms.RecipientString(pub)
}

// HolderRecipient is one holder of a re-split: its id and the key its share is sealed to.
type HolderRecipient struct {
	Holder    string `json:"holder"`
	Recipient string `json:"recipient"`
}

// Resplit splits epoch's VM root R_e (EpochRoot(M, epoch), never M) t-of-n across holders (index i+1 to
// holders[i]), seals each share to its holder's key and signs the share set with the KMS id (which M derives). It
// refuses an M that doesn't derive kmsID: a re-split never starts a new KMS. No plaintext share leaves it.
func Resplit(master []byte, kmsID string, epoch, set uint32, threshold int, holders []HolderRecipient, issuedAt time.Time,
	rnd io.Reader) (*SignedShareSet, []HolderShare, error) {
	id, err := checkMaster(master, kmsID)
	if err != nil {
		return nil, nil, err
	}
	defer clear(id)
	if len(holders) == 0 || len(holders) > MaxHolders {
		return nil, nil, fmt.Errorf("split: 1 to %d holders", MaxHolders)
	}
	pubs := make([]*ecdh.PublicKey, len(holders))
	for i, h := range holders {
		if pubs[i], err = ParseRecipient(h.Recipient); err != nil {
			return nil, nil, fmt.Errorf("split: %s: %w", h.Holder, err)
		}
	}
	root, err := EpochRoot(master, epoch)
	if err != nil {
		return nil, nil, err
	}
	defer clear(root)
	rid, err := RootID(root)
	if err != nil {
		return nil, nil, err
	}
	ss := ShareSet{KMSID: kmsID, Epoch: epoch, Set: set, Root: rid, Threshold: threshold, IssuedAt: issuedAt.UTC()}
	shares, err := kms.Split(root, len(holders), threshold, rnd)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for _, s := range shares {
			clear(s.Y)
		}
	}()
	out := make([]HolderShare, len(holders))
	for i, h := range holders {
		sh := shares[i]
		ss.Holders = append(ss.Holders, SetHolder{Holder: h.Holder, Index: sh.X, Recipient: h.Recipient,
			Commitment: Commitment(kmsID, epoch, set, h.Holder, sh.X, sh.Y)})
		box, err := kms.Seal(pubs[i], LabelHolderShare, HolderShareAAD(kmsID, epoch, set, h.Holder, sh.X), sh.Y)
		if err != nil {
			return nil, nil, err
		}
		out[i] = HolderShare{KMSID: kmsID, Epoch: epoch, Set: set, Holder: h.Holder, Index: sh.X, Recipient: h.Recipient, Sealed: box}
	}
	if err := ss.Validate(); err != nil {
		return nil, nil, err
	}
	doc, err := json.Marshal(ss)
	if err != nil {
		return nil, nil, err
	}
	return &SignedShareSet{Doc: doc, Sig: ed25519.Sign(id, signMessage(sigShareSet, doc))}, out, nil
}

// checkMaster returns the KMS id's private key if M derives kmsID.
func checkMaster(master []byte, kmsID string) (ed25519.PrivateKey, error) {
	id, err := kms.DeriveID(master)
	if err != nil {
		return nil, err
	}
	if kms.IDString(id.Public().(ed25519.PublicKey)) != kmsID {
		clear(id)
		return nil, errors.New("split: this master key doesn't derive the KMS id")
	}
	return id, nil
}

// OpenHolderShare opens a holder's share with its private key.
func OpenHolderShare(priv ecdh.KeyExchanger, hs HolderShare) ([]byte, error) {
	y, err := kms.Open(priv, LabelHolderShare, HolderShareAAD(hs.KMSID, hs.Epoch, hs.Set, hs.Holder, hs.Index), hs.Sealed)
	if err != nil {
		return nil, errors.New("split: the holder share doesn't open with this key")
	}
	return y, nil
}

// lp appends s length-prefixed (u32 big-endian).
func lp(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
