// Package kms is the Tacy key service's wire format and its key math: kmsd (cmd/kmsd, package kms/server) holds
// the master key M inside an Intel TDX VM and releases per-purpose keys and the secrets bundle only to an attested
// VM running a pinned release; kmsctl (cmd/kmsctl) is the admins' offline tool; kms/client is the VM's side. No key or
// secret here is protected by a provider's key: M exists only in TD memory and, offline, as Shamir shares sealed
// to the share holders' keys (passphrases, or hardware keys later).
//
// This package is standard library plus proto and safety only, so the VM's binaries can use it (through
// kms/client) without the verifier.
//
// # Wire format (tacy-kms/v1)
//
// JSON over HTTP. Bodies are decoded strictly (unknown members and trailing data are refused). []byte fields are
// standard base64. Hashes are lowercase hex sha256. A refusal is HTTP 4xx/5xx with {"error": "<reason>"} and never
// carries key material. Every state change is a hash-chained audit entry signed by the KMS id; refusals of requests
// that proved nothing (no valid signature, MAC or attestation) are counted, not stored one by one.
//
//	GET  /v1/status                 -> Status
//	GET  /v1/attest?nonce=<64 hex>  -> proto.Attestation: this boot's X25519 key (kmsctl and peers seal to it),
//	                                   bound to the nonce in the TDX quote's report_data (proto.ReportData)
//	GET  /v1/challenge              -> Challenge: a single-use nonce, valid ChallengeTTL
//	POST /v1/release   ReleaseRequest  -> ReleaseReply
//	POST /v1/lease/renew  LeaseRenew   -> SignedLease
//	POST /v1/lease/drop   LeaseRenew (MAC: DropMAC) -> SignedLease (the freed lease: a clean stop)
//	POST /v1/lease/move   safety.Envelope (KindLeaseMove, a Worker key) -> SignedLease (the lease left behind)
//	POST /v1/gen/commit   GenCommit    -> SignedGen (a reservation, or its "stored" mark)
//	GET  /v1/gen?app=&name=&nonce=<32 hex> -> SignedGen (the nonce is in the signature: an old answer doesn't verify)
//	GET  /v1/gen/snapshot?nonce=<32 hex>   -> SignedSnapshot: the whole register, for kmsctl to keep offline
//	POST /v1/gen/confirm  safety.Envelope (KindGen, admin keys) -> Status: the generations after a cold start
//	POST /v1/genesis   GenesisRequest  -> GenesisReply (an empty replica only)
//	POST /v1/unlock    UnlockRequest   -> UnlockReply (a locked replica)
//	POST /v1/peer/join JoinRequest     -> JoinReply (an unlocked replica, to a peer that has no M yet)
//	POST /v1/policy    safety.Envelope (KindPolicy, admin keys) -> Status
//	POST /v1/secrets/put  SecretsPut   -> SecretsReply
//	POST /v1/secrets/load SecretsLoad  -> SecretsReply
//	GET  /v1/log?from=<seq>            -> []AuditEntry (at most 1000)
//
// Every admin document (Policy, GenConfirm, SecretsDoc) and every LeaseMove names the KMS id and the epoch it is
// for, and a replica refuses one for another: a staging document never applies to production, even under the same
// admin keys. The one exception is the policy that comes with genesis: the KMS id doesn't exist yet, so it names
// none and is taken only together with the genesis document (bound to the replica's boot key); every later policy
// names the id (kmsctl genesis signs and loads that bound policy right after the ceremony).
//
// # Release
//
//  1. The VM gets a nonce: GET /v1/challenge.
//  2. It makes a TDX quote with report_data = proto.ReportData(nonce, key) for its process's boot key (an X25519 key
//     made once per process start; the lease is bound to it) and sends ReleaseRequest{nonce, attestation, release,
//     release_bundle, purposes, holder}.
//  3. kmsd checks: the nonce is one it issued and unused; sha256 of the attested app-compose.json is pinned by
//     the admin-signed Policy for a release of an app (the whole file: app id rules, key provider, ports, flags,
//     envs, the docker compose with every image digest); that release is at least the app's and the global floor;
//     verifier.Verify with the policy's OS images, boot measurements and pre-launch scripts (Intel chain, TCB,
//     report_data, RTMR3 replay, compose); every purpose asked is one the app may have; the holder's lease.
//  4. Reply: Sealed = HPKE(DHKEM(X25519), HKDF-SHA256, AES-256-GCM; info LabelRelease, aad nonce) to the attested
//     key, of ReleasePayload{keys, secrets, lease, lease secret}; Sig = Ed25519 by the KMS id over
//     ReleaseSigMessage(nonce, sha256(attestation bytes as sent), sha256(enc‖ct), lease, log_seq). The client
//     refuses any reply whose Sig doesn't verify under the KMS id it pins, before opening it. The app's secrets
//     (our API keys) go only in a release that asks for SecretsPurpose (vaultd's conn/v1), never in agentd's.
//  5. Keys: HKDF-SHA256(M_e, salt "tacy-kms/v1", info app‖0‖firm‖0‖purpose‖0‖e), 32 bytes (DeriveKey).
//
// The key service can't tell the VM's processes apart (one TD, one quote, one app): which process may ask for which
// purposes is enforced inside the VM, by gatewayd, the only process with a network (gateway.KMSGate: agentd's
// socket may not ask for conn/v1, vaultd's ops socket only for it).
//
// # Master key
//
// Genesis: an empty replica (no KMS id pinned) takes one admin-signed GenesisDoc naming its attested key, makes M,
// splits it t-of-n (Shamir over GF(2^8)), HPKE-seals share i to recipient i (DHKEM(P-256), HKDF-SHA256,
// AES-256-GCM; info LabelShare, aad ShareAAD) and returns the shares and the KMS id: the Ed25519 key whose seed is
// HKDF-SHA256(M, info "tacy-kms/id/v1"). Unlock: a replica started with -kms-id is locked; kmsctl opens one share at
// a time and reseals it to the replica's attested key (info LabelUnlock); the replica keeps a share only if it
// matches its commitment (genesis signs one per share with the KMS id), and with t shares it rebuilds M and
// accepts it only if it derives the pinned KMS id. Join: a peer with the same pin gets M sealed to its attested key
// from an unlocked replica, each side checking the other's attestation against the policy's KMS pins (role and
// floor included) and that the other runs with the same admin keys, threshold and release floor.
//
// # One primary (one replica to start)
//
// The instance leases and the generation register live on one replica, the primary (kmsd -role primary, the
// default; its compose is pinned with Role "primary"). A standby (-role standby) only keeps M: it refuses releases,
// leases, commits and register reads, so two replicas never both grant. A primary that got M by unlock or join
// (not genesis) has no register yet: it releases nothing and commits nothing until the admins confirm the
// generations with a GenConfirm naming this replica's confirm nonce (Status), so a second live primary needs the
// admins' own signature for that very replica. A primary gives M to standbys only. A lease and register held by a
// majority of replicas (quorum) is future work (the keys plan §2.4).
//
// # Instance lease and generations
//
// One live instance (the attested instance-id event) per app and holder (agentd and vaultd each have their own
// lease): a release from another instance, or from the same instance with another boot key, is refused while the
// lease is held (LeaseTTL without renewal), unless a Worker-signed LeaseMove frees it. The lease holder renews it
// and commits generations with an HMAC under the lease secret (only in the sealed payload). The generation register
// (app, name) -> (gen, hash) takes a reservation of gen+1 from the current lease before the VM stores that blob, and
// then the VM's "stored" mark; it answers each entry signed by the KMS id over the caller's nonce, so a VM can refuse
// a replayed or forked sealed blob. After a cold start everything waits until the admin keys confirm the
// generations (KindGen), built from a register snapshot kmsctl exported (GET /v1/gen/snapshot).
package kms

import (
	"encoding/json"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// Version names this wire format.
const Version = "tacy-kms/v1"

// HKDF and HPKE labels. Each use has its own, so nothing made for one purpose opens or verifies as another.
const (
	LabelID        = "tacy-kms/id/v1"          // HKDF info: the KMS id's Ed25519 seed from M
	LabelPurpose   = "tacy-kms/v1"             // HKDF salt: per-purpose keys (DeriveKey)
	LabelSecrets   = "secrets/v1"              // HKDF info: the secrets bundle's AEAD key from M
	LabelShare     = "tacy-kms/share/v1"       // HPKE info: a share sealed to a recipient (P-256)
	LabelUnlock    = "tacy-kms/unlock/v1"      // HPKE info: a share resealed to a locked replica (X25519)
	LabelRelease   = "tacy-kms/release/v1"     // HPKE info: a release reply to a VM (X25519)
	LabelJoin      = "tacy-kms/join/v1"        // HPKE info: M sealed to a joining peer (X25519)
	LabelSecretPut = "tacy-kms/secret-put/v1"  // HPKE info: kmsctl's secrets bundle sealed to a replica (X25519)
	LabelLeaseMAC  = "tacy-kms/lease-mac/v1"   // HMAC label: lease renewals and generation commits
	LabelStoreAuth = "tacy-kms/store-auth/v1"  // HKDF info: a store-auth Ed25519 seed from a state purpose's key
	sigRelease     = "tacy-kms/release-sig/v1" // Ed25519 labels (KMS id)
	sigLease       = "tacy-kms/lease-sig/v1"
	sigGen         = "tacy-kms/gen-sig/v2"
	sigSnapshot    = "tacy-kms/snapshot-sig/v1"
	sigJoin        = "tacy-kms/join-sig/v1"
	sigGenesis     = "tacy-kms/genesis-sig/v1"
	sigCommit      = "tacy-kms/share-commit/v1"
	sigAudit       = "tacy-kms/audit/v1"
	sigAuditEntry  = "tacy-kms/audit-sig/v1"
	sigStoreCert   = "tacy-kms/store-cert/v1"
)

// Admin-signed document kinds (safety.Envelope). The kind is part of what is signed, so a policy signature can't
// pass as genesis or secrets, nor as any agent VM document.
const (
	KindGenesis   = "kms-genesis"    // GenesisDoc, admin keys
	KindPolicy    = "kms-policy"     // Policy, admin keys
	KindSecrets   = "kms-secrets"    // SecretsDoc, admin keys
	KindGen       = "kms-gen"        // GenConfirm, admin keys
	KindLeaseMove = "kms-lease-move" // LeaseMove, a Worker key the policy names
)

// Purposes a key can be released for. A policy gives each app a subset.
var Purposes = []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1", "notify/v1", "operator/v1", "relay-auth/v1"}

// SecretsPurpose is the purpose a release must ask for to carry the app's secrets (our third-party API keys):
// vaultd's. agentd never asks for it, so its release never holds an API key.
const SecretsPurpose = "conn/v1"

// StorePurposes are the purposes whose holders keep sealed state at the chat Worker's state API (GET/PUT
// /api/vm/state/<name>): a release of one carries a StoreCert, so the Worker tells the VM's requests from anyone
// else's by the KMS id alone, with no key of its own. The store-auth key is HKDF(purpose key, LabelStoreAuth): only
// the holder of the purpose key (and kmsd) can sign with it, and it is the same across boots, releases and app ids.
var StorePurposes = []string{"state/v1", "conn/v1"}

// Roles: the primary holds the leases and the register; a standby only keeps M.
const (
	RolePrimary = "primary"
	RoleStandby = "standby"
)

// StoreCert is the KMS id's statement that Key (the store-auth key, "ed25519:<base64>") is app's for purpose (of
// StorePurposes) in this epoch. Sig is Ed25519 by the KMS id over StoreCertMessage.
type StoreCert struct {
	App     string `json:"app"`
	Firm    string `json:"firm"`
	Epoch   uint32 `json:"epoch"`
	Purpose string `json:"purpose"`
	Key     string `json:"key"`
	Sig     []byte `json:"sig"`
}

// Timing and bounds.
const (
	ChallengeTTL  = 2 * time.Minute
	LeaseTTL      = 3 * time.Minute
	LeaseMoveTTL  = 5 * time.Minute // a LeaseMove's or a GenConfirm's issued_at must be this recent
	MaxClockSkew  = time.Minute     // renewals and commits carry the VM's time; an admin document may be this far ahead
	MaxBody       = 1 << 20         // a request body (a release request carries a quote and its event log)
	MaxChallenges = 4096            // outstanding nonces (the oldest go first when full)
	MaxDetail     = 256             // an audit entry's detail, bytes (longer is cut; control bytes escaped)
)

// Status is GET /v1/status.
type Status struct {
	Version   string `json:"version"`
	State     string `json:"state"`  // "empty" (genesis allowed), "locked" (waits for shares or a peer), "unlocked"
	Role      string `json:"role"`   // RolePrimary or RoleStandby
	KMSID     string `json:"kms_id"` // "ed25519:<base64>": the pinned id (locked) or M's (unlocked); "" when empty
	Epoch     uint32 `json:"epoch"`
	PolicySeq uint64 `json:"policy_seq"`
	Shares    int    `json:"shares,omitempty"`    // shares received so far (locked)
	Threshold int    `json:"threshold,omitempty"` // shares needed (locked, once a genesis doc came)
	GensOK    bool   `json:"gens_confirmed"`      // the register is open (false after a cold start until confirmed)
	// ConfirmNonce: while the register waits for confirmation (unlocked primary, gens_confirmed false), the nonce a
	// GenConfirm for this replica must name (32 bytes, hex). Single use: a new one after each confirmation.
	ConfirmNonce string `json:"confirm_nonce,omitempty"`
	SecretSeq    uint64 `json:"secrets_seq"` // the loaded secrets bundle's seq (0: none)
	LogSeq       uint64 `json:"log_seq"`
	LogHead      string `json:"log_head"`
	Refused      uint64 `json:"refused"` // refusals counted (not stored one by one) since start
}

// Challenge is GET /v1/challenge.
type Challenge struct {
	Nonce   string `json:"nonce"`   // 32 random bytes, hex
	Expires int64  `json:"expires"` // unix seconds
}

// ReleaseRequest is POST /v1/release.
type ReleaseRequest struct {
	Nonce string `json:"nonce"` // the challenge, hex
	// Attestation is proto.Attestation for Nonce. Its exact bytes are hashed into the reply's signature.
	Attestation json.RawMessage `json:"attestation"`
	Release     string          `json:"release"` // the VM's release version (vX.Y.Z); must equal the pinned one
	// ReleaseBundle is the release's Sigstore bundle, checked by kmsd's release bundle hook when one is configured.
	ReleaseBundle json.RawMessage `json:"release_bundle,omitempty"`
	Purposes      []string        `json:"purposes"`
	// Holder names the process whose lease this is ("agentd", "vaultd"; ValidHolder): each holds its own.
	Holder string `json:"holder"`
}

// Sealed is an HPKE ciphertext: the encapsulated key and the AEAD ciphertext.
type Sealed struct {
	Enc []byte `json:"enc"`
	CT  []byte `json:"ct"`
}

// Lease is one app holder's live instance.
type Lease struct {
	ID       string `json:"id"` // 16 random bytes, hex
	App      string `json:"app"`
	Holder   string `json:"holder"`
	Instance string `json:"instance"` // the attested instance-id event
	Key      string `json:"key"`      // the holder's boot key (hex X25519, bound in its quote): only it renews or re-takes the lease
	Seq      uint64 `json:"seq"`      // per app and holder, +1 each time the lease changes hands
	Expires  int64  `json:"expires"`  // unix seconds
}

// ReleaseReply is POST /v1/release's answer.
type ReleaseReply struct {
	Sealed Sealed `json:"sealed"` // ReleasePayload
	Sig    []byte `json:"sig"`    // KMS id over ReleaseSigMessage
	Lease  Lease  `json:"lease"`
	LogSeq uint64 `json:"log_seq"` // the audit entry recording this release
	KMSID  string `json:"kms_id"`
}

// ReleasePayload is what a release reply seals to the VM.
type ReleasePayload struct {
	App         string            `json:"app"`
	Firm        string            `json:"firm"`
	Release     string            `json:"release"`
	Epoch       uint32            `json:"epoch"`
	Keys        map[string][]byte `json:"keys"`              // purpose -> 32 bytes
	Secrets     map[string]string `json:"secrets,omitempty"` // the app's secrets from the bundle (SecretsPurpose only)
	Lease       Lease             `json:"lease"`
	LeaseSecret []byte            `json:"lease_secret"` // HMAC key for renewals and commits
	// Certs: for each released purpose of StorePurposes, the KMS id's StoreCert for its store-auth key.
	Certs map[string]StoreCert `json:"certs,omitempty"`
}

// LeaseRenew is POST /v1/lease/renew: MAC = LeaseMAC(secret, "renew", app, holder, lease id, at).
type LeaseRenew struct {
	App    string `json:"app"`
	Holder string `json:"holder"`
	Lease  string `json:"lease"`
	At     int64  `json:"at"` // unix seconds, within MaxClockSkew, and later than the last renewal
	MAC    []byte `json:"mac"`
}

// SignedLease is a lease and the KMS id's signature over LeaseSigMessage.
type SignedLease struct {
	Lease Lease  `json:"lease"`
	Sig   []byte `json:"sig"`
}

// LeaseMove (KindLeaseMove, signed by a Worker key the policy names) frees app's holder's lease ID, or hands it to
// Instance. Cloudflare holds that key: a move decides only which approved instance holds the lease next.
type LeaseMove struct {
	KMSID    string    `json:"kms_id"`
	Epoch    uint32    `json:"epoch"`
	App      string    `json:"app"`
	Holder   string    `json:"holder"`
	Lease    string    `json:"lease"`              // the lease being moved (a move for an older lease does nothing)
	Instance string    `json:"instance,omitempty"` // who may take it next ("": anyone)
	IssuedAt time.Time `json:"issued_at"`
}

// Gen is one entry of the generation register.
type Gen struct {
	App  string `json:"app"`
	Name string `json:"name"`
	Gen  uint64 `json:"gen"`
	Hash string `json:"hash"` // sha256 of the sealed blob, hex
}

// GenCommit is POST /v1/gen/commit, from the lease holder: MAC = CommitMAC(secret, ...). Stored false reserves Gen
// (the current + 1 once the current is stored; or the current again, with another hash, while it isn't); Stored
// true marks the current reservation (same gen and hash) as stored at the backend. Nonce (32 hex) comes back in
// the signed answer.
type GenCommit struct {
	Gen
	Holder string `json:"holder"`
	Stored bool   `json:"stored"`
	Nonce  string `json:"nonce"`
	Lease  string `json:"lease"`
	At     int64  `json:"at"`
	MAC    []byte `json:"mac"`
}

// SignedGen is a register entry, its state and the caller's nonce, signed by the KMS id (GenSigMessage).
type SignedGen struct {
	Gen    Gen    `json:"gen"`
	Prev   string `json:"prev"`   // the hash of generation Gen-1 ("" when unknown: gen 1, or confirmed after a cold start)
	Stored bool   `json:"stored"` // the VM said it stored this generation's blob (false: reserved only)
	Nonce  string `json:"nonce"`
	Sig    []byte `json:"sig"`
}

// SnapshotEntry is one register entry in a snapshot.
type SnapshotEntry struct {
	Gen    Gen    `json:"gen"`
	Prev   string `json:"prev"`
	Stored bool   `json:"stored"`
}

// Snapshot is the whole register at a time, as the KMS id signs it (kmsctl gen-snapshot keeps it offline; after a
// cold start kmsctl gen-doc builds the GenConfirm from it, so rollback protection doesn't rest on the Worker's view).
type Snapshot struct {
	KMSID   string          `json:"kms_id"`
	Epoch   uint32          `json:"epoch"`
	Time    int64           `json:"time"`
	LogSeq  uint64          `json:"log_seq"`
	Nonce   string          `json:"nonce"`
	Entries []SnapshotEntry `json:"entries"`
}

// SignedSnapshot is a Snapshot and the KMS id's signature over SnapshotSigMessage.
type SignedSnapshot struct {
	Snapshot Snapshot `json:"snapshot"`
	Sig      []byte   `json:"sig"`
}

// GenConfirm (KindGen, admin keys) sets the register after a cold start. It is taken only while the register waits
// (gens_confirmed false), names this replica's KMS id, epoch and confirm nonce (Status), and was issued within
// LeaseMoveTTL (and at most MaxClockSkew ahead). An empty list confirms there are none.
type GenConfirm struct {
	KMSID    string    `json:"kms_id"`
	Epoch    uint32    `json:"epoch"`
	Nonce    string    `json:"nonce"`
	Gens     []Gen     `json:"gens"`
	IssuedAt time.Time `json:"issued_at"`
}

// GenesisDoc (KindGenesis, admin keys) is the ceremony's input.
type GenesisDoc struct {
	Recipients     []string  `json:"recipients"` // "p256:<base64 SEC1 uncompressed>": one share each, in order
	Threshold      int       `json:"threshold"`  // shares needed to rebuild M
	AdminKeys      []string  `json:"admin_keys"` // "ed25519:<base64>": must be the replica's pinned admin keys
	AdminThreshold int       `json:"admin_threshold"`
	Peers          []string  `json:"peers,omitempty"` // replica URLs (informational)
	Floor          string    `json:"floor"`           // the lowest release any app may have keys for
	Target         string    `json:"target"`          // hex X25519 key of the replica's attestation: this boot only
	IssuedAt       time.Time `json:"issued_at"`
}

// GenesisRequest is POST /v1/genesis.
type GenesisRequest struct {
	Genesis safety.Envelope `json:"genesis"`
	Policy  safety.Envelope `json:"policy"`
}

// SealedShare is one Shamir share of M sealed to a recipient.
type SealedShare struct {
	Recipient string `json:"recipient"` // "p256:<base64>"
	Index     byte   `json:"index"`     // the share's x (1..n)
	Epoch     uint32 `json:"epoch"`
	KMSID     string `json:"kms_id"`
	Sealed
}

// GenesisReply is POST /v1/genesis's answer: each share goes to its recipient.
type GenesisReply struct {
	KMSID     string        `json:"kms_id"`
	Epoch     uint32        `json:"epoch"`
	Threshold int           `json:"threshold"`
	Shares    []SealedShare `json:"shares"`
	Sig       []byte        `json:"sig"` // KMS id over GenesisSigMessage
	// Commitments are ShareCommitment(kms id, index, epoch, share) for shares 1..n, and CommitSig the KMS id's
	// signature over CommitmentsSigMessage: a locked replica keeps only shares that match them (anyone can seal a
	// share to its public boot key; without these a junk share would spoil an unlock).
	Commitments []string `json:"commitments"`
	CommitSig   []byte   `json:"commit_sig"`
}

// UnlockRequest is POST /v1/unlock: one share, opened on its recipient's key and resealed to the replica's attested
// key (info LabelUnlock, aad ShareAAD). Genesis (and Policy, unless one is loaded) come with the first share.
type UnlockRequest struct {
	Genesis     *safety.Envelope `json:"genesis,omitempty"`
	Policy      *safety.Envelope `json:"policy,omitempty"`
	Commitments []string         `json:"commitments,omitempty"` // with the first share: GenesisReply's
	CommitSig   []byte           `json:"commit_sig,omitempty"`
	Index       byte             `json:"index"`
	Epoch       uint32           `json:"epoch"`
	Share       Sealed           `json:"share"`
}

// UnlockReply is POST /v1/unlock's answer.
type UnlockReply struct {
	State     string `json:"state"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
}

// JoinRequest is POST /v1/peer/join, from a peer that has no M.
type JoinRequest struct {
	Nonce       string          `json:"nonce"`       // a challenge of the replica asked
	Attestation json.RawMessage `json:"attestation"` // the joining peer's, for Nonce
	PeerNonce   string          `json:"peer_nonce"`  // the joining peer's own 32 random bytes (hex)
}

// JoinReply is POST /v1/peer/join's answer.
type JoinReply struct {
	Attestation json.RawMessage `json:"attestation"` // the replica's, for PeerNonce
	Policy      safety.Envelope `json:"policy"`      // so the peer can check the replica's attestation
	Sealed      Sealed          `json:"sealed"`      // JoinPayload, to the peer's attested key
	Sig         []byte          `json:"sig"`         // KMS id over JoinSigMessage
}

// JoinPayload is what a joining peer gets: M and the documents, never leases or the register (only the primary
// holds those; a joined primary waits for the admins' confirmation).
type JoinPayload struct {
	Master  []byte           `json:"master"`
	Epoch   uint32           `json:"epoch"`
	Genesis safety.Envelope  `json:"genesis"`
	Secrets []byte           `json:"secrets,omitempty"` // the sealed secrets bundle, if one is loaded
	Policy  *safety.Envelope `json:"policy,omitempty"`
}

// SecretsDoc (KindSecrets, admin keys) is the secrets bundle: names and values (our third-party API keys), for one
// KMS id and epoch.
type SecretsDoc struct {
	KMSID    string            `json:"kms_id"`
	Epoch    uint32            `json:"epoch"`
	Seq      uint64            `json:"seq"`
	Values   map[string]string `json:"values"`
	IssuedAt time.Time         `json:"issued_at"`
}

// SecretsPut is POST /v1/secrets/put: the admin-signed SecretsDoc envelope (JSON), sealed to the replica's
// attested key (info LabelSecretPut, aad the replica's KMS id string).
type SecretsPut struct {
	Sealed Sealed `json:"sealed"`
}

// SecretsLoad is POST /v1/secrets/load: a bundle a replica sealed under M (after a cold start). Its seq must be at
// least the policy's secrets_floor.
type SecretsLoad struct {
	Sealed []byte `json:"sealed"`
}

// SecretsReply: Sealed is secrets.sealed (store it anywhere: AES-256-GCM under HKDF(M, "secrets/v1")).
type SecretsReply struct {
	Seq    uint64   `json:"seq"`
	Names  []string `json:"names"`
	Sealed []byte   `json:"sealed"`
}

// AuditEntry is one link of the audit chain: Hash = AuditHash(entry), Sig = Ed25519 by the KMS id over
// AuditSigMessage(Hash).
type AuditEntry struct {
	Seq      uint64 `json:"seq"` // from 1
	Time     int64  `json:"time"`
	Kind     string `json:"kind"` // release, refuse, refused (a count), genesis, unlock, join, lease, policy, secrets, gen, ...
	OK       bool   `json:"ok"`
	App      string `json:"app,omitempty"`
	Instance string `json:"instance,omitempty"`
	Detail   string `json:"detail,omitempty"` // a reason or what changed (at most MaxDetail bytes, escaped); never key material
	Prev     string `json:"prev"`             // the previous entry's hash ("" for the first)
	Hash     string `json:"hash"`
	Sig      []byte `json:"sig,omitempty"` // empty only while the replica has no M yet (signed at unlock)
}

// Error is a refusal's body.
type Error struct {
	Error string `json:"error"`
}
