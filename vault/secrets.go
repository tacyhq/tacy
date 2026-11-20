package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pushed secrets (keys plan §3.6 Stage A, the "quick path"): nothing comes from Phala's encrypted env. The
// chat Worker verifies the VM's attestation with the same verifier the browser runs, asks agentd (over EHBP, so the
// answer comes from the attested VM) for this vault's per-boot secrets key, seals the API keys to it and signs the
// box with the operator key the compose pins. Only this process opens the box; the keys stay in its memory and are
// gone with it. Until a push arrives, agentd answers "starting".
//
// The box (HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, info SecretsLabel):
//
//	plaintext  {"type":"tacy.vm-secrets/v1","secrets":{"TINFOIL_API_KEY":"…",…},"token":"<AGENT_VM_TOKEN>"}
//	aad        SecretsLabel ‖ 0 ‖ key ‖ 0 ‖ decimal(at)
//
// The signature: Ed25519 by the operator key over SecretsPushLabel ‖ 0 ‖ key ‖ 0 ‖ decimal(at) ‖ 0 ‖
// hex(sha256(enc)) ‖ 0 ‖ hex(sha256(ct)). A box sealed to another boot's key doesn't open (stale_key); one signed
// by anyone else (Phala could seal its own keys to the public key and so read our users' search queries in its
// own provider account) is refused. "at" is the Worker's clock, kept within SecretsMaxSkew of this one.

const (
	SecretsLabel     = "tacy/v2/secrets"
	SecretsPushLabel = "tacy/v2/secrets-push/v1"
	SecretsType      = "tacy.vm-secrets/v1"
	SecretsMaxSkew   = 15 * time.Minute
)

// SecretsPush is the push as agentd passes it on (its JSON is the body of POST /secrets).
type SecretsPush struct {
	Key string `json:"key"` // "x25519:<base64>": the vault's secrets key it was sealed to
	Enc []byte `json:"enc"`
	CT  []byte `json:"ct"`
	At  int64  `json:"at"`  // unix seconds, the signer's clock
	Sig []byte `json:"sig"` // Ed25519 by the operator key (SecretsSignedBytes)
}

// SecretsResult is the vault's answer: the names it took (never values) and sha256 of the run token, which agentd
// checks the relay's bearer token against.
type SecretsResult struct {
	Names       []string `json:"names"`
	TokenSHA256 string   `json:"token_sha256"`
}

type secretsBox struct {
	Type    string            `json:"type"`
	Secrets map[string]string `json:"secrets"`
	Token   string            `json:"token"`
}

// Errors of a push.
var (
	ErrSecretsOff     = errors.New("vault: secrets push is off")
	ErrSecretsSig     = errors.New("vault: the secrets push isn't signed by the pinned key")
	ErrSecretsStale   = errors.New("vault: the secrets push is sealed to another boot's key")
	ErrSecretsTime    = errors.New("vault: the secrets push's time is off")
	ErrSecretsSealed  = errors.New("vault: the secrets box didn't open or isn't valid")
	errSecretsInvalid = []error{ErrSecretsOff, ErrSecretsSig, ErrSecretsStale, ErrSecretsTime, ErrSecretsSealed}
)

type pushState struct {
	mu     sync.Mutex
	key    *ecdh.PrivateKey
	pub    string
	signer ed25519.PublicKey
	token  [32]byte // sha256 of the run token (zero: none yet)
}

// EnableSecretsPush makes this boot's secrets key and pins signer (the operator key from the compose) as the only
// key whose pushes are taken. Without it every push is refused.
func (v *Vault) EnableSecretsPush(signer ed25519.PublicKey) error {
	if len(signer) != ed25519.PublicKeySize {
		return errors.New("vault: secrets push needs the pinned operator key")
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.push = &pushState{key: k, pub: "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), signer: signer}
	return nil
}

func (v *Vault) pushState() *pushState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.push
}

// SecretsKey is this boot's secrets key ("" when pushes are off).
func (v *Vault) SecretsKey() string {
	if p := v.pushState(); p != nil {
		return p.pub
	}
	return ""
}

// SecretsSignedBytes are the bytes the operator key signs for a push.
func SecretsSignedBytes(key string, at int64, enc, ct []byte) []byte {
	he, hc := sha256.Sum256(enc), sha256.Sum256(ct)
	return []byte(SecretsPushLabel + "\x00" + key + "\x00" + strconv.FormatInt(at, 10) + "\x00" + hex.EncodeToString(he[:]) +
		"\x00" + hex.EncodeToString(hc[:]))
}

// SecretsAAD is a box's associated data.
func SecretsAAD(key string, at int64) []byte {
	return []byte(SecretsLabel + "\x00" + key + "\x00" + strconv.FormatInt(at, 10))
}

// PutSecrets checks a push and takes its secrets: only names granted to a connector, each replacing the value
// before (a later push rotates them). It returns the names it holds and sha256 of the run token.
func (v *Vault) PutSecrets(p SecretsPush) (SecretsResult, error) {
	ps := v.pushState()
	if ps == nil {
		return SecretsResult{}, ErrSecretsOff
	}
	if !ed25519.Verify(ps.signer, SecretsSignedBytes(p.Key, p.At, p.Enc, p.CT), p.Sig) {
		v.recordSecrets("signature")
		return SecretsResult{}, ErrSecretsSig
	}
	if p.Key != ps.pub {
		v.recordSecrets("stale_key")
		return SecretsResult{}, ErrSecretsStale
	}
	if d := v.now().Sub(time.Unix(p.At, 0)); d > SecretsMaxSkew || d < -SecretsMaxSkew {
		v.recordSecrets("time")
		return SecretsResult{}, ErrSecretsTime
	}
	hk, err := hpke.NewDHKEMPrivateKey(ps.key)
	if err != nil {
		return SecretsResult{}, err
	}
	rc, err := hpke.NewRecipient(p.Enc, hk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(SecretsLabel))
	if err != nil {
		v.recordSecrets("sealed")
		return SecretsResult{}, ErrSecretsSealed
	}
	pt, err := rc.Open(SecretsAAD(p.Key, p.At), p.CT)
	if err != nil {
		v.recordSecrets("sealed")
		return SecretsResult{}, ErrSecretsSealed
	}
	defer clear(pt)
	var b secretsBox
	if json.Unmarshal(bytes.TrimRight(pt, " "), &b, json.RejectUnknownMembers(true)) != nil || b.Type != SecretsType ||
		len(b.Token) < 16 || len(b.Token) > 256 || len(b.Secrets) == 0 {
		v.recordSecrets("sealed")
		return SecretsResult{}, ErrSecretsSealed
	}
	v.mu.Lock()
	for name, val := range b.Secrets {
		granted := slices.ContainsFunc(v.grants, func(g Grant) bool { return g.Secret == name })
		if !validName(name) || !granted || val == "" || len(val) > 4096 || name == ConnSecret {
			v.mu.Unlock()
			v.recordSecrets("sealed")
			return SecretsResult{}, ErrSecretsSealed
		}
	}
	for name, val := range b.Secrets {
		if old, ok := v.secrets[name]; ok {
			clear(old)
		}
		v.secrets[name] = []byte(val)
	}
	v.mu.Unlock()
	tok := sha256.Sum256([]byte(b.Token))
	ps.mu.Lock()
	ps.token = tok
	ps.mu.Unlock()
	v.recordSecrets("")
	return SecretsResult{Names: v.Names(), TokenSHA256: hex.EncodeToString(tok[:])}, nil
}

// SecretsStatus is what a push left: the names held and the token hash ("" before the first push).
func (v *Vault) SecretsStatus() SecretsResult {
	r := SecretsResult{Names: v.Names()}
	if ps := v.pushState(); ps != nil {
		ps.mu.Lock()
		if ps.token != ([32]byte{}) {
			r.TokenSHA256 = hex.EncodeToString(ps.token[:])
		}
		ps.mu.Unlock()
	}
	return r
}

// recordSecrets writes a push's decision (names only, never a value).
func (v *Vault) recordSecrets(reason string) {
	if v.record == nil {
		return
	}
	d := "taken"
	if reason != "" {
		d = "denied"
	}
	v.record(Record{Time: v.now().UTC(), Secret: "", Connector: "secrets_push", Decision: d, Reason: reason})
}

// SealSecrets builds a signed push to the vault key pub (the chat Worker's job; tests and cmd/e2e).
func SealSecrets(pub string, at int64, secrets map[string]string, token string, sign func([]byte) []byte) (SecretsPush, error) {
	raw, ok := strings.CutPrefix(pub, "x25519:")
	b, err := base64.StdEncoding.DecodeString(raw)
	if !ok || err != nil {
		return SecretsPush{}, errors.New("vault: bad secrets key")
	}
	pk, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return SecretsPush{}, err
	}
	hp, err := hpke.NewDHKEMPublicKey(pk)
	if err != nil {
		return SecretsPush{}, err
	}
	enc, sender, err := hpke.NewSender(hp, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(SecretsLabel))
	if err != nil {
		return SecretsPush{}, err
	}
	pt, err := json.Marshal(secretsBox{Type: SecretsType, Secrets: secrets, Token: token})
	if err != nil {
		return SecretsPush{}, err
	}
	defer clear(pt)
	ct, err := sender.Seal(SecretsAAD(pub, at), pt)
	if err != nil {
		return SecretsPush{}, err
	}
	return SecretsPush{Key: pub, Enc: enc, CT: ct, At: at, Sig: sign(SecretsSignedBytes(pub, at, enc, ct))}, nil
}

// TokenMatches reports, in constant time, whether token's sha256 is tokenSHA256 (hex).
func TokenMatches(tokenSHA256, token string) bool {
	want, err := hex.DecodeString(tokenSHA256)
	if err != nil || len(want) != sha256.Size || token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
