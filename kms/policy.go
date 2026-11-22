package kms

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// KMSFallbackRemoveBy is the date by which the KMS fallback is gone everywhere (the no-downtime plan row 27, the Fix B
// switch-over; review M2): kms_fallback out of every signed policy (the holders' unlock policy, the key service's),
// the fallback release's pin withdrawn, verifier.KMSRoots empty and pins.go KMSFallback deleted. While the fallback
// is accepted anywhere, the host chooses which approved release boots, and may restart the VM into the one keyed
// by its KMS. A placeholder until the owner sets the Fix B go-live; moving it later is a reviewed change.
var KMSFallbackRemoveBy = time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)

// CheckKMSFallbackRemoval refuses a policy that still sets kms_fallback at or after KMSFallbackRemoveBy. kmsctl runs
// it before it signs or approves any policy, and the agent VM's tests run the same date check on the tree
// (TestKMSFallbackRemovalGate). Holders and kmsd never run it: a check without a person would stop a running service
// on a date, against the no-downtime rule.
func CheckKMSFallbackRemoval(kmsFallback bool, at time.Time) error {
	if kmsFallback && !at.Before(KMSFallbackRemoveBy) {
		return fmt.Errorf("kms_fallback is still on after %s, the date it was to be removed by (the no-downtime plan row 27): drop it, "+
			"withdraw the fallback release, or move the date in a reviewed change", KMSFallbackRemoveBy.Format(time.DateOnly))
	}
	return nil
}

// Policy (KindPolicy, admin keys) is what kmsd releases to whom. Only a higher Seq replaces a loaded one.
type Policy struct {
	// KMSID and Epoch name the key service this policy is for; a replica refuses a policy for another. KMSID is ""
	// only in the policy that comes with genesis (the id doesn't exist yet; that policy is taken with the genesis
	// document only).
	KMSID    string    `json:"kms_id"`
	Epoch    uint32    `json:"epoch"`
	Seq      uint64    `json:"seq"`
	IssuedAt time.Time `json:"issued_at"`
	// Floor is the lowest release any app may have keys for (an app's own floor may be higher).
	Floor string               `json:"floor"`
	Apps  map[string]AppPolicy `json:"apps"`
	// Releases pin, per release, the sha256 of the whole app-compose.json it ships: a VM gets keys only
	// if its attested compose hash is one of these.
	Releases []ReleasePin `json:"releases"`
	// KMS pins the key service's own releases (its app-compose.json sha256s, each with its Role): what kmsctl and
	// peers accept. KMSFloor is the lowest of them any peer may run ("" = none).
	KMS      []ReleasePin `json:"kms"`
	KMSFloor string       `json:"kms_floor,omitempty"`
	// SecretsFloor is the lowest secrets bundle seq a replica loads (a cold start can't bring back revoked keys).
	SecretsFloor uint64 `json:"secrets_floor,omitempty"`
	// The OS trust list: allowed os-image-hash values, boot measurement sets and pre-launch scripts (sha256). nil
	// takes the verifier's compiled-in lists; an empty one allows nothing.
	OSImages  map[string]string `json:"os_images,omitempty"`
	Boot      []BootSet         `json:"boot,omitempty"`
	PreLaunch map[string]string `json:"pre_launch,omitempty"`
	// KMSFallback accepts a pinned app-compose.json that takes its CVM keys from a pinned dstack KMS root
	// (key_provider kms, nothing on the disk) besides keys made in the VM (key_provider none). The key service's
	// own CVM runs this way (the provider's gateway needs its KMS). KMSRoots are those roots (key-provider ids,
	// hex); nil takes the verifier's.
	KMSFallback bool              `json:"kms_fallback,omitempty"`
	KMSRoots    map[string]string `json:"kms_roots,omitempty"`
	// WorkerKeys may sign a LeaseMove ("ed25519:<base64>").
	WorkerKeys []string `json:"worker_keys,omitempty"`
	// AllowE2EDiag lets a pinned release that carries the end-to-end test's diag service (cmd/e2e overlay) have
	// keys. Staging only: a key service started without -staging refuses a policy that sets it.
	AllowE2EDiag bool `json:"allow_e2e_diag,omitempty"`
}

// AppPolicy is one app's grant.
type AppPolicy struct {
	Firm     string   `json:"firm"`              // part of every key's derivation
	Purposes []string `json:"purposes"`          // the purposes it may ask for (of Purposes)
	Secrets  []string `json:"secrets,omitempty"` // names from the secrets bundle it gets
	Floor    string   `json:"floor,omitempty"`   // its lowest release ("" = the policy's)
}

// ReleasePin is one signed release of an app (or of the KMS: App "kms").
type ReleasePin struct {
	App              string `json:"app"`
	Version          string `json:"version"`                  // vX.Y.Z
	ComposeSHA256    string `json:"compose_sha256,omitempty"` // the docker compose (the Sigstore release's subject)
	AppComposeSHA256 string `json:"app_compose_sha256"`       // the whole app-compose.json (the attested compose-hash)
	AppID            string `json:"app_id,omitempty"`         // when set, the attested app-id event must equal it
	// Role (key service pins only): RolePrimary ("" is primary) or RoleStandby; the attested kmsd -role must match.
	Role string `json:"role,omitempty"`
}

// BootSet is one allowed set of boot measurements (verifier.BootMeasurement's fields, hex).
type BootSet struct {
	Name    string `json:"name"`
	OSImage string `json:"os_image"`
	MRTD    string `json:"mrtd"`
	RTMR0   string `json:"rtmr0"`
	RTMR1   string `json:"rtmr1"`
	RTMR2   string `json:"rtmr2"`
}

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex96     = regexp.MustCompile(`^[0-9a-f]{96}$`)
	semverRe  = regexp.MustCompile(`^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	appNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)
	holderRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// ValidName is an app name, a secret name or a register name's syntax.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidHolder is a lease holder's syntax (a process name: "agentd", "vaultd").
func ValidHolder(s string) bool { return holderRe.MatchString(s) }

// PinRole is a key service pin's role ("" is the primary).
func (r ReleasePin) PinRole() string {
	if r.Role == "" {
		return RolePrimary
	}
	return r.Role
}

// CompareVersions compares two vX.Y.Z versions (-1, 0, 1); ok is false if either isn't one.
func CompareVersions(a, b string) (int, bool) {
	ma, mb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// Validate checks a policy's form.
func (p *Policy) Validate() error {
	if p.Seq == 0 {
		return errors.New("kms policy: seq must be > 0")
	}
	if p.Epoch == 0 {
		return errors.New("kms policy: epoch must be > 0")
	}
	if p.KMSID != "" {
		if _, err := ParseID(p.KMSID); err != nil {
			return fmt.Errorf("kms policy: kms_id: %w", err)
		}
	}
	if p.KMSFloor != "" && !semverRe.MatchString(p.KMSFloor) {
		return fmt.Errorf("kms policy: kms floor %q isn't vX.Y.Z", p.KMSFloor)
	}
	if !semverRe.MatchString(p.Floor) {
		return fmt.Errorf("kms policy: floor %q isn't vX.Y.Z", p.Floor)
	}
	for name, a := range p.Apps {
		if !appNameRe.MatchString(name) || name == "kms" {
			return fmt.Errorf("kms policy: bad app name %q", name)
		}
		if a.Firm == "" || !ValidName(a.Firm) {
			return fmt.Errorf("kms policy: app %s: bad firm", name)
		}
		if len(a.Purposes) == 0 {
			return fmt.Errorf("kms policy: app %s has no purposes", name)
		}
		for _, pu := range a.Purposes {
			if !slices.Contains(Purposes, pu) {
				return fmt.Errorf("kms policy: app %s: unknown purpose %q", name, pu)
			}
		}
		for _, s := range a.Secrets {
			if !ValidName(s) {
				return fmt.Errorf("kms policy: app %s: bad secret name %q", name, s)
			}
		}
		if a.Floor != "" && !semverRe.MatchString(a.Floor) {
			return fmt.Errorf("kms policy: app %s: floor %q isn't vX.Y.Z", name, a.Floor)
		}
	}
	seen := map[string]bool{} // across both lists: one app-compose is one release of one thing
	check := func(what string, pins []ReleasePin, kms bool) error {
		for _, r := range pins {
			if kms != (r.App == "kms") {
				return fmt.Errorf("kms policy: %s pin for app %q", what, r.App)
			}
			if _, ok := p.Apps[r.App]; !kms && !ok {
				return fmt.Errorf("kms policy: release pin for unknown app %q", r.App)
			}
			if !semverRe.MatchString(r.Version) {
				return fmt.Errorf("kms policy: %s pin version %q isn't vX.Y.Z", what, r.Version)
			}
			if !hex64.MatchString(r.AppComposeSHA256) || (r.ComposeSHA256 != "" && !hex64.MatchString(r.ComposeSHA256)) {
				return fmt.Errorf("kms policy: %s pin %s %s: hashes must be 64 lowercase hex", what, r.App, r.Version)
			}
			if (!kms && r.Role != "") || (kms && r.Role != "" && r.Role != RolePrimary && r.Role != RoleStandby) {
				return fmt.Errorf("kms policy: %s pin %s %s: bad role %q", what, r.App, r.Version, r.Role)
			}
			if seen[r.AppComposeSHA256] {
				return fmt.Errorf("kms policy: app-compose %s pinned twice", r.AppComposeSHA256)
			}
			seen[r.AppComposeSHA256] = true
		}
		return nil
	}
	if err := check("release", p.Releases, false); err != nil {
		return err
	}
	if err := check("kms", p.KMS, true); err != nil {
		return err
	}
	for h := range p.OSImages {
		if !hex64.MatchString(h) {
			return fmt.Errorf("kms policy: os image %q isn't 64 hex", h)
		}
	}
	for h := range p.KMSRoots {
		if _, err := hex.DecodeString(h); err != nil || h == "" || strings.ToLower(h) != h {
			return fmt.Errorf("kms policy: KMS root %q isn't lowercase hex", h)
		}
	}
	for h := range p.PreLaunch {
		if !hex64.MatchString(h) {
			return fmt.Errorf("kms policy: pre-launch %q isn't 64 hex", h)
		}
	}
	for _, b := range p.Boot {
		if !hex64.MatchString(b.OSImage) || !hex96.MatchString(b.MRTD) || !hex96.MatchString(b.RTMR0) ||
			!hex96.MatchString(b.RTMR1) || !hex96.MatchString(b.RTMR2) {
			return fmt.Errorf("kms policy: boot set %q: bad hex", b.Name)
		}
	}
	for _, k := range p.WorkerKeys {
		if _, err := ParseID(k); err != nil {
			return fmt.Errorf("kms policy: worker key: %w", err)
		}
	}
	return nil
}

// Validate checks a genesis document's form (not its signatures).
func (g *GenesisDoc) Validate() error {
	n := len(g.Recipients)
	if n < 1 || n > 255 || g.Threshold < 1 || g.Threshold > n {
		return fmt.Errorf("kms genesis: %d-of-%d isn't a valid split", g.Threshold, n)
	}
	seen := map[string]bool{}
	for _, r := range g.Recipients {
		if _, err := ParseRecipient(r); err != nil {
			return err
		}
		if seen[r] {
			return errors.New("kms genesis: a recipient is listed twice")
		}
		seen[r] = true
	}
	if len(g.AdminKeys) == 0 || g.AdminThreshold < 1 || g.AdminThreshold > len(g.AdminKeys) {
		return errors.New("kms genesis: admin keys and threshold")
	}
	for _, k := range g.AdminKeys {
		if _, err := ParseID(k); err != nil {
			return err
		}
	}
	if !semverRe.MatchString(g.Floor) {
		return fmt.Errorf("kms genesis: floor %q isn't vX.Y.Z", g.Floor)
	}
	return nil
}

// AdminKeys is the set of keys allowed to sign admin documents and how many must.
type AdminKeys struct {
	Keys      []ed25519.PublicKey
	Threshold int
}

// Open checks e is of kind and signed by at least Threshold of the keys, then decodes its payload strictly into v.
func (a AdminKeys) Open(e *safety.Envelope, kind string, v any) error {
	if e == nil || e.Kind != kind {
		return fmt.Errorf("kms: want a %s document", kind)
	}
	if a.Threshold < 1 || len(a.Keys) == 0 {
		return errors.New("kms: no admin keys")
	}
	if n := Signers(e, a.Keys); n < a.Threshold {
		return fmt.Errorf("kms: %s document has %d of %d admin signatures", kind, n, a.Threshold)
	}
	return Strict(e.Payload, v)
}

// Signers is how many distinct keys of trusted made a valid signature on e, over what safety.Sign signs:
// "tacy-safety/v1" ‖ 0 ‖ kind ‖ 0 ‖ payload. (safety's own count is unexported; it's done here rather than exported
// there so the VM's binaries, which embed safety, stay byte for byte the same. TestAdminOpen checks the two agree.)
func Signers(e *safety.Envelope, trusted []ed25519.PublicKey) int {
	msg := make([]byte, 0, 32+len(e.Kind)+len(e.Payload))
	msg = append(msg, "tacy-safety/v1\x00"...)
	msg = append(msg, e.Kind...)
	msg = append(msg, 0)
	msg = append(msg, e.Payload...)
	seen := map[string]bool{}
	for _, s := range e.Sigs {
		k, err := safety.ParseKey(s.Key)
		if err != nil || seen[string(k)] || len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		for _, t := range trusted {
			if bytes.Equal(t, k) && ed25519.Verify(t, msg, s.Sig) {
				seen[string(k)] = true
				break
			}
		}
	}
	return len(seen)
}

// SameKeys reports whether the strings name exactly keys (any order).
func (a AdminKeys) SameKeys(strs []string, threshold int) bool {
	if len(strs) != len(a.Keys) || threshold != a.Threshold {
		return false
	}
	for _, s := range strs {
		k, err := ParseID(s)
		if err != nil || !slices.ContainsFunc(a.Keys, func(x ed25519.PublicKey) bool { return bytes.Equal(x, k) }) {
			return false
		}
	}
	return true
}

// Strict decodes JSON with unknown members and trailing data refused.
func Strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("kms: trailing data after the JSON value")
	}
	return nil
}

// AppCompose reads the (unverified) app-compose.json from a dstack Info: info.tcb_info.app_compose.
func AppCompose(info json.RawMessage) ([]byte, error) {
	var i struct {
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	if err := json.Unmarshal(info, &i); err != nil {
		return nil, errors.New("kms: attestation info isn't JSON")
	}
	var s string
	if json.Unmarshal(i.TcbInfo, &s) == nil {
		i.TcbInfo = []byte(s)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	if json.Unmarshal(i.TcbInfo, &tcb) != nil || tcb.AppCompose == "" {
		return nil, errors.New("kms: attestation has no app-compose.json")
	}
	return []byte(tcb.AppCompose), nil
}

// DockerCompose is the docker compose inside an app-compose.json.
func DockerCompose(appCompose []byte) (string, error) {
	var ac struct {
		DockerComposeFile string `json:"docker_compose_file"`
	}
	if err := json.Unmarshal(appCompose, &ac); err != nil || strings.TrimSpace(ac.DockerComposeFile) == "" {
		return "", errors.New("kms: app-compose.json has no docker compose")
	}
	return ac.DockerComposeFile, nil
}
