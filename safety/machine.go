package safety

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"
)

// The machine allowlist (V1-DESIGN §3, enforced from launch): a quote counts only when the machine that signed it
// (the PPID and FMSPC in its PCK certificate, which chains to Intel) is named by a machine certificate.
//
// What it stops, and what it doesn't (stated plainly, review H3): it stops a quote forged on any machine outside
// the list, such as an outsider's own TDX machine with an interposer (TEE.fail, DDRop). It does NOT stop the host:
// Phala, or anyone with physical access to prod5 or prod9, can take that machine's PCK key and forge quotes that
// carry its PPID from anywhere, which gives every holder's share and so R_e and all content. That is TDX's
// remaining risk with this host; the holders' unlock events (PPID, instance) are detection, not prevention.
//
// A machine certificate is signed by the KMS id (whose key derives only from M: two of the KMS admin's passphrase
// shares), not by an admin key, and names no policy seq: so an admin key alone can't add a machine, and a
// certificate survives every later policy and trust list that carries it (review M2). It is carried in the holders'
// unlock policy (machine_certs) and in the trust list's optional members (machine_certs; older apps ignore them,
// the no-downtime plan principle 3). Revocations (machines_revoked: certificate hashes) are permanent: each holder keeps every
// hash it has seen in its store, each client the union of every list it has taken, so a newer document that leaves
// a hash out revokes nothing back (second review N8). An admin key alone can revoke, never re-allow: re-allowing
// needs a new certificate (a new issued_at, so a new hash), so the passphrase shares again.
//
// There is no 24 h delay and no policy item for a certificate (decided for v1): every addition already needs
// the KMS id, and a node move takes minutes.

// MachineType names the machine certificate format.
const MachineType = "tacy.machine/v1"

// sigMachine is the KMS id's Ed25519 label for a machine certificate: label ‖ 0 ‖ doc.
const sigMachine = "tacy-split/machine/v1"

// Machine modes and hosts.
const (
	MachineModePPID     = "ppid"         // one machine: its PPID and FMSPC
	MachineModeRegistry = "gcp-registry" // Google Cloud: any host in Google's confidential-host registry, one project
	MachineHostPhala    = "phala"
	MachineHostGoogle   = "google"
)

// The trust list's optional members that carry the machine allowlist.
const (
	TrustMachineCertsMember    = "machine_certs"    // a JSON array of SignedMachineCert
	TrustMachinesRevokedMember = "machines_revoked" // a JSON array of certificate hashes (MachineHash)
)

// MaxMachineCerts and MaxMachinesRevoked bound a document's lists (a trust list's optional member is at most 8 KiB:
// about 14 certificates).
const (
	MaxMachineCerts    = 16
	MaxMachinesRevoked = 64
	// MaxRevokedKept bounds a client's kept union of revocations (TrustSeen.RevokedMachines).
	MaxRevokedKept = 1024
)

// MachineDoc is one machine certificate's content.
type MachineDoc struct {
	Type     string `json:"type"`
	KMSID    string `json:"kms_id"`
	Platform string `json:"platform"` // "dstack"
	Host     string `json:"host"`     // "phala", "google"
	Mode     string `json:"mode"`     // MachineModePPID or MachineModeRegistry
	// PPID (16 bytes) and FMSPC (6 bytes), lowercase hex, as in the PCK certificate's SGX extension. Registry mode
	// names no PPID (Google's registry lists the hosts) and one FMSPC per certificate (a machine family: c3, c4).
	PPID  string `json:"ppid,omitzero"`
	FMSPC string `json:"fmspc"`
	// ProjectNumber (registry mode only): the Google Cloud project whose VMs count; the quote's MR_OWNER must be
	// sha384 of the PZID JSON for this project (Google writes it).
	ProjectNumber string    `json:"project_number,omitzero"`
	Label         string    `json:"label"` // "phala prod5"
	IssuedAt      time.Time `json:"issued_at"`
}

// SignedMachineCert is a MachineDoc's exact JSON (its canonical form: MarshalMachineDoc) and the KMS id's signature
// over sigMachine ‖ 0 ‖ doc. Doc is bytes (base64 in JSON), so re-encoding the outer JSON never changes what was
// signed, and its hash is the certificate's name in revocations.
type SignedMachineCert struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

var (
	hex32        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex12        = regexp.MustCompile(`^[0-9a-f]{12}$`)
	projectNumRe = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// Validate checks a machine document's form.
func (d *MachineDoc) Validate() error {
	if d.Type != MachineType || d.Platform != PlatformDstack || d.IssuedAt.IsZero() || !trustNameRe.MatchString(d.Label) {
		return fmt.Errorf("machine certificate: type %s, platform dstack, a label and its issue time are required", MachineType)
	}
	if _, err := ParseKey(d.KMSID); err != nil || KeyString(mustKey(d.KMSID)) != d.KMSID {
		return errors.New("machine certificate: bad kms_id")
	}
	if !hex12.MatchString(d.FMSPC) {
		return errors.New("machine certificate: fmspc must be 6 bytes of lowercase hex")
	}
	switch d.Mode {
	case MachineModePPID:
		if !hex32.MatchString(d.PPID) || d.ProjectNumber != "" || (d.Host != MachineHostPhala && d.Host != MachineHostGoogle) {
			return errors.New("machine certificate: ppid mode names a host, a 16-byte lowercase hex ppid and no project")
		}
	case MachineModeRegistry:
		if d.Host != MachineHostGoogle || d.PPID != "" || !projectNumRe.MatchString(d.ProjectNumber) {
			return errors.New("machine certificate: gcp-registry mode is host google, a project number and no ppid")
		}
	default:
		return fmt.Errorf("machine certificate: unknown mode %q", d.Mode)
	}
	return nil
}

// MarshalMachineDoc is a document's canonical JSON: what is signed and hashed.
func MarshalMachineDoc(d MachineDoc) ([]byte, error) {
	d.IssuedAt = d.IssuedAt.UTC()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// MachineHash names a certificate in revocations: sha256(sigMachine ‖ 0 ‖ doc), hex. The signature isn't in it, so
// a compiled-in document (verifier.MachineDocs) and the KMS-signed certificate of the same bytes are one machine.
func MachineHash(doc []byte) string {
	h := sha256.Sum256(append(append([]byte(sigMachine), 0), doc...))
	return hex.EncodeToString(h[:])
}

// MachineDocHash is MachineHash of a document's canonical JSON.
func MachineDocHash(d MachineDoc) (string, error) {
	b, err := MarshalMachineDoc(d)
	if err != nil {
		return "", err
	}
	return MachineHash(b), nil
}

// SignMachineCert signs d with the KMS id's private key (kmsctl machine-cert: M from two passphrase shares). d's
// kms_id is set from the key.
func SignMachineCert(kmsID ed25519.PrivateKey, d MachineDoc) (*SignedMachineCert, error) {
	d.KMSID = KeyString(kmsID.Public().(ed25519.PublicKey))
	doc, err := MarshalMachineDoc(d)
	if err != nil {
		return nil, err
	}
	return &SignedMachineCert{Doc: doc, Sig: ed25519.Sign(kmsID, append(append([]byte(sigMachine), 0), doc...))}, nil
}

// Hash is the certificate's MachineHash.
func (c SignedMachineCert) Hash() string { return MachineHash(c.Doc) }

// Open checks kmsID signed c over its canonical document and returns the document. An admin key can't make one.
func (c SignedMachineCert) Open(kmsID ed25519.PublicKey) (*MachineDoc, error) {
	if len(kmsID) != ed25519.PublicKeySize || len(c.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kmsID, append(append([]byte(sigMachine), 0), c.Doc...), c.Sig) {
		return nil, errors.New("machine certificate isn't signed by the KMS id (it takes two passphrase shares)")
	}
	var d MachineDoc
	if err := strict(c.Doc, &d); err != nil {
		return nil, fmt.Errorf("machine certificate: %w", err)
	}
	canon, err := MarshalMachineDoc(d)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, c.Doc) {
		return nil, errors.New("machine certificate: the document isn't in its canonical form")
	}
	if d.KMSID != KeyString(kmsID) {
		return nil, errors.New("machine certificate is for another KMS id")
	}
	return &d, nil
}

// Machine is one allowed machine: its document, its hash and where it came from (for the facts).
type Machine struct {
	Doc    MachineDoc
	Hash   string
	Source string // "built in", "unlock policy 12", "trust list 7"
}

// MachineSet is what a verifier accepts: the machines, minus the revoked hashes.
type MachineSet struct {
	Machines []Machine
	Revoked  map[string]bool
}

// ErrMachineNotAllowed is the machine check's refusal (errors.Is).
var ErrMachineNotAllowed = errors.New("machine isn't one Tacy approved")

// Match is the PPID-mode machine for ppid and fmspc, unrevoked; else an error naming why.
func (s *MachineSet) Match(ppid, fmspc string) (*Machine, error) {
	if s == nil || len(s.Machines) == 0 {
		return nil, fmt.Errorf("%w: no machine certificates", ErrMachineNotAllowed)
	}
	if !hex32.MatchString(ppid) || !hex12.MatchString(fmspc) {
		return nil, fmt.Errorf("%w: the quote names no PPID and FMSPC (ppid %q, fmspc %q)", ErrMachineNotAllowed, ppid, fmspc)
	}
	revoked := false
	for i, m := range s.Machines {
		if m.Doc.Mode != MachineModePPID || m.Doc.PPID != ppid {
			continue
		}
		if s.Revoked[m.Hash] {
			revoked = true
			continue
		}
		if m.Doc.FMSPC != fmspc {
			return nil, fmt.Errorf("%w: platform %s is %s, but its certificate names FMSPC %s", ErrMachineNotAllowed, ppid, fmspc, m.Doc.FMSPC)
		}
		return &s.Machines[i], nil
	}
	if revoked {
		return nil, fmt.Errorf("%w: platform %s's certificate is revoked (permanent; re-allowing needs a new certificate)", ErrMachineNotAllowed, ppid)
	}
	return nil, fmt.Errorf("%w: platform %s (FMSPC %s) has no machine certificate", ErrMachineNotAllowed, ppid, fmspc)
}

// Registry are the unrevoked registry-mode machines for fmspc.
func (s *MachineSet) Registry(fmspc string) []Machine {
	if s == nil {
		return nil
	}
	var out []Machine
	for _, m := range s.Machines {
		if m.Doc.Mode == MachineModeRegistry && m.Doc.FMSPC == fmspc && !s.Revoked[m.Hash] {
			out = append(out, m)
		}
	}
	return out
}

// Allows says whether a quote naming ppid and fmspc can pass: a PPID-mode match, or a registry-mode machine for
// fmspc (its registry and MR_OWNER checks come later, after the Intel chain). The holders' pre-gate runs it before
// any collateral.
func (s *MachineSet) Allows(ppid, fmspc string) error {
	if _, err := s.Match(ppid, fmspc); err == nil {
		return nil
	} else if len(s.Registry(fmspc)) == 0 {
		return err
	}
	return nil
}

// FMSPCs are the FMSPCs of the unrevoked machines, sorted (the collateral the holders' cron keeps).
func (s *MachineSet) FMSPCs() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, m := range s.Machines {
		if !s.Revoked[m.Hash] {
			out = append(out, m.Doc.FMSPC)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// HasRegistry says whether any unrevoked machine is registry mode.
func (s *MachineSet) HasRegistry() bool {
	return s != nil && slices.ContainsFunc(s.Machines, func(m Machine) bool { return m.Doc.Mode == MachineModeRegistry && !s.Revoked[m.Hash] })
}

// ValidRevocations checks a revocation list: at most MaxMachinesRevoked distinct lowercase sha256 hashes.
func ValidRevocations(hashes []string) error {
	if len(hashes) > MaxMachinesRevoked {
		return fmt.Errorf("machines_revoked: at most %d", MaxMachinesRevoked)
	}
	seen := map[string]bool{}
	for _, h := range hashes {
		if !hex64.MatchString(h) || seen[h] {
			return fmt.Errorf("machines_revoked: bad or repeated hash %q", h)
		}
		seen[h] = true
	}
	return nil
}

// OpenMachineCerts opens every certificate under kmsID (any that doesn't verify refuses the whole document, as a bad
// share set or emergency override does) and returns the set without the revoked hashes' machines counted. A
// Google certificate (registry mode, or one Google host) is refused unless registryOK (the document names the Google
// fallback): V1-DESIGN §2.7, no Google certificate while the VM runs on Phala, so only one host can forge.
func OpenMachineCerts(kmsID ed25519.PublicKey, certs []SignedMachineCert, revoked []string, registryOK bool, source string) (*MachineSet, error) {
	if len(certs) > MaxMachineCerts {
		return nil, fmt.Errorf("machine_certs: at most %d", MaxMachineCerts)
	}
	if err := ValidRevocations(revoked); err != nil {
		return nil, err
	}
	s := &MachineSet{Revoked: map[string]bool{}}
	for _, h := range revoked {
		s.Revoked[h] = true
	}
	for i, c := range certs {
		d, err := c.Open(kmsID)
		if err != nil {
			return nil, fmt.Errorf("machine_certs[%d]: %w", i, err)
		}
		if d.Host == MachineHostGoogle && !registryOK {
			return nil, fmt.Errorf("machine_certs[%d]: a Google certificate (%s) is allowed only while the Google fallback runs (the document must name platform dstack-gcp)", i, d.Mode)
		}
		h := c.Hash()
		if slices.ContainsFunc(s.Machines, func(m Machine) bool { return m.Hash == h }) {
			return nil, fmt.Errorf("machine_certs[%d]: listed twice", i)
		}
		s.Machines = append(s.Machines, Machine{Doc: *d, Hash: h, Source: source})
	}
	return s, nil
}

// TrustMachines reads a trust list's optional machine members, unchecked: present says whether the list carries
// machine_certs (then binding for a client that knows them; else the build's own). An unreadable member is an
// error (the list is refused).
func (l *TrustList) TrustMachines() (certs []SignedMachineCert, revoked []string, present bool, err error) {
	if raw, ok := l.Optional[TrustMachineCertsMember]; ok {
		present = true
		if err := strict(raw, &certs); err != nil {
			return nil, nil, true, fmt.Errorf("trust list %d: machine_certs: %w", l.Seq, err)
		}
	}
	if raw, ok := l.Optional[TrustMachinesRevokedMember]; ok {
		if err := strict(raw, &revoked); err != nil {
			return nil, nil, present, fmt.Errorf("trust list %d: machines_revoked: %w", l.Seq, err)
		}
		if err := ValidRevocations(revoked); err != nil {
			return nil, nil, present, fmt.Errorf("trust list %d: %w", l.Seq, err)
		}
	}
	return certs, revoked, present, nil
}

// SetMachines puts the machine certificates and revocations into l's optional members (before l is signed).
// Revocations only grow: kmsctl carries every earlier one forward.
func (l *TrustList) SetMachines(certs []SignedMachineCert, revoked []string) error {
	cb, err := json.Marshal(certs)
	if err != nil {
		return err
	}
	if revoked == nil {
		revoked = []string{}
	}
	rb, err := json.Marshal(revoked)
	if err != nil {
		return err
	}
	if l.Optional == nil {
		l.Optional = map[string]jsontext.Value{}
	}
	l.Optional[TrustMachineCertsMember] = jsontext.Value(cb)
	l.Optional[TrustMachinesRevokedMember] = jsontext.Value(rb)
	return nil
}
