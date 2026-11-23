package verifier

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/tacyhq/tacy/internal/gcetcb"
	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The machine allowlist (V1-DESIGN §3; safety/machine.go has the format and the rules). Checked right after the
// Intel chain and the TCB: the PPID and FMSPC of the PCK certificate whose chain to Intel was just verified must be
// a valid, unrevoked machine certificate's.
//
// IT STOPS OUTSIDERS' FORGED QUOTES, NOT THE HOST. A quote made with a PCK key taken from any machine outside the
// list is refused here. A quote forged by Phala, or by anyone with physical access to prod5 or prod9 (a PCK key
// taken from that machine signs with its PPID, from anywhere), passes, and with it every holder's share: that is
// TDX's remaining risk with this host. The facts say so on every verification (FactMachine).
//
// Where the machines come from:
//   - a client (the browser's WASM, the apps, the chat Worker, cmd/e2e): a signed trust list's
//     optional.machine_certs when the list carries them (binding then), else MachineDocs, the build's own; minus
//     every revocation it has ever taken (TrustSeen.RevokedMachines) and MachinesRevoked;
//   - a holder: its signed unlock policy's machine_certs only (never the built-in ones), minus the policy's
//     machines_revoked and every hash its store has kept (kms/split/holder).

// MachineCheck is the allowlist check's name. Clients map its "machine:" prefix to "machine" (verifier-core.ts).
const MachineCheck = "machine: the quote's signing platform (PPID and FMSPC of its Intel PCK certificate) has a machine certificate"

// FactMachine is the verification fact that names the machine and says what the list doesn't defend against.
const FactMachine = "machine"

// MachineIssuedAt is the built-in certificates' issue time: kmsctl machine-cert -builtin signs exactly these
// documents, so the KMS-signed certificates of the ceremony have the built-in ones' hashes (one revocation covers
// both).
var MachineIssuedAt = time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)

// MachineDocs are the machines this build accepts without a trust list: Phala's prod5 and prod9, the two nodes our
// workspace can deploy to (a research note: 16 boots, the PPIDs from Intel's
// PCK certificates, FMSPC 20a06f000000). Compiled in, they are trusted as the build is (like ProdImages); the
// holders never use them (they need KMS-signed certificates in their policy). No registry-mode document is ever
// built in (TestNoRegistryCertWhileOnPhala).
var MachineDocs = []safety.MachineDoc{
	{Type: safety.MachineType, KMSID: ReleaseKMSID, Platform: safety.PlatformDstack, Host: safety.MachineHostPhala,
		Mode: safety.MachineModePPID, PPID: "3e306e133b7fdaa7bb79f67634cb520c", FMSPC: "20a06f000000", Label: "phala prod5",
		IssuedAt: MachineIssuedAt},
	{Type: safety.MachineType, KMSID: ReleaseKMSID, Platform: safety.PlatformDstack, Host: safety.MachineHostPhala,
		Mode: safety.MachineModePPID, PPID: "62d54040cb9dfc08bb13006fa75ece56", FMSPC: "20a06f000000", Label: "phala prod9",
		IssuedAt: MachineIssuedAt},
}

// MachinesRevoked are machine certificate hashes this build refuses whatever a trust list says (each client release
// copies the newest list's machines_revoked here, so a fresh install starts with them).
var MachinesRevoked = []string{}

// BuiltinMachines is MachineDocs as a set, minus MachinesRevoked.
func BuiltinMachines() *safety.MachineSet {
	s := &safety.MachineSet{Revoked: map[string]bool{}}
	for _, h := range MachinesRevoked {
		s.Revoked[h] = true
	}
	for _, d := range MachineDocs {
		h, err := safety.MachineDocHash(d)
		if err != nil {
			continue // TestMachineCertsBuiltInDefault fails on one
		}
		s.Machines = append(s.Machines, safety.Machine{Doc: d, Hash: h, Source: "built in"})
	}
	return s
}

// MachineNode is a Phala machine's node name ("prod5") from its label ("phala prod5"), "" if it has none: the
// deploy tool creates CVMs only on these (cmd/e2e provisionCVM).
func MachineNode(d safety.MachineDoc) string {
	if m := nodeLabelRe.FindStringSubmatch(d.Label); m != nil && d.Host == safety.MachineHostPhala && d.Mode == safety.MachineModePPID {
		return m[1]
	}
	return ""
}

var nodeLabelRe = regexp.MustCompile(`^phala (prod[0-9]{1,4})$`)

// RegistryURL is Google's confidential-host registry: one unsigned JSON document per host PPID
// ({"timestamp", "zone"}), trusted only as far as Google's TLS for storage.googleapis.com (2026-11-21 probe).
const RegistryURL = "https://storage.googleapis.com/confidential-host-registry/"

// EndorsementsOnly is g for a verifier that reads Google's files through a relay it doesn't trust: the browser's and
// the apps' WASM, whose fetches go through the chat Worker (gcp-prod review H1). Google's firmware endorsements are
// signed under Google's root, which gcetcb checks, so a relay can only withhold one; the host registry is an unsigned
// document, so a relay could say any PPID is a Google host, and a forged quote from any machine of that FMSPC would
// pass a registry-mode certificate. So only endorsement URLs are fetched, the registry is never read, and a
// registry-mode machine certificate passes such a verifier's machine check only with the VM's unlock proof
// (unlockproof.go: both key holders read the registry themselves before they released their shares). The key
// holders fetch Google directly and don't use this.
func EndorsementsOnly(g trust.HTTPSGetter) trust.HTTPSGetter { return endorsementsOnly{g} }

type endorsementsOnly struct{ g trust.HTTPSGetter }

func (e endorsementsOnly) Get(url string) (map[string][]string, []byte, error) {
	return e.GetContext(context.Background(), url)
}

func (e endorsementsOnly) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	if !strings.HasPrefix(url, gcetcb.URLPrefix) {
		return nil, nil, fmt.Errorf("%s isn't read through a relay here (an unsigned document a relay could forge)", url)
	}
	return trust.GetWith(ctx, e.g, url)
}

// checkMachine is the allowlist check (MachineCheck) on a verified quote.
func (r *Result) checkMachine(ctx context.Context, q *tdx.Quote, att *proto.Attestation, p Policy) bool {
	set := p.Machines
	if set == nil {
		set = BuiltinMachines()
	}
	r.Facts["PPID"], r.Facts["FMSPC"] = q.PPID, q.FMSPC
	// The certificate's host must be the boot chain's (gcp-host review M1): a Google machine certificate (registry
	// mode, or one Google host) never counts for a quote on a Phala boot set, and a Phala one never for a quote on a
	// Google Cloud set. Otherwise Google could boot a Phala-shaped chain on a registry-listed machine and pass with no
	// Google check and no dstack-gcp item for the holders' delay. A quote on neither is refused by the boot check.
	gcp, phala := onBootSet(q, p, true), onBootSet(q, p, false)
	m, err := set.Match(q.PPID, q.FMSPC)
	switch {
	case err == nil && m.Doc.Host == safety.MachineHostGoogle && phala:
		m, err = nil, fmt.Errorf("%w: platform %s's certificate is a Google machine's, but the quote is on a Phala boot set", safety.ErrMachineNotAllowed, q.PPID)
	case err == nil && m.Doc.Host != safety.MachineHostGoogle && gcp:
		m, err = nil, fmt.Errorf("%w: platform %s's certificate is a %s machine's, but the quote is on a Google Cloud boot set", safety.ErrMachineNotAllowed, q.PPID, m.Doc.Host)
	}
	if err != nil && errors.Is(err, safety.ErrMachineNotAllowed) && !phala {
		for _, reg := range set.Registry(q.FMSPC) {
			if rerr := r.proofOrRegistry(ctx, p, reg, quoteIDs{ppid: q.PPID, mrOwner: q.MrOwner}, att); rerr == nil {
				m, err = &reg, nil
				break
			} else {
				err = fmt.Errorf("%w (%s: %v)", err, reg.Doc.Label, rerr)
			}
		}
	}
	detail := ""
	if m != nil {
		host := "host Phala"
		if m.Doc.Host == safety.MachineHostGoogle {
			host = "host Google"
		}
		detail = fmt.Sprintf("%s (%s); %s: not defended by the machine list", m.Doc.Label, short(q.PPID), host)
		if r.proof != nil {
			detail += fmt.Sprintf("; Google's host registry: by both key holders (unlock proof, epoch %d)", r.proof.epoch)
		}
		r.Facts[FactMachine] = detail
		r.Facts["machine certificate"] = m.Hash
		r.Facts["machine source"] = m.Source
		if m.Doc.Host == safety.MachineHostGoogle {
			r.Facts[FactMachineHost] = safety.MachineHostGoogle // holders: the dstack-gcp item (review M1)
		}
	}
	return r.add(MachineCheck, err, detail)
}

// FactMachineHost is set to "google" when a Google machine certificate matched (unset for Phala: its facts as before).
const FactMachineHost = "machine host"

// onBootSet: the quote's MRTD and RTMR0-2 are exactly one of p's boot sets, a Google Cloud one (google: its MRTD one
// of the reviewed Google builds; gcpBoot checks the endorsement, the UKI and key provider none after the machine
// check) or another (the MRTD pinned).
func onBootSet(q *tdx.Quote, p Policy, google bool) bool {
	sets := p.Boot
	if sets == nil {
		sets = BootMeasurements
	}
	mrtd := hex.EncodeToString(q.MrTd)
	for _, s := range sets {
		if (s.MRTD == MRTDGoogleEndorsed) != google {
			continue
		}
		if google && !slices.ContainsFunc(s.GoogleMRTDs, func(m string) bool { return strings.EqualFold(m, mrtd) }) || !google && !strings.EqualFold(s.MRTD, mrtd) {
			continue
		}
		if strings.EqualFold(s.RTMR0, hex.EncodeToString(q.Rtmrs[0])) && strings.EqualFold(s.RTMR1, hex.EncodeToString(q.Rtmrs[1])) &&
			strings.EqualFold(s.RTMR2, hex.EncodeToString(q.Rtmrs[2])) {
			return true
		}
	}
	return false
}

// ownerCheck is registry mode's MR_OWNER rule (only while the Google fallback runs, V1-DESIGN §2.7): MR_OWNER is
// sha384 of the PZID JSON for the VM in the certificate's project (Google writes it at launch; go-tdx-guest
// gce/pzid.go). The VM's GCE instance id and zone come with its attestation info (gce_instance_id, gce_zone):
// unverified hints that only MR_OWNER makes count. mrOwner is the verified quote's.
func ownerCheck(m safety.Machine, mrOwner string, att *proto.Attestation) error {
	id, zone, err := gceHints(att)
	if err != nil {
		return err
	}
	proj, err := strconv.ParseUint(m.Doc.ProjectNumber, 10, 64)
	if err != nil {
		return errors.New("bad project number")
	}
	payload := fmt.Sprintf(`{"instanceId":%d,"numericalProjectId":%d,"zone":%s}`, id, proj, strconv.Quote(zone))
	want := sha512.Sum384([]byte(payload))
	if got, _ := hex.DecodeString(mrOwner); !bytes.Equal(got, want[:]) {
		return errors.New("MR_OWNER isn't this project's PZID for the VM")
	}
	return nil
}

func gceHints(att *proto.Attestation) (uint64, string, error) {
	var info struct {
		InstanceID string `json:"gce_instance_id"`
		Zone       string `json:"gce_zone"`
	}
	json.Unmarshal(att.Info, &info)
	id, err := strconv.ParseUint(info.InstanceID, 10, 64)
	if err != nil || !zoneRe.MatchString(info.Zone) {
		return 0, "", errors.New("the attestation names no GCE instance id and zone")
	}
	return id, info.Zone, nil
}

// registryRead is registry mode's registry rule, for a verifier that reads Google directly (the key holders): the
// quote's PPID (from its Intel-verified PCK certificate) has a document in Google's confidential-host registry, in
// the zone the VM names (ownerCheck bound that zone).
func registryRead(ctx context.Context, g trust.HTTPSGetter, ppid string, att *proto.Attestation) error {
	_, zone, err := gceHints(att)
	if err != nil {
		return err
	}
	if g == nil {
		g = &trust.SimpleHTTPSGetter{}
	}
	_, body, err := trust.GetWith(ctx, g, RegistryURL+ppid)
	if err != nil {
		return fmt.Errorf("Google's host registry has no document for %s: %v", short(ppid), err)
	}
	var doc struct {
		Timestamp time.Time `json:"timestamp"`
		Zone      string    `json:"zone"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.Timestamp.IsZero() || doc.Zone != zone {
		return fmt.Errorf("Google's host registry document for %s isn't for zone %s", short(ppid), zone)
	}
	return nil
}

var zoneRe = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]{1,2}-[a-z]$`)

// trustMachines is the machine set a taken trust list gives a client: its machine_certs (opened under the build's
// pinned KMS id; Google ones only when the list names the Google fallback) when it carries them, else
// MachineDocs; minus MachinesRevoked, the list's machines_revoked and every revocation the client kept. platforms
// are the platforms in force at this client (review2 L1): while dstack-gcp is still pending (its 24 h delay), the
// list's Google certificates are left out, though the list (which names it) opens them.
func trustMachines(l *safety.TrustList, platforms []string, kept []string) (*safety.MachineSet, error) {
	certs, revoked, present, err := l.TrustMachines()
	if err != nil {
		return nil, err
	}
	var set *safety.MachineSet
	if present {
		if trustKMSID == nil {
			return nil, errors.New("trust list: machine_certs, but this build pins no KMS id")
		}
		registryOK := false
		for _, pl := range l.Platforms {
			registryOK = registryOK || pl == PlatformDstackGCP
		}
		if set, err = safety.OpenMachineCerts(trustKMSID, certs, revoked, registryOK, fmt.Sprintf("trust list %d", l.Seq)); err != nil {
			return nil, fmt.Errorf("trust list %d: %w", l.Seq, err)
		}
		if !slices.Contains(platforms, PlatformDstackGCP) {
			set.Machines = slices.DeleteFunc(set.Machines, func(m safety.Machine) bool { return m.Doc.Host == safety.MachineHostGoogle })
		}
	} else {
		set = BuiltinMachines()
	}
	for _, h := range revoked {
		set.Revoked[h] = true
	}
	for _, h := range kept {
		set.Revoked[h] = true
	}
	for _, h := range MachinesRevoked {
		set.Revoked[h] = true
	}
	return set, nil
}

// machineSummary is "phala prod5, phala prod9" (the unrevoked machines' labels), for TrustInfo.
func machineSummary(s *safety.MachineSet) []string {
	var out []string
	for _, m := range s.Machines {
		if !s.Revoked[m.Hash] {
			out = append(out, m.Doc.Label)
		}
	}
	return out
}
