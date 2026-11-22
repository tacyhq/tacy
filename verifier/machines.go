package verifier

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

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
// holders never use them (they need KMS-signed certificates in their policy). Every one is a Phala host in ppid mode,
// the only kind a certificate can be (safety.MachineDoc.Validate; TestMachineCertsPhalaOnly).
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

// checkMachine is the allowlist check (MachineCheck) on a verified quote.
func (r *Result) checkMachine(ctx context.Context, q *tdx.Quote, att *proto.Attestation, p Policy) bool {
	set := p.Machines
	if set == nil {
		set = BuiltinMachines()
	}
	r.Facts["PPID"], r.Facts["FMSPC"] = q.PPID, q.FMSPC
	m, err := set.Match(q.PPID, q.FMSPC)
	detail := ""
	if m != nil {
		detail = fmt.Sprintf("%s (%s); host Phala: not defended by the machine list", m.Doc.Label, short(q.PPID))
		r.Facts[FactMachine] = detail
		r.Facts["machine certificate"] = m.Hash
		r.Facts["machine source"] = m.Source
	}
	return r.add(MachineCheck, err, detail)
}

// trustMachines is the machine set a taken trust list gives a client: its machine_certs (opened under the build's
// pinned KMS id) when it carries them, else MachineDocs; minus MachinesRevoked, the list's machines_revoked and every
// revocation the client kept.
func trustMachines(l *safety.TrustList, kept []string) (*safety.MachineSet, error) {
	certs, revoked, present, err := l.TrustMachines()
	if err != nil {
		return nil, err
	}
	var set *safety.MachineSet
	if present {
		if trustKMSID == nil {
			return nil, errors.New("trust list: machine_certs, but this build pins no KMS id")
		}
		if set, err = safety.OpenMachineCerts(trustKMSID, certs, revoked, fmt.Sprintf("trust list %d", l.Seq)); err != nil {
			return nil, fmt.Errorf("trust list %d: %w", l.Seq, err)
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
