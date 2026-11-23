package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-tdx-guest/verify/trust"
	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Registry mode by proof of unlock (gcp-prod review H1; design review 2026-11-23 H1-1). Google's host registry is
// an unsigned document, so a verifier that reads Google through a relay it doesn't trust (EndorsementsOnly: the
// browser's and the apps' WASM, the chat Worker's own check) never reads it. Both key holders read it themselves
// before they release their shares to a Google VM (the Vercel holder from Vercel, the Cloudflare holder through
// Cloudflare's runtime), so a VM that shows it holds a key derived from the epoch root R_e passed both holders'
// registry checks. Such a verifier accepts a registry-mode machine certificate only with the VM's unlock proof
// (proto.UnlockProof):
//
//   - the epoch certificate is signed by a Tacy KMS id this verifier pins (Policy.KMSIDs, else KMSIDs) and names the
//     activity signer ("activity-sign/v1"), the key agentd derives from R_e;
//   - that signer signed UnlockProofLabel over this attestation's HPKE key (the one report_data binds), the KMS id,
//     the epoch, and the app id, instance id and app-compose sha256 the proof names;
//   - those three are the attested ones (RTMR3), the KMS id is the one the compose names (-kms-key), and the epoch
//     is at least the compose's unlockd -min-epoch (so a release that raised it after a leaked root refuses the old
//     epoch's proofs): checkUnlockProofBinding, after the compose checks;
//   - MR_OWNER is still the certificate's project's PZID for the VM's instance and zone (ownerCheck).
//
// What forging takes: an attestation key from a TDX machine of the FMSPC, plus a VM that unlocked, so both holders'
// shares (Cloudflare and Vercel), or the admin's break-glass. A forged quote carrying a genuine VM's proof binds
// that VM's HPKE key, which only that VM can open, and must claim exactly its app id, instance and release. There
// is no expiry to manage: the proof is for one boot's key, and the host check is the holders' at that unlock (as
// for the shares themselves).

// UnlockProofCheck is the binding check's name (only for a VM on a registry-mode machine, through a relay).
const UnlockProofCheck = "unlock proof: the VM's key belongs to a VM both key holders unlocked (they checked Google's host registry)"

// signerPurpose is the epoch certificate's signer the proof is signed with (split.EpochCert.Signers).
const signerPurpose = "activity-sign/v1"

// epochCertLabel is split's Ed25519 label for an epoch certificate (kms/split root.go sigEpochCert).
const epochCertLabel = "tacy-split/epoch-cert/v1"

// proofMode: registry-mode machines are taken by proof of unlock, never by reading the registry (a getter behind a
// relay: EndorsementsOnly).
func proofMode(g trust.HTTPSGetter) bool {
	_, ok := g.(endorsementsOnly)
	return ok
}

// unlockProof is what a checked proof claimed, for checkUnlockProofBinding.
type unlockProof struct {
	kmsID            string
	epoch            uint32
	appID, instance  string
	appComposeSHA256 string
}

// epochCertDoc is the part of split.EpochCert the proof needs.
type epochCertDoc struct {
	KMSID   string            `json:"kms_id"`
	Epoch   uint32            `json:"epoch"`
	Signers map[string]string `json:"signers"`
}

// openUnlockProof checks att's unlock proof up to its signature: the epoch certificate under a pinned KMS id, the
// activity signer it names, the signature over att's HPKE key. ids are the pinned KMS ids.
func openUnlockProof(att *proto.Attestation, ids map[string]string) (*unlockProof, error) {
	pr := att.UnlockProof
	if pr == nil {
		return nil, errors.New("the attestation has no unlock proof (a registry-mode machine counts here only with one; a VM shows it once unlocked)")
	}
	var sc struct {
		Doc []byte `json:"doc"`
		Sig []byte `json:"sig"`
	}
	if err := json.Unmarshal(pr.EpochCert, &sc); err != nil || len(sc.Doc) == 0 {
		return nil, errors.New("unlock proof: the epoch certificate isn't one")
	}
	var doc epochCertDoc
	if err := json.Unmarshal(sc.Doc, &doc); err != nil || doc.Epoch == 0 {
		return nil, errors.New("unlock proof: the epoch certificate doesn't parse")
	}
	if ids[doc.KMSID] == "" {
		return nil, fmt.Errorf("unlock proof: the epoch certificate is for Tacy KMS %s, which isn't a pinned one", short(doc.KMSID))
	}
	kms, err := safety.ParseKey(doc.KMSID)
	if err != nil || len(sc.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kms, append(append([]byte(epochCertLabel), 0), sc.Doc...), sc.Sig) {
		return nil, errors.New("unlock proof: the epoch certificate isn't signed by its KMS id")
	}
	signer, err := safety.ParseKey(doc.Signers[signerPurpose])
	if err != nil {
		return nil, errors.New("unlock proof: the epoch certificate names no activity signer")
	}
	key, err := hexKey(att.HPKEPublicKey)
	if err != nil {
		return nil, err
	}
	d := pr.Digest(key, doc.KMSID, doc.Epoch)
	if len(pr.Sig) != ed25519.SignatureSize || !ed25519.Verify(signer, append(append([]byte(proto.UnlockProofLabel), 0), d[:]...), pr.Sig) {
		return nil, errors.New("unlock proof: not signed by the epoch's activity signer over this VM's key (a proof for another boot or VM)")
	}
	return &unlockProof{kmsID: doc.KMSID, epoch: doc.Epoch, appID: pr.AppID, instance: pr.InstanceID, appComposeSHA256: pr.AppComposeSHA256}, nil
}

func hexKey(s string) ([]byte, error) {
	b := make([]byte, 0, 32)
	for i := 0; i+1 < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, errors.New("unlock proof: the HPKE key isn't hex")
		}
		b = append(b, byte(v))
	}
	if len(b) != 32 || len(s) != 64 {
		return nil, errors.New("unlock proof: the HPKE key isn't 32 bytes")
	}
	return b, nil
}

// checkUnlockProofBinding is the proof's binding to what was attested (only when the machine check took a
// registry-mode certificate by proof): the app id, instance id and app-compose hash from the RTMR3 replay, the KMS
// id the compose names, and the compose's minimum epoch.
func (r *Result) checkUnlockProofBinding(compose string) bool {
	pr := r.proof
	if pr == nil {
		return true
	}
	var err error
	switch {
	case pr.appID != r.Facts["app id"]:
		err = fmt.Errorf("the proof is for app id %s, the VM attests %s", short(pr.appID), short(r.Facts["app id"]))
	case pr.instance != r.Facts["instance id"]:
		err = fmt.Errorf("the proof is for instance %s, the VM attests %s", short(pr.instance), short(r.Facts["instance id"]))
	case !strings.EqualFold(pr.appComposeSHA256, r.Facts["compose hash"]):
		err = fmt.Errorf("the proof is for app-compose %s, the VM attests %s", short(pr.appComposeSHA256), short(r.Facts["compose hash"]))
	}
	if err == nil {
		keys, _, kerr := composeKMS(compose)
		switch {
		case kerr != nil:
			err = kerr
		case len(keys) == 0:
			// A VM unlocks only from the Tacy KMS its compose names, so a proof for one naming none is another VM's.
			// (Also what keeps a trust list's added KMS id from certifying keys for a signed release that names ours.)
			err = errors.New("the compose names no Tacy KMS (-kms-key), so this VM can't have unlocked")
		case !contains(keys, pr.kmsID):
			err = fmt.Errorf("the proof's epoch is Tacy KMS %s's, the compose names %s", short(pr.kmsID), strings.Join(keys, ", "))
		}
	}
	if err == nil {
		min, merr := composeMinEpoch(compose)
		if merr != nil {
			err = merr
		} else if pr.epoch < min {
			err = fmt.Errorf("the proof is of epoch %d, below the compose's minimum %d", pr.epoch, min)
		}
	}
	return r.add(UnlockProofCheck, err, fmt.Sprintf("epoch %d of Tacy KMS %s", pr.epoch, short(pr.kmsID)))
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// composeMinEpoch is unlockd's -min-epoch in the compose (1 when unlockd or the flag is absent: unlockd's default).
func composeMinEpoch(compose string) (uint32, error) {
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return 0, fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	svc := doc.Services[UnlockdService]
	var args []string
	for _, k := range []string{"entrypoint", "command"} {
		switch v := svc[k].(type) {
		case string:
			args = append(args, strings.Fields(v)...)
		case []any:
			for _, a := range v {
				args = append(args, fmt.Sprint(a))
			}
		}
	}
	min := uint64(1)
	for i, a := range args {
		name, val, eq := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "min-epoch" {
			continue
		}
		if !eq {
			if i+1 >= len(args) {
				return 0, errors.New("unlockd's -min-epoch has no value")
			}
			val = args[i+1]
		}
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil || v == 0 {
			return 0, fmt.Errorf("unlockd's -min-epoch %q isn't an epoch", val)
		}
		min = max(min, v)
	}
	return uint32(min), nil
}

// proofOrRegistry is the registry part of a registry-mode machine: by proof of unlock through a relay, else the
// registry read straight from Google.
func (r *Result) proofOrRegistry(ctx context.Context, p Policy, m safety.Machine, q quoteIDs, att *proto.Attestation) error {
	if err := ownerCheck(m, q.mrOwner, att); err != nil {
		return err
	}
	if !proofMode(p.GoogleGetter) {
		return registryRead(ctx, p.GoogleGetter, q.ppid, att)
	}
	pr, err := openUnlockProof(att, cmpOr(p.KMSIDs, KMSIDs))
	if err != nil {
		return err
	}
	// The Google VM the proof names is the one MR_OWNER binds (ownerCheck read the same hints).
	id, zone, _ := gceHints(att)
	if att.UnlockProof.GCEInstanceID != strconv.FormatUint(id, 10) || att.UnlockProof.GCEZone != zone {
		return fmt.Errorf("unlock proof: for GCE instance %s in %s, the VM's MR_OWNER is for %d in %s",
			att.UnlockProof.GCEInstanceID, att.UnlockProof.GCEZone, id, zone)
	}
	r.proof = pr
	return nil
}

// quoteIDs are the verified quote's values registry mode reads.
type quoteIDs struct{ ppid, mrOwner string }
