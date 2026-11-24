package unlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/tacyhq/tacy/proto"
)

// NewUnlockProof is agentd's unlock proof (proto.UnlockProof, gcp-prod review H1) for one attestation: its own HPKE
// key (only ever this boot's: agentd passes s.id's public key, never a key it was handed), and the app id, instance
// id and app-compose.json of the dstack Info unlockd returned with the quote. sign is the epoch's activity signer
// (activity.Signer.SignLabeled, the key agentd derived from R_e); epochCert, kmsID and epoch are the unlock's
// (Keys.EpochCert, KMSID, Epoch). The verifier checks the three values against the ones the quote attests.
func NewUnlockProof(sign func(label string, digest [32]byte) ([]byte, error), epochCert json.RawMessage, kmsID string, epoch uint32,
	hpkePublicKey []byte, info json.RawMessage) (*proto.UnlockProof, error) {
	if len(epochCert) == 0 || kmsID == "" || epoch == 0 || len(hpkePublicKey) != 32 {
		return nil, errors.New("unlock: no epoch certificate or key for an unlock proof")
	}
	var in struct {
		AppID      string          `json:"app_id"`
		InstanceID string          `json:"instance_id"`
		TcbInfo    json.RawMessage `json:"tcb_info"`
		GCEID      json.RawMessage `json:"gce_instance_id"`
		GCEZone    string          `json:"gce_zone"`
	}
	if err := json.Unmarshal(info, &in); err != nil {
		return nil, errors.New("unlock: the attestation info isn't JSON")
	}
	tcb := in.TcbInfo
	var s string
	if json.Unmarshal(tcb, &s) == nil { // dstack sends tcb_info as a JSON string
		tcb = []byte(s)
	}
	var t struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(tcb, &t); err != nil || t.AppCompose == "" {
		return nil, errors.New("unlock: the attestation info has no app-compose.json")
	}
	h := sha256.Sum256([]byte(t.AppCompose))
	pr := &proto.UnlockProof{EpochCert: epochCert, AppID: strings.ToLower(in.AppID), InstanceID: strings.ToLower(in.InstanceID),
		AppComposeSHA256: hex.EncodeToString(h[:]), GCEInstanceID: gceID(in.GCEID), GCEZone: in.GCEZone}
	sig, err := sign(proto.UnlockProofLabel, pr.Digest(hpkePublicKey, kmsID, epoch))
	if err != nil {
		return nil, err
	}
	pr.Sig = sig
	return pr, nil
}

// gceID is the info's gce_instance_id as text (gateway/gce.go writes it as a JSON string; a number is taken too).
func gceID(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}
