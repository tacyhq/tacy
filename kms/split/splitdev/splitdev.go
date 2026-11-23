// Package splitdev makes a development split key: a random M (so a dev KMS id, never production's), a dev admin
// key, epoch 1's VM root re-split across the named holders with their dev keys and nonce keys, its epoch
// certificate, and an unlock policy for the caller to pin releases in. For tests (the holders', unlockd's, the
// Worker's fixtures) and staging (kmsctl split-dev writes its files). Never production: every key here is made in
// memory and its private half is handed to the caller. Like all of kms/, it touches no file.
package splitdev

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/holder"
	"github.com/tacyhq/tacy/safety"
)

// App and Firm are the development agent VM's app and firm in the policy; AdminGeneration names the dev admin key.
const (
	App             = "agent-vm"
	Firm            = "f_chat"
	AdminGeneration = "dev-admin-1"
)

// Dev is one development split key.
type Dev struct {
	Master   []byte
	KMSID    string
	IDPub    ed25519.PublicKey
	Admin    ed25519.PrivateKey
	AdminPub ed25519.PublicKey
	Epoch    uint32
	// Root is epoch 1's VM root (what holders hold shares of).
	Root []byte
	// Holders, in order; Keys and NonceKeys per holder id.
	Holders   []string
	Keys      map[string]*ecdh.PrivateKey
	NonceKeys map[string][]byte
	Set       *split.SignedShareSet
	Cert      *split.SignedEpochCert
	Shares    map[string]split.HolderShare
	// Policy pins nothing yet: AddRelease, then SignPolicy.
	Policy split.UnlockPolicy
}

// New makes a dev split t-of-n across holders (ids), set 2, epoch 1, issued at now.
func New(holders []string, threshold int, now time.Time) (*Dev, error) {
	d := &Dev{Epoch: 1, Holders: holders, Keys: map[string]*ecdh.PrivateKey{}, NonceKeys: map[string][]byte{},
		Shares: map[string]split.HolderShare{}}
	d.Master = make([]byte, kms.MasterSize)
	rand.Read(d.Master)
	id, err := kms.DeriveID(d.Master)
	if err != nil {
		return nil, err
	}
	d.IDPub = id.Public().(ed25519.PublicKey)
	d.KMSID = kms.IDString(d.IDPub)
	d.AdminPub, d.Admin, _ = ed25519.GenerateKey(rand.Reader)
	if d.Root, err = split.EpochRoot(d.Master, d.Epoch); err != nil {
		return nil, err
	}
	var recips []split.HolderRecipient
	for _, h := range holders {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		nk := make([]byte, 32)
		rand.Read(nk)
		d.Keys[h], d.NonceKeys[h] = k, nk
		recips = append(recips, split.HolderRecipient{Holder: h, Recipient: split.RecipientString(k.PublicKey())})
	}
	set, shares, err := split.Resplit(d.Master, d.KMSID, d.Epoch, 2, threshold, recips, now, rand.Reader)
	if err != nil {
		return nil, err
	}
	d.Set = set
	for _, s := range shares {
		d.Shares[s.Holder] = s
	}
	wpub, err := split.WitnessPublic(d.Root, App, Firm, d.Epoch)
	if err != nil {
		return nil, err
	}
	// The activity signer too, as the key ceremony certifies it (cmd/kmsctl epochCert; production's epoch 1
	// certificate names it): clients check activity records and the VM's unlock proof (proto.UnlockProof) with it.
	ak, err := split.RootKey(d.Root, App, Firm, "activity-sign/v1", d.Epoch)
	if err != nil {
		return nil, err
	}
	signer, err := activitySigner(ak, Firm)
	clear(ak)
	if err != nil {
		return nil, err
	}
	if d.Cert, err = split.NewEpochCert(d.Master, d.KMSID, d.Epoch, App, Firm,
		map[string]string{"activity-sign/v1": signer, split.WitnessPurpose: wpub}, now); err != nil {
		return nil, err
	}
	d.Policy = split.UnlockPolicy{
		Policy: kms.Policy{KMSID: d.KMSID, Epoch: d.Epoch, Seq: 1, IssuedAt: now.UTC(), Floor: "v0.0.1",
			Apps: map[string]kms.AppPolicy{App: {Firm: Firm, Purposes: []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1",
				"notify/v1", "operator/v1", "relay-auth/v1"}, Secrets: []string{"TINFOIL_API_KEY", "EXA_API_KEY", "TAVILY_API_KEY"}}}},
		ShareSets: []split.SignedShareSet{*set}, EpochCerts: []split.SignedEpochCert{*d.Cert}}
	for _, h := range holders {
		d.Policy.Holders = append(d.Policy.Holders, split.HolderURL{Holder: h, URL: "https://" + h + ".holders.invalid"})
	}
	// The machine allowlist: Phala's prod5 and prod9 (the nodes throwaways and the recordings run on), certified
	// by the dev KMS id (production's are the KMS ceremony's).
	for _, m := range []struct{ ppid, label string }{{PPIDProd5, "phala prod5"}, {PPIDProd9, "phala prod9"}} {
		c, err := d.MachineCert(safety.MachineDoc{Type: safety.MachineType, Platform: safety.PlatformDstack, Host: safety.MachineHostPhala,
			Mode: safety.MachineModePPID, PPID: m.ppid, FMSPC: FMSPCPhala, Label: m.label, IssuedAt: now})
		if err != nil {
			return nil, err
		}
		d.Policy.MachineCerts = append(d.Policy.MachineCerts, *c)
	}
	return d, nil
}

// Phala's two workspace nodes (Intel PCK PPIDs) and their FMSPC, as verifier.MachineDocs has them.
const (
	PPIDProd5  = "3e306e133b7fdaa7bb79f67634cb520c"
	PPIDProd9  = "62d54040cb9dfc08bb13006fa75ece56"
	FMSPCPhala = "20a06f000000"
)

// MachineCert is a machine certificate signed by the dev KMS id.
func (d *Dev) MachineCert(doc safety.MachineDoc) (*safety.SignedMachineCert, error) {
	return split.NewMachineCert(d.Master, d.KMSID, doc)
}

// AddRelease pins a release of App by its whole app-compose.json sha256 (and its docker compose's, optional).
func (d *Dev) AddRelease(version, appComposeSHA256, composeSHA256 string) {
	d.Policy.Releases = append(d.Policy.Releases, kms.ReleasePin{App: App, Version: version, AppComposeSHA256: appComposeSHA256,
		ComposeSHA256: composeSHA256})
}

// SignPolicy is the policy signed with the dev admin key (safety.Envelope JSON).
func (d *Dev) SignPolicy() (json.RawMessage, error) {
	if err := d.Policy.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(d.Policy)
	if err != nil {
		return nil, err
	}
	return json.Marshal(safety.Sign(split.KindUnlockPolicy, b, d.Admin))
}

// HolderConfig is holder id's dev config: its share, key, nonce key, in-memory stores (initialized at seq 0) and
// no pin delay. Callers add Check (attestation switches), Now and Notify.
func (d *Dev) HolderConfig(id string) holder.Config {
	st := &holder.MemoryStore{}
	st.Init(AdminGeneration, 0)
	return holder.Config{ID: id, KMSID: d.KMSID, Admin: kms.AdminKeys{Keys: []ed25519.PublicKey{d.AdminPub}, Threshold: 1},
		AdminGeneration: AdminGeneration, Shares: []split.HolderShare{d.Shares[id]}, Opener: holder.KeyOpener{Key: d.Keys[id]},
		NonceKey: d.NonceKeys[id], Nonces: holder.NewMemoryNonces(4096), Store: st, NoPinDelay: true}
}

// SealSecrets seals dev API keys under the dev root (seq 1).
func (d *Dev) SealSecrets(values map[string]string) ([]byte, error) {
	return split.SealSecrets(d.Root, split.SecretsBundle{KMSID: d.KMSID, Epoch: d.Epoch, Seq: 1, Values: values})
}

// activitySigner is activity.DeriveSigner(ikm, firm).Public() (HKDF-SHA256(ikm, info "tacy-activity/v1/signing-key\x00"
// ‖ firm) as the Ed25519 seed), without package activity (its store needs SQLite, which the holders' builds don't
// take). app TestAttestUnlockProof checks the two agree.
func activitySigner(ikm []byte, firm string) (string, error) {
	seed, err := hkdf.Key(sha256.New, ikm, nil, "tacy-activity/v1/signing-key\x00"+firm, ed25519.SeedSize)
	if err != nil {
		return "", err
	}
	k := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	pub := k.Public().(ed25519.PublicKey)
	clear(k)
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub), nil
}
