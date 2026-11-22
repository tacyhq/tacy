package unlock

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
)

// The development root (unlockd -platform local): a VM with nothing attested, no holders (they refuse platform
// local), an epoch root made from a seed the developer gives (as the ceremony makes R_1 from M), and the dev API
// keys from a file. Never on dstack (unlockd refuses -dev-* there, and New refuses a DevRoot unless the platform is
// local).

// DevApp and DevFirm are a development VM's app and firm.
const (
	DevApp  = "agent-vm"
	DevFirm = "f_chat"
)

// devRoot is epoch 1's root of a development M, with its epoch certificate and the dev API keys.
type devRoot struct {
	r       []byte
	kmsID   string
	cert    *split.EpochCert
	secrets map[string]string
}

func (d *devRoot) Key(app, firm, purpose string) ([]byte, error) {
	if d.r == nil {
		return nil, errors.New("unlock: root dropped")
	}
	return split.RootKey(d.r, app, firm, purpose, 1)
}

func (d *devRoot) OpenSecrets(sealed []byte) (*split.SecretsBundle, error) {
	if d.r == nil {
		return nil, errors.New("unlock: root dropped")
	}
	return split.OpenSecrets(d.r, d.kmsID, 1, sealed)
}

func (d *devRoot) StoreCert(purpose string) (kms.StoreCert, error) {
	c, ok := d.cert.StoreCerts[purpose]
	if !ok {
		return kms.StoreCert{}, fmt.Errorf("unlock: no %s store certificate", purpose)
	}
	return c, nil
}

func (d *devRoot) Drop() { clear(d.r); d.r = nil }

// DevKMSID is the KMS id a development seed (its M) derives: what unlockd -platform local is pinned to.
func DevKMSID(seed []byte) (string, error) {
	id, err := kms.DeriveID(seed)
	if err != nil {
		return "", err
	}
	defer clear(id)
	return kms.IDString(id.Public().(ed25519.PublicKey)), nil
}

// DevRoot is a development root and grant: every purpose but relay-auth, and the dev API keys as if they came from
// the epoch's bundle. seed is the development M (32 bytes).
func DevRoot(seed []byte, secrets map[string]string) (Root, Grant, error) {
	if len(seed) != kms.MasterSize {
		return nil, Grant{}, errors.New("unlock: a development seed is 32 bytes")
	}
	kmsID, err := DevKMSID(seed)
	if err != nil {
		return nil, Grant{}, err
	}
	r, err := split.EpochRoot(seed, 1)
	if err != nil {
		return nil, Grant{}, err
	}
	sc, err := split.NewEpochCert(seed, kmsID, 1, DevApp, DevFirm, nil, time.Now())
	if err != nil {
		return nil, Grant{}, err
	}
	id, _ := kms.ParseID(kmsID)
	cert, err := sc.Open(id)
	if err != nil {
		return nil, Grant{}, err
	}
	g := Grant{App: DevApp, Release: "local", Policy: kms.AppPolicy{Firm: DevFirm,
		Purposes: slices.DeleteFunc(slices.Clone(kms.Purposes), func(p string) bool { return p == "relay-auth/v1" })}}
	return &devRoot{r: r, kmsID: kmsID, cert: cert, secrets: secrets}, g, nil
}
