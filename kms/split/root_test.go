package split

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
)

// R_e is per epoch and isn't M; the KMS id's epoch certificate names R_e's root id and store certificates the
// Worker checks as before; it can't be made without M.
func TestEpochRootAndCert(t *testing.T) {
	m, idStr, idPub := master(t)
	r1, _ := EpochRoot(m, 1)
	r2, _ := EpochRoot(m, 2)
	if bytes.Equal(r1, m) || bytes.Equal(r1, r2) {
		t.Fatal("epoch roots must differ from M and from each other")
	}
	if _, err := EpochRoot(m, 0); err == nil {
		t.Fatal("epoch 0")
	}
	sc, err := NewEpochCert(m, idStr, 1, "agent-vm", "f_chat", map[string]string{"activity-sign/v1": "ed25519:x"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := sc.Open(idPub)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := RootID(r1)
	if c.Root != rid || c.Epoch != 1 || len(c.StoreCerts) != len(kms.StorePurposes) {
		t.Fatalf("cert: %+v", c)
	}
	for pu, st := range c.StoreCerts {
		k, _ := RootKey(r1, "agent-vm", "f_chat", pu, 1)
		sk, _ := kms.StoreAuthKey(k)
		if st.Key != kms.IDString(sk.Public().(ed25519.PublicKey)) || !ed25519.Verify(idPub, kms.StoreCertMessage(st), st.Sig) {
			t.Fatalf("%s store certificate isn't the root's store-auth key under the KMS id", pu)
		}
	}
	// Re-encoded it still opens; edited it doesn't; another M can't make one for this id.
	pretty, _ := json.MarshalIndent(sc, "", "  ")
	var back SignedEpochCert
	json.Unmarshal(pretty, &back)
	if _, err := back.Open(idPub); err != nil {
		t.Fatal(err)
	}
	var ec EpochCert
	json.Unmarshal(sc.Doc, &ec)
	ec.Root = idStr
	doc, _ := json.Marshal(ec)
	if _, err := (SignedEpochCert{Doc: doc, Sig: sc.Sig}).Open(idPub); err == nil {
		t.Fatal("an edited certificate opened")
	}
	other, _, _ := master(t)
	if _, err := NewEpochCert(other, idStr, 1, "agent-vm", "f_chat", nil, time.Now()); err == nil {
		t.Fatal("a certificate from another M")
	}
}

func TestSecretsBundle(t *testing.T) {
	m, idStr, _ := master(t)
	r1, _ := EpochRoot(m, 1)
	b := SecretsBundle{KMSID: idStr, Epoch: 1, Seq: 3, Values: map[string]string{"TINFOIL_API_KEY": "tk", "EXA_API_KEY": "ek"}}
	sealed, err := SealSecrets(r1, b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("tk")) && bytes.Contains(sealed, []byte("TINFOIL")) {
		t.Fatal("the bundle isn't sealed")
	}
	got, err := OpenSecrets(r1, idStr, 1, sealed)
	if err != nil || got.Seq != 3 || got.Values["EXA_API_KEY"] != "ek" {
		t.Fatalf("open: %v", err)
	}
	r2, _ := EpochRoot(m, 2)
	if _, err := OpenSecrets(r2, idStr, 1, sealed); err == nil {
		t.Fatal("opened with another epoch's root")
	}
	if _, err := OpenSecrets(r1, idStr, 2, sealed); err == nil {
		t.Fatal("opened as another epoch's")
	}
	bad := bytes.Clone(sealed)
	bad[len(secretsMagic)+7] ^= 1 // the seq in the header
	if _, err := OpenSecrets(r1, idStr, 1, bad); err == nil {
		t.Fatal("a bundle whose seq was changed opened")
	}
}
