package unlock_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/unlock"
)

// The unlock proof's VM side (gcp-prod review H1): after a real 2-of-2 unlock, agentd's keys carry the policy's
// signed certificate of the epoch that unlocked (vaultd's don't), naming the activity signer agentd derives from
// its activity-sign/v1 key; NewUnlockProof signs this boot's key and the info's values with it. A container restart
// from the cache keeps the certificate.
func TestUnlockProofFromBoot(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(nil)
	if st := r.run(u, 30*time.Second); st.State != unlock.StateReady {
		t.Fatalf("status %+v", st)
	}
	a, v := r.mustKeys(u, unlock.RoleAgent), r.mustKeys(u, unlock.RoleVault)
	if len(v.EpochCert) != 0 {
		t.Fatal("vaultd got the epoch certificate (agentd's alone)")
	}
	var sc split.SignedEpochCert
	if err := json.Unmarshal(a.EpochCert, &sc); err != nil {
		t.Fatalf("agentd's epoch certificate: %v", err)
	}
	cert, err := sc.Open(r.w.IDPub)
	if err != nil || cert.Epoch != a.Epoch {
		t.Fatalf("not the KMS id's certificate of epoch %d: %v", a.Epoch, err)
	}
	signer, err := activity.DeriveSigner(a.Keys["activity-sign/v1"], a.Firm) // as agentd does (app/state.go)
	if err != nil || cert.Signers["activity-sign/v1"] != signer.Public() {
		t.Fatalf("the certificate's activity signer %q isn't agentd's %q (%v)", cert.Signers["activity-sign/v1"], signer.Public(), err)
	}
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	info := json.RawMessage(`{"app_id":"ABCD","instance_id":"EF01","tcb_info":"{\"app_compose\":\"{}\"}","gce_instance_id":"42","gce_zone":"us-central1-a"}`)
	pr, err := unlock.NewUnlockProof(signer.SignLabeled, a.EpochCert, a.KMSID, a.Epoch, k.PublicKey().Bytes(), info)
	if err != nil {
		t.Fatal(err)
	}
	if pr.AppID != "abcd" || pr.InstanceID != "ef01" || pr.GCEInstanceID != "42" || pr.GCEZone != "us-central1-a" ||
		pr.AppComposeSHA256 != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatalf("proof %+v", pr)
	}
	pub, _ := activity.ParseKey(signer.Public())
	d := pr.Digest(k.PublicKey().Bytes(), a.KMSID, a.Epoch)
	if !ed25519.Verify(pub, append([]byte(proto.UnlockProofLabel+"\x00"), d[:]...), pr.Sig) {
		t.Fatal("the proof isn't the activity signer's over this key")
	}
	// A container restart: the cached keyring serves the same certificate.
	u2 := r.unlocker(nil)
	if st := r.run(u2, 10*time.Second); !st.Cached || string(r.mustKeys(u2, unlock.RoleAgent).EpochCert) != string(a.EpochCert) {
		t.Fatalf("after a restart: %+v", st)
	}
	// No proof without a certificate, a key of 32 bytes or an app-compose in the info.
	for name, f := range map[string]func() error{
		"no certificate": func() error { _, err := unlock.NewUnlockProof(signer.SignLabeled, nil, a.KMSID, a.Epoch, k.PublicKey().Bytes(), info); return err },
		"short key":      func() error { _, err := unlock.NewUnlockProof(signer.SignLabeled, a.EpochCert, a.KMSID, a.Epoch, []byte{1}, info); return err },
		"no app-compose": func() error {
			_, err := unlock.NewUnlockProof(signer.SignLabeled, a.EpochCert, a.KMSID, a.Epoch, k.PublicKey().Bytes(), json.RawMessage(`{"app_id":"a"}`))
			return err
		},
	} {
		if err := f(); err == nil || !strings.HasPrefix(err.Error(), "unlock:") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
