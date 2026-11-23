package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/unlock"
)

// /attest carries the unlock proof (gcp-prod review H1) once agentd has its keys from unlockd: this boot's own HPKE
// key (never another), signed with the activity signer the dev epoch certificate names, for the info the quote came
// with. A local run (no unlockd) and a keyring with no certificate serve none.
func TestAttestUnlockProof(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ak, _ := split.RootKey(d.Root, splitdev.App, splitdev.Firm, PurposeActivity, d.Epoch)
	signer, _ := activity.DeriveSigner(ak, splitdev.Firm)
	ec, _ := d.Cert.Open(d.IDPub)
	if ec.Signers[PurposeActivity] != signer.Public() {
		t.Fatal("the dev epoch certificate doesn't name the activity signer")
	}
	cert, _ := json.Marshal(d.Cert)
	uk := &unlock.Keys{KMSID: d.KMSID, Epoch: d.Epoch, EpochCert: cert}

	a, _, _ := newTestAgent(t, textSSE("x"))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	info := json.RawMessage(`{"app_id":"ab","instance_id":"cd","tcb_info":"{\"app_compose\":\"{}\"}"}`)
	attest := func() proto.Attestation {
		t.Helper()
		rec := httptest.NewRecorder()
		s.attest(rec, httptest.NewRequest(http.MethodGet, "/attest?nonce="+strings.Repeat("11", 32), nil))
		var att proto.Attestation
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &att) != nil {
			t.Fatalf("attest: %d %s", rec.Code, rec.Body)
		}
		return att
	}
	if att := attest(); att.UnlockProof != nil {
		t.Fatal("a local run served an unlock proof")
	}
	s.attester = func(context.Context, []byte, []byte) (json.RawMessage, json.RawMessage, error) {
		return json.RawMessage(`{"quote":"00"}`), info, nil
	}
	if unlockProofs(signer, &unlock.Keys{KMSID: d.KMSID, Epoch: d.Epoch}, id.MarshalPublicKey()) != nil {
		t.Fatal("a proof maker without an epoch certificate")
	}
	s.proof = unlockProofs(signer, uk, id.MarshalPublicKey())
	att := attest()
	pr := att.UnlockProof
	if pr == nil || pr.AppID != "ab" || pr.InstanceID != "cd" || string(pr.EpochCert) != string(cert) {
		t.Fatalf("proof %+v", pr)
	}
	key, _ := hex.DecodeString(att.HPKEPublicKey)
	if att.HPKEPublicKey != id.MarshalPublicKeyHex() {
		t.Fatal("not this boot's key")
	}
	pub, _ := activity.ParseKey(signer.Public())
	dg := pr.Digest(key, d.KMSID, d.Epoch)
	if !ed25519.Verify(pub, append([]byte(proto.UnlockProofLabel+"\x00"), dg[:]...), pr.Sig) {
		t.Fatal("the proof isn't signed over this boot's key")
	}
}
