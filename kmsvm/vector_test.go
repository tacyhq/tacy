package kmsvm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
)

// stateVector is testdata/vm-state-auth-v1.json: a sealed-state request as the VM signs it, fixed. The chat
// Worker's tests (the chat's test/unit/vm-state.test.ts) check vm-state.ts accepts exactly it.
type stateVector struct {
	KMSIDSeed   string        `json:"kms_id_seed"` // base64: the test KMS id's Ed25519 seed
	KMSID       string        `json:"kms_id"`
	PurposeKey  string        `json:"purpose_key"` // hex: the released state/v1 key
	Cert        kms.StoreCert `json:"cert"`
	CertMessage string        `json:"cert_message"` // hex: what the KMS id signs
	CertHeader  string        `json:"cert_header"`  // X-Tacy-Cert
	Method      string        `json:"method"`
	Name        string        `json:"name"`
	Time        int64         `json:"time"`
	Gen         string        `json:"gen"`
	Prev        string        `json:"prev"`
	Body        string        `json:"body"` // base64
	Message     string        `json:"message"`
	AuthHeader  string        `json:"auth_header"` // X-Tacy-Auth
}

func makeStateVector() stateVector {
	idSeed := bytes.Repeat([]byte{9}, 32)
	id := ed25519.NewKeyFromSeed(idSeed)
	pk := bytes.Repeat([]byte{5}, 32)
	sk, _ := kms.StoreAuthKey(pk)
	c := kms.StoreCert{App: "agent-vm", Firm: "f_chat", Epoch: 0, Purpose: "state/v1", Key: kms.IDString(sk.Public().(ed25519.PublicKey))}
	c.Sig = ed25519.Sign(id, kms.StoreCertMessage(c))
	body := []byte("TACYSEAL1 a sealed blob stands here")
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC).Unix()
	ch, ah := SignState(sk, c, "PUT", "side", at, "4", "3", body)
	return stateVector{KMSIDSeed: base64.StdEncoding.EncodeToString(idSeed), KMSID: kms.IDString(id.Public().(ed25519.PublicKey)),
		PurposeKey: hex.EncodeToString(pk), Cert: c, CertMessage: hex.EncodeToString(kms.StoreCertMessage(c)), CertHeader: ch,
		Method: "PUT", Name: "side", Time: at, Gen: "4", Prev: "3", Body: base64.StdEncoding.EncodeToString(body),
		Message: string(StateMessage("PUT", "side", at, "4", "3", body)), AuthHeader: ah}
}

// The vector is what the code makes (UPDATE_GOLDEN=1 rewrites it), and the Go twin of the Worker accepts it.
func TestStateAuthVector(t *testing.T) {
	v := makeStateVector()
	got, _ := json.MarshalIndent(v, "", "  ")
	got = append(got, '\n')
	const path = "../testdata/vm-state-auth-v1.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatalf("%s is stale (UPDATE_GOLDEN=1 go test ./kmsvm): %v", path, err)
	}
	id, _ := kms.ParseID(v.KMSID)
	body, _ := base64.StdEncoding.DecodeString(v.Body)
	now := time.Unix(v.Time, 0).Add(30 * time.Second)
	if ns := CheckAuth(id, now, v.Method, v.Name, v.CertHeader, v.AuthHeader, v.Gen, v.Prev, body); ns != "agent-vm/state" {
		t.Fatalf("namespace %q", ns)
	}
	for name, bad := range map[string]func() string{
		"late": func() string {
			return CheckAuth(id, now.Add(3*time.Minute), v.Method, v.Name, v.CertHeader, v.AuthHeader, v.Gen, v.Prev, body)
		},
		"other name": func() string {
			return CheckAuth(id, now, v.Method, "activity", v.CertHeader, v.AuthHeader, v.Gen, v.Prev, body)
		},
		"other prev": func() string {
			return CheckAuth(id, now, v.Method, v.Name, v.CertHeader, v.AuthHeader, v.Gen, "2", body)
		},
		"other body": func() string {
			return CheckAuth(id, now, v.Method, v.Name, v.CertHeader, v.AuthHeader, v.Gen, v.Prev, []byte("x"))
		},
		"other kms": func() string {
			o, _, _ := ed25519.GenerateKey(nil)
			return CheckAuth(o, now, v.Method, v.Name, v.CertHeader, v.AuthHeader, v.Gen, v.Prev, body)
		},
	} {
		if bad() != "" {
			t.Errorf("%s accepted", name)
		}
	}
}
