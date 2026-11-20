// Package kmsdev runs a development key service in this process: a real kmsd (package kms/server) with no TDX
// (-dev-local: nothing is attested), its genesis done, a policy for the agent VM app and a secrets bundle. For tests
// and local runs only; never in a release (a development kmsd releases keys to anyone who asks as platform local).
package kmsdev

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/safety"
)

// App and Firm are the development agent VM's app in the key service's policy; Release its pinned release.
const (
	App     = "agent-vm"
	Firm    = "f_chat"
	Release = "v0.21.0"
)

// LocalVMAppCompose must equal kmsvm.LocalAppCompose (a development VM's app-compose.json; checked by kmsvm's tests).
const LocalVMAppCompose = `{"docker_compose_file":"services:\n  agentvm:\n    image: local-development\n","runner":"docker-compose"}`

// Dev is a running development key service.
type Dev struct {
	Server *server.Server
	KMSID  ed25519.PublicKey
	Admin  ed25519.PrivateKey
	Policy kms.Policy
	// Recipients hold the genesis shares (P-256, in memory).
	Recipients []*ecdh.PrivateKey
	Genesis    *kms.GenesisReply
}

// Options change the development policy.
type Options struct {
	Purposes []string          // the app's purposes; nil: all but relay-auth
	Secrets  map[string]string // the secrets bundle; nil: test values for TINFOIL, EXA and TAVILY
	Now      func() time.Time
}

type localPlatform struct{}

func (localPlatform) Name() string { return "local" }
func (localPlatform) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	return nil, server.LocalInfo("local-kms"), nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Start makes an unlocked development key service.
func Start(o Options) (*Dev, error) {
	if o.Purposes == nil {
		o.Purposes = []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1", "notify/v1", "operator/v1"}
	}
	if o.Secrets == nil {
		o.Secrets = map[string]string{"TINFOIL_API_KEY": "tk-dev-tinfoil", "EXA_API_KEY": "exa-dev", "TAVILY_API_KEY": "tvly-dev"}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	adminPub, admin, _ := ed25519.GenerateKey(rand.Reader)
	var names []string
	for n := range o.Secrets {
		names = append(names, n)
	}
	d := &Dev{Admin: admin, Policy: kms.Policy{Epoch: 1, Seq: 1, IssuedAt: o.Now().UTC(), Floor: "v0.0.1",
		Apps:     map[string]kms.AppPolicy{App: {Firm: Firm, Purposes: o.Purposes, Secrets: names}},
		Releases: []kms.ReleasePin{{App: App, Version: Release, AppComposeSHA256: sum([]byte(LocalVMAppCompose))}},
		KMS:      []kms.ReleasePin{{App: "kms", Version: "v0.1.0", AppComposeSHA256: sum([]byte(server.LocalAppCompose))}}}}
	s, err := server.New(server.Config{Admin: kms.AdminKeys{Keys: []ed25519.PublicKey{adminPub}, Threshold: 1},
		Platform: localPlatform{}, Now: o.Now, DevLocal: true})
	if err != nil {
		return nil, err
	}
	d.Server = s
	for range 3 {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		d.Recipients = append(d.Recipients, k)
	}
	key, err := d.attest()
	if err != nil {
		return nil, err
	}
	var recips []string
	for _, k := range d.Recipients {
		recips = append(recips, kms.RecipientString(k.PublicKey()))
	}
	doc := kms.GenesisDoc{Recipients: recips, Threshold: 2, AdminKeys: []string{kms.IDString(adminPub)}, AdminThreshold: 1,
		Floor: "v0.0.1", Target: hex.EncodeToString(key.Bytes()), IssuedAt: o.Now().UTC()}
	var rep kms.GenesisReply
	if err := d.call("POST", "/v1/genesis", kms.GenesisRequest{Genesis: d.Sign(kms.KindGenesis, doc), Policy: d.Sign(kms.KindPolicy, d.Policy)}, &rep); err != nil {
		return nil, fmt.Errorf("kmsdev genesis: %w", err)
	}
	d.Genesis = &rep
	if d.KMSID, err = kms.ParseID(rep.KMSID); err != nil {
		return nil, err
	}
	// The policy bound to the new KMS id (kmsctl genesis does the same): what unlocks and joins take.
	d.Policy.KMSID, d.Policy.Seq = rep.KMSID, 2
	if err := d.call("POST", "/v1/policy", d.Sign(kms.KindPolicy, d.Policy), nil); err != nil {
		return nil, fmt.Errorf("kmsdev policy: %w", err)
	}
	if err := d.PutSecrets(1, o.Secrets, o.Now); err != nil {
		return nil, err
	}
	return d, nil
}

// Sign signs v as an admin document of kind.
func (d *Dev) Sign(kind string, v any) safety.Envelope {
	b, _ := json.Marshal(v)
	return safety.Sign(kind, b, d.Admin)
}

// Handler is kmsd's HTTP API.
func (d *Dev) Handler() http.Handler { return d.Server.Handler() }

// HTTP serves the API on a local listener (close it when done).
func (d *Dev) HTTP() *httptest.Server { return httptest.NewServer(d.Handler()) }

func (d *Dev) call(method, path string, in, out any) error {
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	req := httptest.NewRequest(method, "http://kms"+path, bytes.NewReader(b))
	w := httptest.NewRecorder()
	d.Server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return fmt.Errorf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	if out != nil {
		return kms.Strict(w.Body.Bytes(), out)
	}
	return nil
}

// attest is kmsctl's first step: the replica's attestation, checked against the policy's KMS pins (nothing is
// attested in development).
func (d *Dev) attest() (*ecdh.PublicKey, error) {
	n := make([]byte, 32)
	rand.Read(n)
	req := httptest.NewRequest("GET", "http://kms/v1/attest?nonce="+hex.EncodeToString(n), nil)
	w := httptest.NewRecorder()
	d.Server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return nil, errors.New("kmsdev: attest: " + w.Body.String())
	}
	a, err := server.VerifyKMS(context.Background(), w.Body.Bytes(), n, &d.Policy, server.CheckOptions{DevLocal: true})
	if err != nil {
		return nil, err
	}
	return a.Key, nil
}

// PutSecrets is kmsctl secret-put: a new secrets bundle.
func (d *Dev) PutSecrets(seq uint64, values map[string]string, now func() time.Time) error {
	key, err := d.attest()
	if err != nil {
		return err
	}
	env, _ := json.Marshal(d.Sign(kms.KindSecrets, kms.SecretsDoc{KMSID: kms.IDString(d.KMSID), Epoch: 1, Seq: seq, Values: values, IssuedAt: now().UTC()}))
	box, err := kms.Seal(key, kms.LabelSecretPut, []byte(d.Server.Status().KMSID), env)
	if err != nil {
		return err
	}
	var rep kms.SecretsReply
	return d.call("POST", "/v1/secrets/put", kms.SecretsPut{Sealed: box}, &rep)
}
