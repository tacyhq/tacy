// Package kmsvm is a VM process's side of the Tacy key service (the keys plan §2.4, §3.2): at boot it asks the key service
// for the process's own purposes (kms/client: a fresh attestation bound to this process's boot key, a reply only the
// pinned KMS id signed, sealed to that key), then keeps its instance lease renewed, gives sealstate the generation
// register, and signs the process's calls to the chat Worker's sealed-state API with the store-auth key the KMS id
// certified.
//
// agentd asks for state/v1, activity-sign/v1 and task-ids/v1 (holder "agentd"); vaultd for conn/v1 (holder
// "vaultd"), and only its release carries the API keys from the secrets bundle. Each holds its own lease. Both reach
// the key service through gatewayd (gateway.KMSTransport), which lets each socket ask only for its own purposes
// (gateway.KMSGate). Releases, leases and the register are the primary's (replica 0, the first -kms-url): the VM
// talks to no other replica for them.
//
// Fail closed: a lease that can't be renewed before it lapses, or a renewal the key service refuses, calls OnLost
// (the process stops): another instance may hold the lease by then, and only one may serve.
package kmsvm

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/sealstate"
)

// Config is one process's key service setup.
type Config struct {
	KMSID     ed25519.PublicKey                    // the compose's -kms-key
	Hosts     int                                  // how many replicas gatewayd knows (its -kms-url, in order; 0 is the primary)
	Transport func(host int) client.Transport      // gateway.KMSTransport on the CVM
	Evidence  client.Evidence                      // dstack's GetQuote and Info
	Platform  string                               // "dstack"; "local" against a development kmsd only
	Release   string                               // this VM's release (vX.Y.Z); "" lets kmsd take the pinned one
	Purposes  []string                             // this process's own
	Holder    string                               // this process's lease ("agentd", "vaultd")
	Wait      time.Duration                        // keep trying this long (a lease the last boot held frees within kms.LeaseTTL); 0: 6 min
	Now       func() time.Time                     // nil: time.Now
	Sleep     func(context.Context, time.Duration) // nil: a timer
	Logf      func(string, ...any)                 // nil: log.Printf
	// OnLost is called once when the lease is lost (refused, or not renewed before it lapsed): the process must
	// stop serving. nil: log.Fatalf.
	OnLost func(error)
}

// Keys is what a release gave this process, with the replica that gave it.
type Keys struct {
	cfg  Config
	c    *client.Client
	mu   sync.Mutex
	k    *client.Keys
	lost error
}

// Boot releases cfg.Purposes from the primary, again every few seconds until cfg.Wait passes (the key service may be
// locked after a cold start, or the previous boot's lease not expired yet). Every try uses the same boot key, made
// here: the lease is bound to it. A reply the pinned KMS id didn't sign ends it at once.
func Boot(ctx context.Context, cfg Config) (*Keys, error) {
	if len(cfg.KMSID) != ed25519.PublicKeySize || cfg.Hosts < 1 || cfg.Transport == nil || cfg.Evidence == nil || len(cfg.Purposes) == 0 {
		return nil, errors.New("kmsvm: a KMS id, at least one host, a transport, evidence and purposes are required")
	}
	if !kms.ValidHolder(cfg.Holder) {
		return nil, errors.New("kmsvm: a holder name is required (agentd, vaultd)")
	}
	if cfg.Wait == 0 {
		cfg.Wait = 6 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.OnLost == nil {
		cfg.OnLost = func(err error) { log.Fatalf("keys: %v", err) }
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
	bootKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	c, err := client.New(client.Config{KMSID: cfg.KMSID, Transport: cfg.Transport(0), Evidence: cfg.Evidence,
		Platform: cfg.Platform, Release: cfg.Release, Holder: cfg.Holder, Key: bootKey, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	deadline := cfg.Now().Add(cfg.Wait)
	for try := 0; ; try++ {
		k, err := c.Release(ctx, cfg.Purposes)
		if err == nil {
			cfg.Logf("keys: released %s to %s by the key service (app %s, epoch %d, lease %d, audit entry %d)",
				strings.Join(cfg.Purposes, ","), cfg.Holder, k.App, k.Epoch, k.Lease.Seq, k.LogSeq)
			return &Keys{cfg: cfg, c: c, k: k}, nil
		}
		if errors.Is(err, client.ErrBadSignature) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if cfg.Now().After(deadline) {
			return nil, fmt.Errorf("kmsvm: no key service release after %s: %w", cfg.Wait, err)
		}
		if try%6 == 0 {
			cfg.Logf("keys: waiting for the key service: %v", err)
		}
		cfg.Sleep(ctx, 5*time.Second)
	}
}

// Key is a copy of purpose's 32-byte key.
func (k *Keys) Key(_ context.Context, purpose string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, err := k.k.Key(purpose)
	if err != nil {
		return nil, err
	}
	return slices.Clone(b), nil
}

// App is the key service's app name (the namespace of this VM's keys and sealed state).
func (k *Keys) App() string { return k.k.App }

// Firm is the app's firm (part of every key's derivation).
func (k *Keys) Firm() string { return k.k.Firm }

// Secrets are the app's API keys from the secrets bundle (vaultd's release).
func (k *Keys) Secrets() map[string]string { return k.k.Secrets }

// Lease is the instance lease this process holds now.
func (k *Keys) Lease() kms.Lease {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.k.Lease
}

// Renew keeps the lease: every period (0: a third of kms.LeaseTTL) until ctx ends. A renewal the key service
// refuses, or none that got through before the lease's expiry (less a margin for clock drift), loses the lease:
// OnLost, once, and nothing more is committed.
func (k *Keys) Renew(ctx context.Context, period time.Duration) {
	if period <= 0 {
		period = kms.LeaseTTL / 3
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(period):
		}
		if err := k.RenewOnce(ctx); err != nil && ctx.Err() == nil {
			if k.Lost() != nil {
				return
			}
			k.cfg.Logf("keys: lease renewal failed (will retry before it lapses): %v", err)
		}
	}
}

// RenewOnce renews the lease now. A refusal, or a failure once the lease is about to lapse, loses it (OnLost).
func (k *Keys) RenewOnce(ctx context.Context) error {
	k.mu.Lock()
	if k.lost != nil {
		k.mu.Unlock()
		return k.lost
	}
	_, err := k.c.Renew(ctx, k.k)
	var lost error
	var re *client.RefusedError
	switch {
	case err == nil:
	case errors.As(err, &re) || errors.Is(err, client.ErrBadSignature):
		lost = fmt.Errorf("the key service refused the lease renewal: %w", err)
	case !k.cfg.Now().Before(time.Unix(k.k.Lease.Expires, 0).Add(-renewMargin)):
		lost = fmt.Errorf("the lease lapses without a renewal: %w", err)
	}
	if lost != nil {
		k.lost = lost
	}
	k.mu.Unlock()
	if lost != nil {
		k.cfg.OnLost(lost)
		return lost
	}
	return err
}

// renewMargin: a lease counts as lost this long before it expires on the key service's clock (drift between them).
const renewMargin = 20 * time.Second

// Lost is why the lease was lost, or nil.
func (k *Keys) Lost() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lost
}

// live is an error unless the lease is held and not about to lapse (k.mu held).
func (k *Keys) live() error {
	if k.lost != nil {
		return k.lost
	}
	if !k.cfg.Now().Before(time.Unix(k.k.Lease.Expires, 0).Add(-renewMargin)) {
		return errors.New("kmsvm: the lease is lapsing")
	}
	return nil
}

// Drop frees this process's lease (a clean stop): its next boot takes it at once. Each process drops only its own.
func (k *Keys) Drop(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.c.Drop(ctx, k.k)
}

// Register is the key service's generation register for purpose's states (sealstate.Register): entries are named
// "<purpose tag>/<state name>" in the app's register, so agentd's and vaultd's states never share one.
func (k *Keys) Register(purpose string) *Register { return &Register{k: k, tag: Tag(purpose)} }

// Tag is a state purpose's short name ("state/v1" -> "state"): the register's prefix and the Worker's namespace.
func Tag(purpose string) string { t, _, _ := strings.Cut(purpose, "/"); return t }

// Register implements sealstate.Register on the key service (the primary).
type Register struct {
	k   *Keys
	tag string
}

// refused wraps a refusal (or a reply not signed by the KMS id) as sealstate.ErrRefused: the Store stops.
func refused(err error) error {
	var re *client.RefusedError
	if errors.As(err, &re) || errors.Is(err, client.ErrBadSignature) {
		return fmt.Errorf("%w: %w", sealstate.ErrRefused, err)
	}
	return err
}

func (r *Register) Generation(ctx context.Context, name string) (sealstate.Entry, error) {
	g, err := r.k.c.Generation(ctx, r.k.k.App, r.tag+"/"+name)
	if err != nil {
		return sealstate.Entry{}, err
	}
	return sealstate.Entry{Gen: g.Gen.Gen, Hash: g.Gen.Hash, Prev: g.Prev, Stored: g.Stored}, nil
}

func (r *Register) Reserve(ctx context.Context, name string, gen uint64, hash string) error {
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	if err := r.k.live(); err != nil {
		return fmt.Errorf("%w: %w", sealstate.ErrRefused, err)
	}
	_, err := r.k.c.Reserve(ctx, r.k.k, r.tag+"/"+name, gen, hash)
	return refused(err)
}

func (r *Register) Stored(ctx context.Context, name string, gen uint64, hash string) error {
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	if err := r.k.live(); err != nil {
		return fmt.Errorf("%w: %w", sealstate.ErrRefused, err)
	}
	_, err := r.k.c.MarkStored(ctx, r.k.k, r.tag+"/"+name, gen, hash)
	return refused(err)
}

// StoreAuth signs requests to the Worker's sealed-state API with purpose's store-auth key (sealstate.Relay's Auth).
func (k *Keys) StoreAuth(purpose string) (func(*http.Request), error) {
	k.mu.Lock()
	cert, ok := k.k.Certs[purpose]
	key, kerr := k.k.Key(purpose)
	k.mu.Unlock()
	if !ok || kerr != nil {
		return nil, fmt.Errorf("kmsvm: no store certificate for %s", purpose)
	}
	sk, err := kms.StoreAuthKey(key)
	if err != nil {
		return nil, err
	}
	now := k.cfg.Now
	return func(req *http.Request) {
		var body []byte
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				body, _ = io.ReadAll(rc)
				rc.Close()
			}
		}
		name := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		c, a := SignState(sk, cert, req.Method, name, now().Unix(), req.Header.Get("X-Tacy-Gen"), req.Header.Get("X-Tacy-Prev-Gen"), body)
		req.Header.Set("X-Tacy-Cert", c)
		req.Header.Set("X-Tacy-Auth", a)
	}, nil
}

// StateLabel starts what a store-auth key signs on a sealed-state request.
const StateLabel = "tacy/vm-state/v1"

// StateMessage is what a store-auth key signs on a sealed-state request (the chat Worker checks it, vm-state.ts):
//
//	"tacy/vm-state/v1" \n METHOD \n name \n unix seconds \n X-Tacy-Gen \n X-Tacy-Prev-Gen \n hex(sha256(body)) \n
//
// (the two generations "" on a GET).
func StateMessage(method, name string, at int64, gen, prev string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(StateLabel + "\n" + method + "\n" + name + "\n" + strconv.FormatInt(at, 10) + "\n" + gen + "\n" + prev + "\n" +
		hex.EncodeToString(h[:]) + "\n")
}

// SignState makes the two headers of a sealed-state request: X-Tacy-Cert (the StoreCert's JSON, base64url) and
// X-Tacy-Auth ("t=<unix seconds>,s=<base64url signature over StateMessage>").
func SignState(sk ed25519.PrivateKey, cert kms.StoreCert, method, name string, at int64, gen, prev string, body []byte) (string, string) {
	cb, _ := json.Marshal(cert)
	sig := ed25519.Sign(sk, StateMessage(method, name, at, gen, prev, body))
	return base64.RawURLEncoding.EncodeToString(cb), "t=" + strconv.FormatInt(at, 10) + ",s=" + base64.RawURLEncoding.EncodeToString(sig)
}

// LocalAppCompose is the app-compose.json a development VM (platform local, no TDX) reports to a development kmsd
// (-dev-local), whose policy pins its sha256. Nothing about it is attested.
const LocalAppCompose = `{"docker_compose_file":"services:\n  agentvm:\n    image: local-development\n","runner":"docker-compose"}`

// LocalEvidence is a development VM's evidence: no quote, and an Info naming LocalAppCompose and instance.
func LocalEvidence(instance string) client.Evidence {
	return func(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
		tcb, _ := json.Marshal(map[string]string{"app_compose": LocalAppCompose})
		b, _ := json.Marshal(map[string]string{"app_id": "local", "instance_id": instance, "tcb_info": string(tcb)})
		return nil, b, nil
	}
}
