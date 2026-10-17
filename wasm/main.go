//go:build js && wasm

// wasm is the agent VM verifier (package verifier, all of its checks) compiled to WebAssembly for the browser:
//
//	cd wasm && GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w" -o verifier.wasm .
//
// It registers globalThis.sealedAgentVM (name kept from before the rename; clients look it up) and stays running:
//
//	verifyRelease(attestationJSON, nonceHex, bundleJSON, fetchCollateral, nowISO?, lastSeenVersion?) -> Promise<string>
//	    Every check, and the VM's docker compose must be a signed release (package release): bundleJSON is the
//	    Sigstore bundle for sha256(docker compose), as JSON: one "bundle" of GitHub's attestations API response for
//	    that digest (an entry with only a bundle_url must be fetched and Snappy-decoded first, e.g. by a relay;
//	    release.ResolveAttestations), or the release asset compose.sigstore.json. Output JSON below.
//	verifyReleaseBundle(bundleJSON, composeSha256Hex, lastSeenVersion?) -> string
//	    Only the release check, for a compose hash (a verify page, or to check a bundle before an attestation).
//	    JSON {ok, error?, release?: {version, commit, compose_sha256, identity, run_url, log_index, signed_at}}.
//	lastSeenVersion ("vX.Y.Z", optional, "" or undefined = none) is the newest release this client accepted
//	    before (keep release.version / facts.release): an older release is refused (rollback protection).
//	verify(attestationJSON, nonceHex, fetchCollateral, nowISO?) -> Promise<string>
//	    Deprecated: the older exact mode, against the compose.yaml embedded in this binary (tacy.Compose).
//	releaseIdentity, minVersion, composeSha256: the pinned signer prefix, minimum version, embedded compose hash.
//
// fetchCollateral(url) is called for Intel PCS URLs (TCB info, QE identity, PCK CRL, root CA CRL) and must resolve
// to {status, headers: {name: value}, body: Uint8Array}. A client can map them to a same-origin relay; Intel's
// signatures are checked here, so the relay can only withhold collateral (verification fails), not forge it.
// nowISO is for tests with recorded collateral only.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/textproto"
	"syscall/js"
	"time"

	"github.com/tacyhq/tacy"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/verifier"
)

type output struct {
	OK            bool              `json:"ok"`
	Error         string            `json:"error,omitempty"`
	HPKEPublicKey string            `json:"hpkePublicKey,omitempty"`
	Checks        []verifier.Check  `json:"checks"`
	Facts         map[string]string `json:"facts"`
	ComposeSHA256 string            `json:"composeSha256"` // the embedded compose's; with a bundle, the VM's (verified)
}

// jsGetter fetches collateral through a JS function returning a Promise.
type jsGetter struct{ fetch js.Value }

func (g jsGetter) Get(url string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g jsGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	v, err := await(ctx, g.fetch.Invoke(url))
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	status := v.Get("status").Int()
	if status >= 300 {
		return nil, nil, fmt.Errorf("fetch %s: HTTP %d", url, status)
	}
	headers := map[string][]string{}
	if h := v.Get("headers"); h.Type() == js.TypeObject {
		keys := js.Global().Get("Object").Call("keys", h)
		for i := 0; i < keys.Length(); i++ {
			k := keys.Index(i).String()
			headers[textproto.CanonicalMIMEHeaderKey(k)] = []string{h.Get(k).String()}
		}
	}
	b := v.Get("body")
	body := make([]byte, b.Get("length").Int())
	js.CopyBytesToGo(body, b)
	return headers, body, nil
}

// await blocks this goroutine (not the JS event loop) until p settles.
func await(ctx context.Context, p js.Value) (js.Value, error) {
	type res struct {
		v   js.Value
		err error
	}
	ch := make(chan res, 1)
	var then, catch js.Func
	then = js.FuncOf(func(_ js.Value, a []js.Value) any {
		ch <- res{v: a[0]}
		return nil
	})
	catch = js.FuncOf(func(_ js.Value, a []js.Value) any {
		msg := "rejected"
		if len(a) > 0 && a[0].Truthy() {
			msg = a[0].Call("toString").String()
		}
		ch <- res{err: errors.New(msg)}
		return nil
	})
	defer then.Release()
	defer catch.Release()
	p.Call("then", then, catch)
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return js.Undefined(), ctx.Err()
	}
}

func composeSum() string {
	h := sha256.Sum256(tacy.Compose)
	return hex.EncodeToString(h[:])
}

// run verifies an attestation. bundle nil = the deprecated exact mode against the embedded compose.
func run(attJSON, nonceHex string, bundle []byte, fetch js.Value, now, lastSeen string) output {
	out := output{Checks: []verifier.Check{}, Facts: map[string]string{}, ComposeSHA256: composeSum()}
	fail := func(err error) output {
		out.OK, out.Error, out.HPKEPublicKey = false, err.Error(), ""
		return out
	}
	var att proto.Attestation
	if err := json.Unmarshal([]byte(attJSON), &att); err != nil {
		return fail(fmt.Errorf("attestation isn't JSON: %w", err))
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		return fail(errors.New("nonce must be 32 bytes of hex"))
	}
	p := verifier.Policy{Bundle: bundle, Getter: jsGetter{fetch}, Release: release.Policy{LastSeen: lastSeen}}
	if bundle == nil {
		p.Compose = tacy.Compose
	}
	if now != "" {
		t, err := time.Parse(time.RFC3339, now)
		if err != nil {
			return fail(fmt.Errorf("bad time: %w", err))
		}
		p.Now = t
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := verifier.Verify(ctx, &att, nonce, p)
	if res != nil {
		out.Checks, out.Facts = res.Checks, res.Facts
	}
	if err != nil {
		return fail(err)
	}
	out.OK = true
	out.HPKEPublicKey = hex.EncodeToString(res.HPKEPublicKey)
	if bundle != nil {
		out.ComposeSHA256 = res.Facts["docker compose sha256"]
	}
	return out
}

// promise runs f on a goroutine (it may block on fetchCollateral) and resolves with its JSON.
func promise(f func() output) js.Value {
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, pa []js.Value) any {
		resolve := pa[0]
		go func() {
			defer executor.Release()
			b, _ := json.Marshal(f())
			resolve.Invoke(string(b))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

func reject(msg string) js.Value { return js.Global().Get("Promise").Call("reject", msg) }

func optString(a []js.Value, i int) string {
	if len(a) > i && a[i].Type() == js.TypeString {
		return a[i].String()
	}
	return ""
}

func main() {
	verify := js.FuncOf(func(_ js.Value, a []js.Value) any {
		if len(a) < 3 || a[0].Type() != js.TypeString || a[1].Type() != js.TypeString || a[2].Type() != js.TypeFunction {
			return reject("verify(attestationJSON, nonceHex, fetchCollateral, nowISO?)")
		}
		att, nonce, fetch, now := a[0].String(), a[1].String(), a[2], optString(a, 3)
		return promise(func() output { return run(att, nonce, nil, fetch, now, "") })
	})
	verifyRelease := js.FuncOf(func(_ js.Value, a []js.Value) any {
		if len(a) < 4 || a[0].Type() != js.TypeString || a[1].Type() != js.TypeString || a[2].Type() != js.TypeString ||
			a[3].Type() != js.TypeFunction {
			return reject("verifyRelease(attestationJSON, nonceHex, bundleJSON, fetchCollateral, nowISO?, lastSeenVersion?)")
		}
		att, nonce, bundle, fetch, now := a[0].String(), a[1].String(), []byte(a[2].String()), a[3], optString(a, 4)
		lastSeen := optString(a, 5)
		return promise(func() output { return run(att, nonce, bundle, fetch, now, lastSeen) })
	})
	verifyReleaseBundle := js.FuncOf(func(_ js.Value, a []js.Value) any {
		type out struct {
			OK      bool             `json:"ok"`
			Error   string           `json:"error,omitempty"`
			Release *release.Release `json:"release,omitempty"`
		}
		var o out
		d, err := hex.DecodeString(optString(a, 1))
		if len(a) < 2 || a[0].Type() != js.TypeString || err != nil || len(d) != 32 {
			o.Error = "verifyReleaseBundle(bundleJSON, composeSha256Hex, lastSeenVersion?)"
		} else if r, err := release.Verify([]byte(a[0].String()), d, release.Policy{LastSeen: optString(a, 2)}); err != nil {
			o.Error = err.Error()
		} else {
			o.OK, o.Release = true, r
		}
		b, _ := json.Marshal(o)
		return string(b)
	})
	api := js.Global().Get("Object").New()
	api.Set("verify", verify)
	api.Set("verifyRelease", verifyRelease)
	api.Set("verifyReleaseBundle", verifyReleaseBundle)
	api.Set("composeSha256", composeSum())
	api.Set("releaseIdentity", release.Policy{}.Identity())
	api.Set("minVersion", release.Policy{}.Minimum())
	js.Global().Set("sealedAgentVM", api)
	select {}
}
