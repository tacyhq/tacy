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
//	    release.ResolveAttestations), or the release asset compose.sigstore.json. "" = the bundle of a release the
//	    signed trust list taken names for that compose (verifier.Policy.Releases), if any. Output JSON below.
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
//
// In release mode the VM's app-compose.json (every CVM setting) must be exactly the one a release of its docker
// compose is deployed with (verifier.ReleaseAppCompose, key mode tacy.KMSFallback), and that docker compose a signed
// release. The deprecated exact mode checks the compose.yaml and app-compose.json embedded here (tacy.Compose,
// tacy.AppCompose).
//
//	setTrustList(envelopeJSON, minSeq, nowISO?, seenJSON?) -> string
//	    Takes a signed trust list (admin keys pinned in package verifier) for later checks: JSON verifier.TrustInfo,
//	    with releaseEntries (the list's VM releases and their Sigstore bundles) for a client's bundle lookup. Each
//	    later check applies the list again (it may have expired): its OS images, boot sets, pre-launch scripts and
//	    Tacy KMS ids next to the built-in ones, its release floor, and its VM releases.
//	appComposeSha256: the embedded app-compose.json's hash (exact mode).
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
	// AppComposeSHA256 is the pinned app-compose.json's (with a bundle, the VM's, verified); TrustList the signed
	// trust list this check used, if any.
	AppComposeSHA256 string              `json:"appComposeSha256"`
	TrustList        *verifier.TrustInfo `json:"trustList,omitempty"`
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

// trust is the signed trust list setTrustList took (verifier.TrustState: the envelope, checked again at each verify,
// since it may have expired).
var trust verifier.TrustState

func appComposeSum() string {
	h := sha256.Sum256(tacy.AppCompose)
	return hex.EncodeToString(h[:])
}

// run verifies an attestation. bundle nil = the deprecated exact mode against the embedded compose.
func run(attJSON, nonceHex string, bundle []byte, fetch js.Value, now, lastSeen string) output {
	out := output{Checks: []verifier.Check{}, Facts: map[string]string{}, ComposeSHA256: composeSum(), AppComposeSHA256: appComposeSum()}
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
	p := verifier.Policy{Bundle: bundle, Getter: jsGetter{fetch}, Release: release.Policy{LastSeen: lastSeen},
		KMSFallback: tacy.KMSFallback}
	if bundle == nil {
		p.Compose, p.AppCompose = tacy.Compose, tacy.AppCompose
	}
	if now != "" {
		t, err := time.Parse(time.RFC3339, now)
		if err != nil {
			return fail(fmt.Errorf("bad time: %w", err))
		}
		p.Now = t
	}
	at := p.Now
	if at.IsZero() {
		at = time.Now()
	}
	p, out.TrustList = trust.Apply(p, at)
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
		out.AppComposeSHA256 = res.Facts["app-compose sha256"]
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
	api.Set("appComposeSha256", appComposeSum())
	// setTrustList(envelopeJSON, minSeq, nowISO?, seenJSON?) -> JSON verifier.TrustInfo: takes a signed trust list for
	// later checks if it is signed by the pinned admin keys, not expired and its seq is at least minSeq ("" clears it).
	// seenJSON is the caller's record of the list's items (the last answer's seen; none: every addition waits): only
	// what has been listed for 24 h counts (safety/trustdelay.go); the answer's seen is the record to keep, its
	// pending what doesn't count yet, its releaseEntries the list's VM releases that count (with their Sigstore
	// bundles) for a release-mode client's lookup.
	api.Set("setTrustList", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if len(a) < 2 || a[0].Type() != js.TypeString || a[1].Type() != js.TypeNumber {
			b, _ := json.Marshal(verifier.TrustInfo{Error: "setTrustList(envelopeJSON, minSeq, nowISO?, seenJSON?)"})
			return string(b)
		}
		now := time.Now()
		if len(a) > 2 && a[2].Type() == js.TypeString && a[2].String() != "" {
			t, err := time.Parse(time.RFC3339, a[2].String())
			if err != nil {
				b, _ := json.Marshal(verifier.TrustInfo{Error: "bad time: " + err.Error()})
				return string(b)
			}
			now = t
		}
		minSeq := a[1].Float()
		if minSeq < 0 || minSeq > 1<<53 {
			minSeq = 1 << 53
		}
		var seen []byte
		if len(a) > 3 && a[3].Type() == js.TypeString {
			seen = []byte(a[3].String())
		}
		b, _ := json.Marshal(trust.TakeSeen([]byte(a[0].String()), uint64(minSeq), now, seen))
		return string(b)
	}))
	js.Global().Set("sealedAgentVM", api)
	select {}
}
