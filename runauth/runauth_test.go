package runauth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/proto"
)

func xkey(t *testing.T, h string) *ecdh.PrivateKey {
	b, _ := hex.DecodeString(h)
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func edkey(h string) ed25519.PrivateKey {
	b, _ := hex.DecodeString(h)
	return ed25519.NewKeyFromSeed(b)
}

// ---- golden vectors (the chat's src/client/agent/run-auth.ts replays the same file) -------------------------------

type vectors struct {
	Format    string `json:"format"`
	Note      string `json:"note"`
	Constants struct {
		Labels map[string]string `json:"labels"`
	} `json:"constants"`
	VM       string `json:"vm_private"` // hex: test keys from fixed seeds, never real ones
	VMPublic string `json:"vm_public"`  // hex
	Seal     string `json:"seal_private"`
	SealPub  string `json:"seal"`
	Space    string `json:"space"`
	Proof    string `json:"proof"` // base64
	Identity struct {
		Seed string `json:"seed"`
		ID   string `json:"id"`
		Key  string `json:"key"`
	} `json:"identity"`
	Requests []struct {
		Name   string `json:"name"`
		Body   string `json:"body"`   // the exact JSON body, identity_sig included
		Digest string `json:"digest"` // hex
	} `json:"requests"`
	Refused []struct {
		Why  string `json:"why"`
		Body string `json:"body"`
	} `json:"refused"`
}

const at = 1_792_000_000

func makeVectors(t *testing.T) *vectors {
	vm := xkey(t, strings.Repeat("71", 32))
	seal := xkey(t, strings.Repeat("72", 32))
	id := edkey(strings.Repeat("73", 32))
	space := IDFrom("s", [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	a := &Asker{Space: space, Seal: seal, Identity: IDFrom("i", [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}), Key: id,
		Now: func() time.Time { return time.Unix(at, 0) }}
	v := &vectors{Format: "tacy-golden-crypto-vectors",
		Note: "Keys v2 slice 6: a run request's space proof and identity signature (runauth, TestVectors). Made once from fixed seeds; never regenerate.",
		VM:   hex.EncodeToString(vm.Bytes()), VMPublic: hex.EncodeToString(vm.PublicKey().Bytes()),
		Seal: hex.EncodeToString(seal.Bytes()), SealPub: SealString(seal.PublicKey()), Space: space}
	v.Constants.Labels = map[string]string{"spaceProof": ProofLabel, "runRequest": RequestLabel}
	v.Identity.Seed, v.Identity.ID, v.Identity.Key = strings.Repeat("73", 32), a.Identity, EdString(id.Public().(ed25519.PublicKey))
	p, err := SpaceProof(seal, vm.PublicKey(), space, v.SealPub, vm.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	v.Proof = base64.StdEncoding.EncodeToString(p)
	nonce := 0
	sign := func(r proto.RunRequest) proto.RunRequest {
		t.Helper()
		if err := a.Authorize(&r, vm.PublicKey().Bytes()); err != nil {
			t.Fatal(err)
		}
		nonce++
		r.Nonce = strings.Repeat(hex.EncodeToString([]byte{byte(nonce)}), 16) // fixed nonces, so the file is stable
		b, _ := json.Marshal(r)
		var w proto.RunRequest
		json.Unmarshal(b, &w)
		r.IdentitySig = Sign(id, &w, vm.PublicKey().Bytes())
		return r
	}
	add := func(name string, r proto.RunRequest) {
		r = sign(r)
		b, _ := json.Marshal(r)
		var w proto.RunRequest
		json.Unmarshal(b, &w)
		d := Digest(&w, vm.PublicKey().Bytes())
		v.Requests = append(v.Requests, struct {
			Name   string `json:"name"`
			Body   string `json:"body"`
			Digest string `json:"digest"`
		}{name, string(b), hex.EncodeToString(d[:])})
	}
	add("minimal", proto.RunRequest{Model: "gpt-oss-120b", Messages: []proto.Message{{Role: "user", Content: "hi"}}})
	full := proto.RunRequest{Model: "kimi-k3", ReasoningEffort: "high", Tools: []string{"web_search", "fetch_page"}, MaxSteps: 3,
		CacheSecret: "cache ü 秘密", RunSecret: strings.Repeat("ab", 32),
		Permissions:    map[string]string{"web.search": "ask", "web.fetch": "always", "web.images": "never"},
		FallbackModels: []string{"glm-5-3", "gemma4-31b"}, AutoFallback: true,
		Messages: []proto.Message{{Role: "system", Content: "Today is Friday, October 16, 2026.\nBe brief."},
			{Role: "user", Content: "Résumé ✓ 🙂 with a NUL \x00 and \"quotes\""}, {Role: "assistant", Content: ""},
			{Role: "user", Content: "and again"}}}
	add("full", full)
	add("no tools at all (an empty list, not absent)", proto.RunRequest{Model: "gpt-oss-120b", Tools: []string{},
		Messages: []proto.Message{{Role: "user", Content: "hi"}}})
	refuse := func(why string, r proto.RunRequest) {
		b, _ := json.Marshal(r)
		v.Refused = append(v.Refused, struct {
			Why  string `json:"why"`
			Body string `json:"body"`
		}{why, string(b)})
	}
	base := sign(proto.RunRequest{Model: "gpt-oss-120b", Messages: []proto.Message{{Role: "user", Content: "hi"}}})
	r := base
	r.Messages = []proto.Message{{Role: "user", Content: "hi!"}}
	refuse("a message changed after signing", r)
	r = base
	r.Space = IDFrom("s", [16]byte{9})
	refuse("another space with the same proof", r)
	r = base
	r.SpaceProof, _ = SpaceProof(xkey(t, strings.Repeat("74", 32)), vm.PublicKey(), base.Space, base.SpaceSeal, vm.PublicKey().Bytes())
	refuse("a proof made with another seal key", r)
	r = base
	r.Model = "kimi-k3"
	refuse("another model after signing", r)
	r = base
	r.Permissions = map[string]string{"web.search": "always"}
	refuse("permissions added after signing", r)
	r = base
	r.FallbackModels, r.AutoFallback = []string{"kimi-k3"}, true
	refuse("fallback models added after signing", r)
	r = base
	r.AutoFallback = true
	refuse("auto fallback turned on after signing", r)
	r = base
	b, _ := json.Marshal(r)
	var w proto.RunRequest
	json.Unmarshal(b, &w)
	r.IdentitySig = Sign(edkey(strings.Repeat("75", 32)), &w, vm.PublicKey().Bytes())
	refuse("signed by another key", r)
	r = base
	r.IdentitySig = Sign(id, &w, xkey(t, strings.Repeat("76", 32)).PublicKey().Bytes())
	refuse("signed for another VM", r)
	// Built-in agents (docs/30 slice 1), added after the vectors above: they keep their bytes (a request without an
	// agent hashes as before), and these come after them.
	add("research agent", proto.RunRequest{Model: "gpt-oss-120b", Agent: "a_research", RunSecret: strings.Repeat("cd", 32),
		Tools: []string{"web_search", "fetch_page"}, Permissions: map[string]string{"web.search": "always", "web.fetch": "always"},
		Messages: []proto.Message{{Role: "user", Content: "Brief: what changed in harbor lighting rules this year?"}}})
	r = base
	r.Agent = "a_research"
	refuse("an agent added after signing", r)
	return v
}

func TestVectors(t *testing.T) {
	want := makeVectors(t)
	path := "testdata/v2-run.json"
	if os.Getenv("RUNAUTH_WRITE_VECTORS") == "1" {
		b, _ := jsonv2.Marshal(want, jsonv2.Deterministic(true))
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := jsonv2.Marshal(want, jsonv2.Deterministic(true))
	if string(append(wb, '\n')) != string(b) {
		t.Fatal("testdata/v2-run.json differs from what the code makes (never regenerate it; fix the code)")
	}
	var got vectors
	if err := jsonv2.Unmarshal(b, &got, jsonv2.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	vm := xkey(t, got.VM)
	now := time.Unix(at, 0)
	for _, c := range got.Requests {
		var r proto.RunRequest
		if err := json.Unmarshal([]byte(c.Body), &r); err != nil {
			t.Fatal(err)
		}
		if d := Digest(&r, vm.PublicKey().Bytes()); hex.EncodeToString(d[:]) != c.Digest {
			t.Errorf("%s: digest", c.Name)
		}
		who, err := Check(vm, &r, now)
		if err != nil || who.Space != got.Space || who.Seal != got.SealPub || who.Identity != got.Identity.ID || who.Key != got.Identity.Key {
			t.Errorf("%s: %v %+v", c.Name, err, who)
		}
	}
	for _, c := range got.Refused {
		var r proto.RunRequest
		json.Unmarshal([]byte(c.Body), &r)
		if _, err := Check(vm, &r, now); err == nil {
			t.Errorf("%s: passed", c.Why)
		}
	}
	if got.Proof != base64.StdEncoding.EncodeToString(mustProof(t, xkey(t, got.Seal), vm, got.Space, got.SealPub)) {
		t.Error("proof")
	}
}

func mustProof(t *testing.T, seal, vm *ecdh.PrivateKey, space, sealPub string) []byte {
	p, err := SpaceProof(seal, vm.PublicKey(), space, sealPub, vm.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- checks ------------------------------------------------------------------------------------------------------

func TestCheckAndNonces(t *testing.T) {
	vm := xkey(t, strings.Repeat("71", 32))
	a, err := NewAsker()
	if err != nil {
		t.Fatal(err)
	}
	r := proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "hi"}}}
	if err := a.Authorize(&r, vm.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	if !IsID(r.Space, "s") || !IsID(r.Identity, "i") || IsID("s_chat", "s") || IsID(r.Space, "i") {
		t.Fatal("ids")
	}
	now := time.Unix(r.SignedAt, 0)
	if _, err := Check(vm, &r, now.Add(MaxSkew)); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{MaxSkew + time.Second, -MaxSkew - time.Second} {
		if _, err := Check(vm, &r, now.Add(d)); err == nil {
			t.Fatalf("signed_at %v away passed", d)
		}
	}
	// The all-zero seal key and a non-canonical spelling are refused.
	for _, s := range []string{"x25519:" + base64.StdEncoding.EncodeToString(make([]byte, 32)), strings.TrimSuffix(r.SpaceSeal, "=")} {
		if _, err := ParseSeal(s); err == nil {
			t.Fatalf("seal %q parsed", s)
		}
	}

	clock := now
	n := &Nonces{Now: func() time.Time { return clock }, Max: 4}
	if err := n.Claim(r.Nonce, r.SignedAt); err != nil {
		t.Fatal(err)
	}
	if err := n.Claim(r.Nonce, r.SignedAt); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	// Parallel: a nonce is taken once.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	m := &Nonces{Now: func() time.Time { return clock }}
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m.Claim("aa", r.SignedAt) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("one nonce taken %d times", ok)
	}
	// Full: refused until old ones can be forgotten (once their signed_at can't pass any more).
	for _, x := range []string{"b", "c", "d"} {
		if err := n.Claim(x, r.SignedAt); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Claim("e", r.SignedAt); !errors.Is(err, ErrBusy) {
		t.Fatalf("full: %v", err)
	}
	clock = clock.Add(MaxSkew + 2*time.Second)
	if err := n.Claim("e", clock.Unix()); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if err := n.Claim(r.Nonce, clock.Unix()); err != nil {
		t.Fatal("an expired nonce is forgotten (its request fails its time check anyway)")
	}
}

// ---- a search's and a pictures request's (v0.10.0; the chat's run-auth.ts replays testdata/v2-search.json) -------

type kindVector struct {
	Kind   string `json:"kind"` // "search" or "pictures"
	Name   string `json:"name"`
	Body   string `json:"body"`   // the exact JSON body, identity_sig included
	Digest string `json:"digest"` // hex
}

type kindVectors struct {
	Format    string `json:"format"`
	Note      string `json:"note"`
	Constants struct {
		Labels map[string]string `json:"labels"`
	} `json:"constants"`
	VM       string `json:"vm_private"`
	VMPublic string `json:"vm_public"`
	Seal     string `json:"seal_private"`
	SealPub  string `json:"seal"`
	Space    string `json:"space"`
	Identity struct {
		Seed string `json:"seed"`
		ID   string `json:"id"`
		Key  string `json:"key"`
	} `json:"identity"`
	Requests []kindVector `json:"requests"`
	Refused  []kindVector `json:"refused"` // Name is why; Digest empty
}

func makeKindVectors(t *testing.T) *kindVectors {
	vm := xkey(t, strings.Repeat("71", 32))
	seal := xkey(t, strings.Repeat("72", 32))
	id := edkey(strings.Repeat("73", 32))
	vmPub := vm.PublicKey().Bytes()
	space := IDFrom("s", [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	a := &Asker{Space: space, Seal: seal, Identity: IDFrom("i", [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}), Key: id,
		Now: func() time.Time { return time.Unix(at, 0) }}
	v := &kindVectors{Format: "tacy-golden-crypto-vectors",
		Note: "Keys v2 slice 6 (v0.10.0): a search's and a pictures request's space proof and identity signature (runauth, TestKindVectors). Made once from fixed seeds; never regenerate.",
		VM:   hex.EncodeToString(vm.Bytes()), VMPublic: hex.EncodeToString(vmPub),
		Seal: hex.EncodeToString(seal.Bytes()), SealPub: SealString(seal.PublicKey()), Space: space}
	v.Constants.Labels = map[string]string{"spaceProof": ProofLabel, "searchRequest": SearchLabel, "picturesRequest": PicturesLabel}
	v.Identity.Seed, v.Identity.ID, v.Identity.Key = strings.Repeat("73", 32), a.Identity, EdString(id.Public().(ed25519.PublicKey))
	nonce := 0x40
	fixed := func() string { // fixed nonces, so the file is stable
		nonce++
		return strings.Repeat(hex.EncodeToString([]byte{byte(nonce)}), 16)
	}
	signSearch := func(r proto.SearchRequest) proto.SearchRequest {
		t.Helper()
		if err := a.AuthorizeSearch(&r, vmPub); err != nil {
			t.Fatal(err)
		}
		r.Nonce = fixed()
		w, _ := onWire(&r)
		r.IdentitySig = SignSearch(id, w, vmPub)
		return r
	}
	signPictures := func(r proto.PicturesRequest) proto.PicturesRequest {
		t.Helper()
		if err := a.AuthorizePictures(&r, vmPub); err != nil {
			t.Fatal(err)
		}
		r.Nonce = fixed()
		w, _ := onWire(&r)
		r.IdentitySig = SignPictures(id, w, vmPub)
		return r
	}
	addSearch := func(name string, r proto.SearchRequest) {
		r = signSearch(r)
		b, _ := json.Marshal(r)
		w, _ := onWire(&r)
		d := SearchDigest(w, vmPub)
		v.Requests = append(v.Requests, kindVector{"search", name, string(b), hex.EncodeToString(d[:])})
	}
	addPictures := func(name string, r proto.PicturesRequest) {
		r = signPictures(r)
		b, _ := json.Marshal(r)
		w, _ := onWire(&r)
		d := PicturesDigest(w, vmPub)
		v.Requests = append(v.Requests, kindVector{"pictures", name, string(b), hex.EncodeToString(d[:])})
	}
	addSearch("minimal search", proto.SearchRequest{Query: "quiet keyboards", Decision: proto.SearchOnce})
	addSearch("full search", proto.SearchRequest{Query: "Résumé ✓ 🙂 \"quotes\"", Count: 8, Question: "which one?\nand why ü 秘密",
		Decision: proto.SearchAlways, Edited: true, CacheSecret: strings.Repeat("cd", 32)})
	addPictures("pictures", proto.PicturesRequest{Ticket: strings.Repeat("0f", 16)})

	refuse := func(kind, why string, r any) {
		b, _ := json.Marshal(r)
		v.Refused = append(v.Refused, kindVector{Kind: kind, Name: why, Body: string(b)})
	}
	sb := signSearch(proto.SearchRequest{Query: "quiet keyboards", Decision: proto.SearchOnce})
	r := sb
	r.Query = "quiet keyboards price"
	refuse("search", "the query changed after signing", r)
	r = sb
	r.Count = 8
	refuse("search", "the count changed after signing", r)
	r = sb
	r.Decision = proto.SearchAlways
	refuse("search", "the decision changed after signing", r)
	r = sb
	r.Edited = true
	refuse("search", "edited turned on after signing", r)
	r = sb
	r.Question = "something else"
	refuse("search", "the question changed after signing", r)
	r = sb
	r.Space = IDFrom("s", [16]byte{9})
	refuse("search", "another space with the same proof", r)
	r = sb
	w, _ := onWire(&sb)
	r.IdentitySig = ed25519.Sign(id, signed(RequestLabel, SearchDigest(w, vmPub)))
	refuse("search", "its digest signed under the run label", r)
	r = sb
	r.IdentitySig = SignSearch(id, w, xkey(t, strings.Repeat("76", 32)).PublicKey().Bytes())
	refuse("search", "signed for another VM", r)
	pb := signPictures(proto.PicturesRequest{Ticket: strings.Repeat("0f", 16)})
	p := pb
	p.Ticket = strings.Repeat("1e", 16)
	refuse("pictures", "another ticket after signing", p)
	p = pb
	pw, _ := onWire(&pb)
	p.IdentitySig = ed25519.Sign(id, signed(SearchLabel, PicturesDigest(pw, vmPub)))
	refuse("pictures", "its digest signed under the search label", p)
	p = pb
	p.IdentitySig = SignPictures(edkey(strings.Repeat("75", 32)), pw, vmPub)
	refuse("pictures", "signed by another key", p)
	return v
}

func TestKindVectors(t *testing.T) {
	want := makeKindVectors(t)
	path := "testdata/v2-search.json"
	if os.Getenv("RUNAUTH_WRITE_KIND_VECTORS") == "1" {
		b, _ := jsonv2.Marshal(want, jsonv2.Deterministic(true))
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := jsonv2.Marshal(want, jsonv2.Deterministic(true))
	if string(append(wb, '\n')) != string(b) {
		t.Fatal("testdata/v2-search.json differs from what the code makes (never regenerate it; fix the code)")
	}
	var got kindVectors
	if err := jsonv2.Unmarshal(b, &got, jsonv2.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	vm := xkey(t, got.VM)
	vmPub := vm.PublicKey().Bytes()
	now := time.Unix(at, 0)
	// As agentd decodes them: strict JSON v2.
	check := func(c kindVector) (Who, string, error) {
		switch c.Kind {
		case "search":
			var r proto.SearchRequest
			if err := jsonv2.Unmarshal([]byte(c.Body), &r, jsonv2.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			d := SearchDigest(&r, vmPub)
			who, err := CheckSearch(vm, &r, now)
			return who, hex.EncodeToString(d[:]), err
		case "pictures":
			var r proto.PicturesRequest
			if err := jsonv2.Unmarshal([]byte(c.Body), &r, jsonv2.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			d := PicturesDigest(&r, vmPub)
			who, err := CheckPictures(vm, &r, now)
			return who, hex.EncodeToString(d[:]), err
		}
		t.Fatalf("kind %q", c.Kind)
		return Who{}, "", nil
	}
	for _, c := range got.Requests {
		who, d, err := check(c)
		if d != c.Digest {
			t.Errorf("%s: digest", c.Name)
		}
		if err != nil || who.Space != got.Space || who.Seal != got.SealPub || who.Identity != got.Identity.ID || who.Key != got.Identity.Key {
			t.Errorf("%s: %v %+v", c.Name, err, who)
		}
	}
	for _, c := range got.Refused {
		if _, _, err := check(c); err == nil {
			t.Errorf("%s: passed", c.Name)
		}
	}
	// A run's signature never passes as a search's: the same where and who, a run signed, its signature on a search.
	a, _ := NewAsker()
	run := proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "hi"}}}
	if err := a.Authorize(&run, vmPub); err != nil {
		t.Fatal(err)
	}
	s := proto.SearchRequest{Query: "hi", Decision: proto.SearchOnce, Space: run.Space, SpaceSeal: run.SpaceSeal, SpaceProof: run.SpaceProof,
		Identity: run.Identity, IdentityKey: run.IdentityKey, Nonce: run.Nonce, SignedAt: run.SignedAt, IdentitySig: run.IdentitySig}
	if _, err := CheckSearch(vm, &s, time.Unix(run.SignedAt, 0)); err == nil {
		t.Error("a run's signature passed as a search's")
	}
}
