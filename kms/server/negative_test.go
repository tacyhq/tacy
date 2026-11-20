package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/verifier"
)

// vmRequest is what a VM with this quote and info sends for nonce: its quote binds nonce and key (report_data
// patched in, as its TD would have made it) unless raw is set (a quote replayed as recorded).
func vmRequest(t *testing.T, nonce, key []byte, quote, info json.RawMessage, raw bool, purposes []string, release string) kms.ReleaseRequest {
	t.Helper()
	if !raw {
		quote = patchQuote(t, quote, offReportData, proto.ReportData(nonce, key))
	}
	att, _ := json.Marshal(proto.Attestation{Version: proto.Version, Platform: "dstack", Nonce: hex.EncodeToString(nonce),
		HPKEPublicKey: hex.EncodeToString(key), HPKESuite: proto.HPKESuite, Quote: quote, Info: info, Booted: "2026-11-15T00:00:00Z"})
	return kms.ReleaseRequest{Nonce: hex.EncodeToString(nonce), Attestation: att, Release: release, Purposes: purposes, Holder: "agentd"}
}

func freshKey() []byte {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return k.PublicKey().Bytes()
}

func (r *rig) challenge(s *Server) []byte {
	r.t.Helper()
	var ch kms.Challenge
	r.ok(s, http.MethodGet, "/v1/challenge", nil, &ch)
	n, _ := hex.DecodeString(ch.Nonce)
	return n
}

// refused checks a refusal: not 200, only {"error"} in the body with the expected reason, no key material, and
// the refusal recorded in the signed audit log: an entry of its own with the reason when the caller proved itself
// (an attested VM), else counted in a "refused" entry by the reason's form.
func (r *rig) refused(s *Server, code int, body []byte, want string) {
	r.t.Helper()
	r.refusedSince(s, code, body, want, 0)
}

func (r *rig) refusedSince(s *Server, code int, body []byte, want string, before uint64) {
	r.t.Helper()
	if code == http.StatusOK {
		r.t.Fatalf("accepted: %s", body)
	}
	var e kms.Error
	if err := kms.Strict(body, &e); err != nil {
		r.t.Fatalf("refusal body isn't just an error: %s", body)
	}
	if !strings.Contains(e.Error, want) {
		r.t.Fatalf("refused for another reason: %q (want %q)", e.Error, want)
	}
	assertNoLeak(r.t, "refusal", body, secretsOf(r.t, s, testSecrets))
	assertNoLeak(r.t, "logs", []byte(r.logs.String()), secretsOf(r.t, s, testSecrets))
	log := s.Log(0, 10000)
	last := log[len(log)-1]
	switch {
	case last.Kind == "refuse" && !last.OK && strings.Contains(last.Detail, want):
	case last.Kind == "refused" && !last.OK && s.Status().Refused > before && strings.Contains(last.Detail, "unauthenticated"):
	default:
		r.t.Fatalf("not in the audit log: %+v", last)
	}
	id, _ := kms.ParseID(s.Status().KMSID)
	if _, err := kms.VerifyLog(log, "", id); err != nil {
		r.t.Fatal(err)
	}
}

// TestRefusals: the tampered and unknown VM cases (a)-(f) on recorded quotes, plus the other ways a request can be wrong. A good request
// from the recorded VM passes first, so each refusal is the one thing changed.
func TestRefusals(t *testing.T) {
	envLine := regexp.MustCompile(`(?m)^      [A-Z_]+: \$\{[A-Z_]+\}$`)
	digest := regexp.MustCompile(`@sha256:[0-9a-f]{64}`)
	cases := []struct {
		name, want string
		// req makes the request; it may change the rig's policy (reloaded before) or the replica.
		req func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest
		pol func(r *rig, p *kms.Policy)
	}{
		{name: "(a) tampered compose: one env line changed", want: "isn't a pinned release",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				var changed string
				info, ac := editAppCompose(t, r.vmInfo, func(m map[string]any) {
					dc := m["docker_compose_file"].(string)
					line := envLine.FindString(dc)
					if line == "" {
						t.Fatal("no env line in the recorded compose")
					}
					changed = strings.Replace(dc, line, strings.SplitN(line, ":", 2)[0]+": attacker-value", 1)
					m["docker_compose_file"] = changed
				})
				return vmRequest(t, r.challenge(s), freshKey(), editEvents(t, r.vmQuote, map[string]string{"compose-hash": sum(ac)}), info, false, vmPurposes, vmRelease)
			}},
		{name: "(a) tampered app-compose: a deployer env allowed", want: "isn't a pinned release",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				info, ac := editAppCompose(t, r.vmInfo, func(m map[string]any) {
					m["allowed_envs"] = append(m["allowed_envs"].([]any), "EXTRA_KEY")
				})
				return vmRequest(t, r.challenge(s), freshKey(), editEvents(t, r.vmQuote, map[string]string{"compose-hash": sum(ac)}), info, false, vmPurposes, vmRelease)
			}},
		{name: "(a) tampered app-compose: another key provider", want: "isn't a pinned release",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				info, ac := editAppCompose(t, r.vmInfo, func(m map[string]any) { m["key_provider_id"] = strings.Repeat("ab", 32) })
				return vmRequest(t, r.challenge(s), freshKey(), editEvents(t, r.vmQuote, map[string]string{"compose-hash": sum(ac)}), info, false, vmPurposes, vmRelease)
			}},
		{name: "(a) tampered VM showing the pinned app-compose (its measured one differs)", want: "compose-hash",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				_, ac := editAppCompose(t, r.vmInfo, func(m map[string]any) { m["allowed_envs"] = []string{"EXTRA_KEY"} })
				return vmRequest(t, r.challenge(s), freshKey(), editEvents(t, r.vmQuote, map[string]string{"compose-hash": sum(ac)}), r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(b) wrong image digest", want: "isn't a pinned release",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				info, ac := editAppCompose(t, r.vmInfo, func(m map[string]any) {
					dc := m["docker_compose_file"].(string)
					d := digest.FindString(dc)
					m["docker_compose_file"] = strings.Replace(dc, d, "@sha256:"+strings.Repeat("0", 64), 1)
				})
				return vmRequest(t, r.challenge(s), freshKey(), editEvents(t, r.vmQuote, map[string]string{"compose-hash": sum(ac)}), info, false, vmPurposes, vmRelease)
			}},
		{name: "(c) valid quote replayed with a different key", want: "report_data",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				// Even for the very nonce the recording answered: only the key differs.
				s.mu.Lock()
				s.nonces[hex.EncodeToString(r.recNonce)] = r.clock().Add(time.Minute)
				s.mu.Unlock()
				return vmRequest(t, r.recNonce, freshKey(), r.vmQuote, r.vmInfo, true, vmPurposes, vmRelease)
			}},
		{name: "(c) valid attestation replayed for a fresh nonce", want: "nonce",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				a, _ := load065(t)
				key, _ := hex.DecodeString(a.HPKEPublicKey)
				req := vmRequest(t, r.recNonce, key, r.vmQuote, r.vmInfo, true, vmPurposes, vmRelease) // RTMR3 as the release VM's
				req.Nonce = hex.EncodeToString(r.challenge(s))
				return req
			}},
		{name: "(d) release below the policy floor", want: "below the policy floor v0.20.0",
			pol: func(_ *rig, p *kms.Policy) { p.Floor = "v0.20.0" },
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(d) release below the app's floor", want: "below the app floor v0.19.4",
			pol: func(_ *rig, p *kms.Policy) { a := p.Apps[vmApp]; a.Floor = "v0.19.4"; p.Apps[vmApp] = a },
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(e) second instance while the lease is held", want: "holds agent-vm's agentd lease",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				if code, b := call(s, http.MethodPost, "/v1/release", vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)); code != http.StatusOK {
					t.Fatalf("first instance: %d %s", code, b)
				}
				q := editEvents(t, r.vmQuote, map[string]string{"instance-id": strings.Repeat("cd", 20)})
				return vmRequest(t, r.challenge(s), freshKey(), q, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(f) unapproved OS image", want: "isn't a known production image",
			pol: func(_ *rig, p *kms.Policy) { p.OSImages = map[string]string{strings.Repeat("ef", 32): "dstack-next"} },
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(f) OS image listed, boot measurements not", want: "MRTD",
			pol: func(_ *rig, p *kms.Policy) {
				b := verifier.BootMeasurements[0]
				p.Boot = []kms.BootSet{{Name: "other firmware", OSImage: b.OSImage, MRTD: strings.Repeat("00", 48), RTMR0: b.RTMR0, RTMR1: b.RTMR1, RTMR2: b.RTMR2}}
			},
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(f) unreviewed pre-launch script (in a pinned app-compose)", want: "pre-launch script",
			pol: func(r *rig, p *kms.Policy) {
				var h string
				r.altQuote, r.altInfo, h = r.variant(func(m map[string]any) { m["pre_launch_script"] = "#!/bin/sh\necho unreviewed\n" })
				p.Releases = append(p.Releases, kms.ReleasePin{App: vmApp, Version: vmRelease, AppComposeSHA256: h})
			},
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.altQuote, r.altInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(f) keys from a provider's KMS while the policy allows only keys made in the VM", want: "explicit KMS fallback",
			pol: func(_ *rig, p *kms.Policy) { p.KMSFallback = false },
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(f) KMS root not pinned", want: "isn't a pinned one",
			pol: func(_ *rig, p *kms.Policy) { p.KMSRoots = map[string]string{strings.Repeat("ab", 32): "another root"} },
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "(a) pinned app-compose with swap on", want: "swap_size",
			pol: func(r *rig, p *kms.Policy) {
				var h string
				r.altQuote, r.altInfo, h = r.variant(func(m map[string]any) { m["swap_size"] = "2G" })
				p.Releases = append(p.Releases, kms.ReleasePin{App: vmApp, Version: vmRelease, AppComposeSHA256: h})
			},
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.altQuote, r.altInfo, false, vmPurposes, vmRelease)
			}},
		{name: "purpose the app has no grant for", want: "may not have operator/v1",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, []string{"state/v1", "operator/v1"}, vmRelease)
			}},
		{name: "unknown purpose", want: "unknown or repeated",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, []string{"disk/v1"}, vmRelease)
			}},
		{name: "claims another release", want: "claimed",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				return vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, "v0.20.0")
			}},
		{name: "nonce used twice", want: "unknown, used or expired nonce",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				req := vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
				if code, b := call(s, http.MethodPost, "/v1/release", req); code != http.StatusOK {
					t.Fatalf("first use: %d %s", code, b)
				}
				return req
			}},
		{name: "nonce expired", want: "unknown, used or expired nonce",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				n := r.challenge(s)
				r.advance(kms.ChallengeTTL + time.Second)
				return vmRequest(t, n, freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
		{name: "nonce never issued", want: "unknown, used or expired nonce",
			req: func(t *testing.T, r *rig, s *Server) kms.ReleaseRequest {
				n := make([]byte, 32)
				rand.Read(n)
				return vmRequest(t, n, freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			s, _, _ := r.unlocked()
			// The unchanged VM gets its keys (so the refusal below is the change alone), then its lease is let go.
			if code, b := call(s, http.MethodPost, "/v1/release", vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)); code != http.StatusOK {
				t.Fatalf("baseline: %d %s", code, b)
			}
			r.advance(kms.LeaseTTL + time.Second)
			if c.pol != nil {
				r.policy.Seq++
				c.pol(r, &r.policy)
				var st kms.Status
				r.ok(s, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
			}
			req := c.req(t, r, s)
			before := s.Status().Refused
			code, body := call(s, http.MethodPost, "/v1/release", req)
			r.refusedSince(s, code, body, c.want, before)
		})
	}
}

// The lease of (e) ends by expiry or by a move the Worker signs, and only so.
func TestSecondInstanceAfterExpiryOrMove(t *testing.T) {
	r := newRig(t)
	s, _, _ := r.unlocked()
	other := editEvents(t, r.vmQuote, map[string]string{"instance-id": strings.Repeat("cd", 20)})
	release := func(q json.RawMessage) (int, []byte) {
		return call(s, http.MethodPost, "/v1/release", vmRequest(t, r.challenge(s), freshKey(), q, r.vmInfo, false, vmPurposes, vmRelease))
	}
	code, b := release(r.vmQuote)
	var rep kms.ReleaseReply
	if code != http.StatusOK || json.Unmarshal(b, &rep) != nil {
		t.Fatalf("first: %d %s", code, b)
	}
	r.advance(kms.LeaseTTL - 10*time.Second)
	if code, _ := release(other); code != http.StatusConflict {
		t.Fatalf("other instance before expiry: %d", code)
	}
	r.advance(11 * time.Second)
	code, b = release(other)
	if code != http.StatusOK {
		t.Fatalf("other instance after expiry: %d %s", code, b)
	}
	json.Unmarshal(b, &rep)
	if rep.Lease.Instance != strings.Repeat("cd", 20) || rep.Lease.Seq != 2 {
		t.Fatalf("lease %+v", rep.Lease)
	}
	// Now the first instance is the second one; a move signed by an admin key (not the Worker's) does nothing.
	mv := kms.LeaseMove{KMSID: s.Status().KMSID, Epoch: 1, App: vmApp, Holder: "agentd", Lease: rep.Lease.ID, Instance: recordedInstance, IssuedAt: r.clock()}
	if code, _ := call(s, http.MethodPost, "/v1/lease/move", r.sign(kms.KindLeaseMove, mv)); code != http.StatusForbidden {
		t.Fatalf("move not signed by the Worker: %d", code)
	}
	// A stale move does nothing either.
	stale := mv
	stale.IssuedAt = r.clock().Add(-kms.LeaseMoveTTL - time.Second)
	if code, _ := call(s, http.MethodPost, "/v1/lease/move", r.sign(kms.KindLeaseMove, stale, r.worker)); code != http.StatusForbidden {
		t.Fatalf("stale move: %d", code)
	}
	if code, _ := release(r.vmQuote); code != http.StatusConflict {
		t.Fatalf("first instance while the second holds it: %d", code)
	}
	// The Worker's move hands it to the first instance, and to it only.
	var sl kms.SignedLease
	r.ok(s, http.MethodPost, "/v1/lease/move", r.sign(kms.KindLeaseMove, mv, r.worker), &sl)
	third := editEvents(t, r.vmQuote, map[string]string{"instance-id": strings.Repeat("ef", 20)})
	if code, _ := release(third); code != http.StatusConflict {
		t.Fatalf("a third instance took a lease moved to the first: %d", code)
	}
	if code, b := release(r.vmQuote); code != http.StatusOK {
		t.Fatalf("first instance after the move: %d %s", code, b)
	}
	// The same move again is for an older lease: nothing happens.
	if code, _ := call(s, http.MethodPost, "/v1/lease/move", r.sign(kms.KindLeaseMove, mv, r.worker)); code != http.StatusConflict {
		t.Fatalf("replayed move: %d", code)
	}
}

// A locked replica releases nothing, whatever the request.
func TestLockedReleasesNothing(t *testing.T) {
	r := newRig(t)
	_, id, _ := r.unlocked()
	s := r.server(id)
	code, body := call(s, http.MethodPost, "/v1/release", vmRequest(t, r.challenge(s), freshKey(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease))
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "locked") {
		t.Fatalf("%d %s", code, body)
	}
}

// The leak check finds a key in any encoding it scans for, and a successful reply's body holds no key in the clear.
func TestReplyBodiesCarryNoPlaintextKeys(t *testing.T) {
	r := newRig(t)
	s, id, _ := r.unlocked()
	secrets := secretsOf(t, s, testSecrets)
	for _, e := range encodings(secrets[0])[:5] {
		if !leaks([]byte(`{"x":"`+e+`"}`), secrets) {
			t.Fatalf("leak check misses %q", e)
		}
	}
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	n := r.challenge(s)
	req := vmRequest(t, n, priv.PublicKey().Bytes(), r.vmQuote, r.vmInfo, false, vmPurposes, vmRelease)
	code, body := call(s, http.MethodPost, "/v1/release", req)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	assertNoLeak(t, "release reply", body, secretsOf(t, s, testSecrets))
	assertNoLeak(t, "logs", []byte(r.logs.String()), secretsOf(t, s, testSecrets))
	keys, err := client.OpenRelease(body, id, n, req.Attestation, priv, vmPurposes)
	if err != nil || len(keys.Keys) != 2 {
		t.Fatalf("open: %v", err)
	}
}
